# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Settings document, storage safety (lost indices, retention policies) and the backup reminder."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from . import auditlog
from .collector import _parse
from .i18n import t
from .notify import plain_message
from .notify import send as notify_send
from .settingsdoc import DOC_ID, EnvSettings, diff
from .storagecheck import prefix_issue, storage_report
from .store import now_iso

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt")
SETTINGS_TTL = 60          # seconds; another replica may have saved


class AdminMixin:
    # ------------------------------------------------------------ settings
    async def env_settings(self, rt: EnvRuntime, fresh: bool = False) -> EnvSettings:
        now = time.monotonic()
        if not fresh and rt.settings is not None and now - rt.settings_at < SETTINGS_TTL:
            return rt.settings
        doc = await rt.repo.get_state(DOC_ID)
        try:
            st = EnvSettings.model_validate(doc or {})
        except ValueError as e:      # a document written by a newer/older version: keep working on defaults
            log.warning("%s: stored settings are invalid, using defaults: %s", rt.env.id, e)
            st = EnvSettings()
        rt.settings, rt.settings_at = st, now
        return st

    async def save_settings(self, env_id: str, patch: dict, by: str) -> EnvSettings:
        """Validate and store a partial update (whole sections: watch / ai / backup / mask)."""
        rt = self.get(env_id)
        cur = await self.env_settings(rt, fresh=True)
        before = cur.model_dump()
        merged = {**before, **{k: v for k, v in patch.items() if k in ("watch", "ai", "backup", "mask")}}
        new = EnvSettings.model_validate(merged)
        if new.mask.content() != cur.mask.content():
            new.mask.version = cur.mask.version + 1
        else:
            new.mask.version = cur.mask.version
        new.updated_at, new.updated_by = now_iso(), by
        await rt.repo.put_state(DOC_ID, new.model_dump())
        rt.settings, rt.settings_at = new, time.monotonic()
        changed = [p for p in diff(before, new.model_dump()) if not p.startswith("updated_")]
        auditlog.record("settings.update", actor=by, role="admin", env=env_id, target="settings", result="ok",
                        detail={"changed": changed[:40], "mask_version": new.mask.version})
        return new

    async def load_all_settings(self) -> None:
        """At startup: the AI-round schedule from the settings page must be in force before the first tick."""
        for rt in self.envs.values():
            try:
                await self.env_settings(rt, fresh=True)
            except Exception as e:  # noqa: BLE001 - the indexer may not be up yet; the scheduler retries
                log.warning("%s: settings not loaded yet: %s", rt.env.id, e)

    def schedule_for(self, rt: EnvRuntime):
        """The effective AI-round schedule: the YAML schedule with the settings page on top."""
        st = rt.settings
        return st.schedule(rt.env.schedule) if st is not None else rt.env.schedule

    # ------------------------------------------------------------ storage safety
    async def storage_status(self, env_id: str) -> dict:
        """Lost indices, the prefix check and the retention-policy check (read-only)."""
        rt = self.get(env_id)
        health = getattr(rt.store, "health", None) or {}
        if self.demo or not hasattr(rt.ix, "ism_explain"):
            rep = {"prefix": rt.env.storage_prefix, "prefix_issue": prefix_issue(rt.env.storage_prefix),
                   "indices": [], "checked": False, "error": None, "deletes": False, "worst": None, "demo": True}
        else:
            rep = await storage_report(rt.ix, rt.env.storage_prefix)
        rep["lost"] = list(health.get("lost") or [])
        rep["initialised_at"] = health.get("initialised_at") or health.get("since")
        rep["backup"] = await rt.repo.get_state("backup") or {}
        return rep

    async def storage_flags(self, rt: EnvRuntime, lang: str) -> list[dict]:
        """Health flags for a run: what would make the application lose its own data."""
        flags: list[dict] = []
        try:
            st = await self.storage_status(rt.env.id)
        except Exception as e:  # noqa: BLE001 - never fail a run over this
            log.warning("%s: storage check failed: %s", rt.env.id, e)
            return flags
        for x in st["lost"]:
            flags.append({"code": "storage_lost", "severity": "critical",
                          "message": t(lang, "flag.storage_lost", index=x["index"], at=x["detected_at"][:16])})
        if st["prefix_issue"]:
            flags.append({"code": "storage_prefix", "severity": "warn",
                          "message": t(lang, "flag.storage_prefix", prefix=st["prefix"])})
        for r in st["indices"]:
            if r.get("deletes"):
                flags.append({"code": "storage_retention", "severity": "warn",
                              "message": t(lang, "flag.storage_retention", index=r["index"], policy=r["policy"],
                                           on=(r.get("deletes_on") or "?")[:10])})
        age = self._backup_age_days(st)
        remind = (await self.env_settings(rt)).backup.remind_days
        if remind and age is not None and age >= remind:
            flags.append({"code": "backup_overdue", "severity": "info",
                          "message": t(lang, "flag.backup_overdue", d=age)})
        return flags

    @staticmethod
    def _backup_age_days(st: dict) -> int | None:
        """Days since the last export; counted from the installation date when there never was one."""
        last = (st.get("backup") or {}).get("last_at") or st.get("initialised_at")
        if not last:
            return None
        try:
            return (datetime.now(UTC) - _parse(last)).days
        except ValueError:
            return None

    async def storage_ack(self, env_id: str, by: str) -> int:
        rt = self.get(env_id)
        n = await rt.store.acknowledge_loss(by)
        auditlog.record("storage.acknowledge_loss", actor=by, role="admin", env=env_id, target=rt.env.storage_prefix,
                        result=str(n))
        return n

    async def _storage_tick(self):
        """Every ten minutes: did an index disappear? Once a day: is a backup overdue? Announce each once."""
        loop_now = asyncio.get_running_loop().time()
        for env_id, rt in self.envs.items():
            if loop_now - self._storage_last.get(env_id, -1e9) < 600:
                continue
            self._storage_last[env_id] = loop_now
            try:
                health = await rt.store.verify()
            except Exception as e:  # noqa: BLE001 - the indexer is down: the liveness check reports that
                log.debug("%s: storage verification skipped: %s", env_id, e)
                continue
            try:
                await self._storage_announce(rt, health)
            except Exception:  # noqa: BLE001
                log.exception("%s: storage announcement failed", env_id)

    async def _storage_announce(self, rt: EnvRuntime, health: dict, transport=None) -> dict | None:
        lang = self.lang(rt.env)
        cfg = self.settings.notify_for(rt.env)
        state = await rt.repo.get_state("storage_notice") or {}
        told = set(state.get("told") or [])
        lines: list[str] = []
        keys: list[str] = []
        for x in health.get("lost") or []:
            k = f"lost:{x['index']}:{x['detected_at']}"
            if k not in told:
                keys.append(k)
                lines.append("🔴 " + t(lang, "flag.storage_lost", index=x["index"], at=x["detected_at"][:16]))
                log.error("%s: storage index %s was missing and has been created empty — data lost", rt.env.id,
                          x["index"])
        if health.get("fresh") and health.get("initialised_at"):
            k = f"init:{health['initialised_at']}"
            if k not in told:
                keys.append(k)
                lines.append(t(lang, "storage.initialised", prefix=rt.env.storage_prefix))
                log.warning("%s: storage indices %s-* created (new installation, or all data was deleted)",
                            rt.env.id, rt.env.storage_prefix)
        st = await self.env_settings(rt)
        day = datetime.now(self.tz).strftime("%Y-%m-%d")
        if st.backup.remind_days and state.get("reminded_day") != day:
            age = self._backup_age_days({"backup": await rt.repo.get_state("backup") or {},
                                         "initialised_at": health.get("initialised_at") or health.get("since")})
            last_rem = state.get("reminded_at")
            due = age is not None and age >= st.backup.remind_days
            recently = False
            if last_rem:
                try:
                    recently = (datetime.now(UTC) - _parse(last_rem)).days < 7      # at most one reminder a week
                except ValueError:
                    recently = False
            if due and not recently:
                lines.append(t(lang, "flag.backup_overdue", d=age))
                state["reminded_at"], state["reminded_day"] = now_iso(), day
        if not lines:
            return None
        res = None
        if cfg.enabled and cfg.channels:
            link = f"{cfg.ui_url.rstrip('/')}/e/{rt.env.id}/settings#backup" if cfg.ui_url else ""
            crit = any(k.startswith("lost:") for k in keys)
            msg = plain_message(t(lang, "storage.title_lost" if crit else "storage.title", env=rt.env.name),
                                lines + ([t(lang, "storage.restore_hint")] if crit else []), link)
            res = await notify_send(cfg, msg, transport=transport or self.notify_transport)
        state["told"] = sorted(told | set(keys))[-200:]
        await rt.repo.put_state("storage_notice", state)
        return res
