# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Backup: export and import of the application's own data (knowledge base, reports, watch events, settings).

The data lives in the Wazuh indexer and nowhere else. This is the way out when an index retention policy,
a cluster rebuild or a mistake removes it:

* **export** — one encrypted archive per environment, downloaded in the browser and, when S3 is
  configured, also uploaded there. Scheduled automatically only when S3 *and* ``BACKUP_PASSPHRASE`` are set.
* **import** — a preview first (what would be added / changed), then either *add what is missing* or
  *overwrite*. Imported rule drafts lose their approved/deployed state and need approval again: an archive
  must never be a way to get a rule onto a manager.

The archive never contains credentials (they are not in the indices in the first place). It is encrypted
with a passphrase: scrypt → AES-256-GCM, authenticated, so a tampered or truncated file is refused.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit

import httpx

from . import __version__, auditlog
from .backupcfg import BackupCfg, S3Cfg, backup_from_env
from .collector import _parse
from .settingsdoc import DOC_ID, EnvSettings
from .store import MANIFEST_ID, now_iso

if TYPE_CHECKING:
    pass

log = logging.getLogger("wdt.backup")

MAGIC = b"WDTBAK1\n"
FORMAT = "wazuh-daily-triage-backup"
MIN_PASSPHRASE = 12
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_RUNS = 2000
_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
# never written to another installation: proof of what happened *there*
RULE_STATE_FIELDS = ("deploy", "verify", "promoted", "approved_by", "approved_at", "deployed_at", "whatif")


class BackupError(ValueError):
    """The archive cannot be produced or read; the message is safe to show."""


# ------------------------------------------------------------------ encryption
def _key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=_SCRYPT["n"], r=_SCRYPT["r"], p=_SCRYPT["p"],
                          maxmem=128 * 1024 * 1024, dklen=32)


def check_passphrase(passphrase: str) -> None:
    if len(passphrase or "") < MIN_PASSPHRASE:
        raise BackupError(f"the passphrase must have at least {MIN_PASSPHRASE} characters")


def encrypt(payload: dict, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    check_passphrase(passphrase)
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = gzip.compress(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode(),
                        mtime=0)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, raw, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> dict:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(blob) > MAX_ARCHIVE:
        raise BackupError("the archive is too large")
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 28 + 16:
        raise BackupError("this is not a wazuh-daily-triage backup archive")
    body = blob[len(MAGIC):]
    salt, nonce, ct = body[:16], body[16:28], body[28:]
    try:
        raw = AESGCM(_key(passphrase or "", salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise BackupError("wrong passphrase, or the archive is damaged") from None
    try:
        data = json.loads(gzip.decompress(raw))
    except (OSError, ValueError) as e:
        raise BackupError("the archive content is not readable") from e
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise BackupError("unknown archive format")
    if int(data.get("version") or 0) > 1:
        raise BackupError(f"the archive was written by a newer version ({data.get('app_version')})")
    return data


# ------------------------------------------------------------------ S3 (SigV4, no SDK)
def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def s3_request(cfg: S3Cfg, key: str, body: bytes, now: datetime | None = None) -> tuple[str, dict[str, str]]:
    """URL and signed headers for ``PUT <key>`` (AWS Signature Version 4, single-chunk)."""
    now = now or datetime.now(UTC)
    u = urlsplit(cfg.endpoint.rstrip("/"))
    host = u.netloc if cfg.path_style else f"{cfg.bucket}.{u.netloc}"
    path = (f"/{cfg.bucket}" if cfg.path_style else "") + "/" + quote(key.lstrip("/"), safe="/-_.~")
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    sha = hashlib.sha256(body).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": sha, "x-amz-date": amz}
    signed = ";".join(sorted(headers))
    canonical = "\n".join(["PUT", path, "", *[f"{k}:{headers[k]}" for k in sorted(headers)], "", signed, sha])
    scope = f"{day}/{cfg.region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + cfg.secret_key).encode(), day), cfg.region), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={cfg.access_key}/{scope}, "
                                f"SignedHeaders={signed}, Signature={sig}")
    headers["content-type"] = "application/octet-stream"
    return f"{u.scheme}://{host}{path}", headers


async def s3_put(cfg: S3Cfg, key: str, body: bytes, transport: httpx.AsyncBaseTransport | None = None) -> str:
    url, headers = s3_request(cfg, key, body)
    async with httpx.AsyncClient(timeout=120, verify=cfg.verify_tls, transport=transport) as c:
        r = await c.put(url, content=body, headers=headers)
    if r.status_code >= 300:
        raise BackupError(f"S3 upload failed ({r.status_code})")
    return f"s3://{cfg.bucket}/{key.lstrip('/')}"


# ------------------------------------------------------------------ archive content
def _meta(doc: dict) -> bool:
    return str(doc.get("id") or "").startswith("_") or doc.get("env") == "__meta__"


def sanitize_rule_draft(doc: dict) -> dict:
    """An imported rule draft is a proposal again, whatever it was where it came from."""
    d = {k: v for k, v in doc.items() if k not in RULE_STATE_FIELDS}
    if d.get("status") == "active":
        d["status"] = "proposed"
    d["imported"] = True
    return d


def plan(archive: dict, have: dict[str, dict[str, dict]], mode: str) -> dict:
    """What an import would do. ``have`` maps kind → id → current document."""
    if mode not in ("missing", "overwrite"):
        raise BackupError("mode must be 'missing' or 'overwrite'")
    data = archive.get("data") or {}
    out: dict = {"mode": mode, "kinds": {}, "writes": {}, "rule_drafts_reset": 0}
    for kind, idf in (("knowledge", "id"), ("runs", "run_id"), ("events", "id")):
        add, change, same = [], [], 0
        for doc in data.get(kind) or []:
            if not isinstance(doc, dict) or not doc.get(idf) or _meta(doc):
                continue
            if kind == "knowledge" and doc.get("kind") == "rule_draft":
                clean = sanitize_rule_draft(doc)
                if {k: v for k, v in clean.items() if k != "imported"} != doc:
                    out["rule_drafts_reset"] += 1
                doc = clean
            cur = have.get(kind, {}).get(str(doc[idf]))
            if cur is None:
                add.append(doc)
            elif _same(cur, doc):
                same += 1
            elif mode == "overwrite":
                change.append(doc)
            else:
                same += 1                      # "add missing": an existing document is left alone
        out["kinds"][kind] = {"in_archive": len(data.get(kind) or []), "add": len(add), "change": len(change),
                              "unchanged": same}
        out["writes"][kind] = add + change
    out["settings"] = bool(data.get("settings")) and mode == "overwrite"
    return out


def _same(a: dict, b: dict) -> bool:
    drop = ("updated_at", "imported")
    return {k: v for k, v in a.items() if k not in drop} == {k: v for k, v in b.items() if k not in drop}


# ------------------------------------------------------------------ runtime side
class BackupMixin:
    def backup_cfg(self) -> BackupCfg:
        return getattr(self.settings, "backup", None) or BackupCfg()

    async def backup_build(self, env_id: str, include_runs: bool = True) -> dict:
        rt = self.get(env_id)
        kn = [k for k in await rt.store.query("knowledge", {"env": env_id}, "updated_at", 10_000) if not _meta(k)]
        runs: list[dict] = []
        if include_runs:
            runs = await rt.store.query("runs", {"env": env_id}, "started_at", MAX_RUNS, exclude=["agent.trace"])
        events = await rt.store.query("events", {"env": env_id}, "created_at", 10_000)
        st = await self.env_settings(rt, fresh=True)
        live = await rt.store.get("knowledge", f"_live_{env_id}")
        return {"format": FORMAT, "version": 1, "app_version": __version__, "env": env_id, "env_name": rt.env.name,
                "created_at": now_iso(), "storage_prefix": rt.env.storage_prefix,
                "counts": {"knowledge": len(kn), "runs": len(runs), "events": len(events)},
                "data": {"knowledge": kn, "runs": runs, "events": events,
                         "settings": st.model_dump(exclude={"updated_at", "updated_by"}),
                         "outages": (live or {}).get("events") or []}}

    async def backup_export(self, env_id: str, passphrase: str, by: str, to_s3: bool = False,
                            include_runs: bool = True, transport=None, trigger: str = "manual") -> dict:
        """Returns ``{"blob", "filename", "counts", "s3"}`` and records the export (who, when, how much)."""
        rt = self.get(env_id)
        archive = await self.backup_build(env_id, include_runs)
        blob = encrypt(archive, passphrase)
        name = f"wdt-{env_id}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.wdtbak"
        s3_url, s3_err = None, None
        cfg = self.backup_cfg()
        if to_s3:
            if not cfg.s3.enabled:
                s3_err = "S3 is not configured"
            else:
                try:
                    s3_url = await s3_put(cfg.s3, f"{cfg.s3.prefix.strip('/')}/{env_id}/{name}", blob, transport)
                except (BackupError, httpx.HTTPError) as e:
                    s3_err = str(e)[:200] if isinstance(e, BackupError) else type(e).__name__
                    log.warning("%s: S3 upload failed: %s", env_id, e)
        state = await rt.repo.get_state("backup") or {}
        if not to_s3 or s3_url:
            state.update(last_at=now_iso(), last_by=by, last_bytes=len(blob), last_counts=archive["counts"],
                         last_trigger=trigger)
        if to_s3:
            state.update(s3_at=now_iso() if s3_url else state.get("s3_at"), s3_url=s3_url or state.get("s3_url"),
                         s3_error=s3_err)
        await rt.repo.put_state("backup", state)
        auditlog.record("backup.export", actor=by, role="admin" if trigger == "manual" else "system", env=env_id,
                        target=name, result="ok" if not s3_err else "s3_failed",
                        detail={"bytes": len(blob), **archive["counts"], "s3": bool(s3_url), "trigger": trigger})
        return {"blob": blob, "filename": name, "counts": archive["counts"], "s3": s3_url, "s3_error": s3_err}

    async def backup_import(self, env_id: str, blob: bytes, passphrase: str, mode: str, dry_run: bool,
                            by: str) -> dict:
        rt = self.get(env_id)
        archive = decrypt(blob, passphrase)
        have = {
            "knowledge": {k["id"]: k for k in await rt.store.query("knowledge", {"env": env_id}, "updated_at", 10_000)},
            "runs": {r["run_id"]: r for r in await rt.store.query("runs", {"env": env_id}, "started_at", MAX_RUNS,
                                                                  exclude=["agent.trace"])},
            "events": {e["id"]: e for e in await rt.store.query("events", {"env": env_id}, "created_at", 10_000)},
        }
        p = plan(archive, have, mode)
        res = {"dry_run": dry_run, "mode": mode, "kinds": p["kinds"], "rule_drafts_reset": p["rule_drafts_reset"],
               "settings": p["settings"], "archive": {k: archive.get(k) for k in ("env", "env_name", "created_at",
                                                                                   "app_version", "counts")},
               "other_env": archive.get("env") != env_id}
        if dry_run:
            return res
        idf = {"knowledge": "id", "runs": "run_id", "events": "id"}
        for kind, docs in p["writes"].items():
            for doc in docs:
                doc = {**doc, "env": env_id}               # an archive of another environment lands in this one
                if kind == "runs" and doc.get("status") == "running":
                    doc["status"] = "error"
                await rt.store.put(kind, str(doc[idf[kind]]), doc)
        if p["settings"]:
            try:
                st = EnvSettings.model_validate(archive["data"]["settings"])
                await self.save_settings(env_id, st.model_dump(include={"watch", "ai", "backup", "mask"}), by)
            except ValueError as e:
                res["settings_error"] = str(e)[:300]
        state = await rt.repo.get_state("backup") or {}
        state.update(last_import_at=now_iso(), last_import_by=by, last_import_mode=mode)
        await rt.repo.put_state("backup", state)
        auditlog.record("backup.import", actor=by, role="admin", env=env_id, target=str(archive.get("created_at")),
                        result="ok", detail={"mode": mode, "from_env": archive.get("env"),
                                             **{k: v["add"] + v["change"] for k, v in p["kinds"].items()},
                                             "rule_drafts_reset": p["rule_drafts_reset"]})
        return res

    async def _backup_tick(self):
        """Automatic backup — only when S3 and BACKUP_PASSPHRASE are configured and the admin switched it on."""
        cfg = self.backup_cfg()
        day = datetime.now(self.tz).strftime("%Y-%m-%d")
        if cfg.keep_events_days:                 # old watch events (independent of S3)
            for env_id, rt in self.envs.items():
                key = f"prune:{env_id}:{day}"
                if key in self._backup_done:
                    continue
                self._backup_done.add(key)
                try:
                    await rt.repo.prune_events(cfg.keep_events_days)
                except Exception as e:  # noqa: BLE001
                    log.debug("%s: event pruning skipped: %s", env_id, e)
        if not (cfg.s3.enabled and len(cfg.passphrase) >= MIN_PASSPHRASE):
            return
        for env_id, rt in self.envs.items():
            key = f"{env_id}:{day}"
            if key in self._backup_done:
                continue
            self._backup_done.add(key)
            try:
                st = await self.env_settings(rt)
                if not st.backup.auto:
                    continue
                state = await rt.repo.get_state("backup") or {}
                last = state.get("s3_at")
                if last and (datetime.now(UTC) - _parse(last)).days < st.backup.auto_interval_days:
                    continue
                res = await self.backup_export(env_id, cfg.passphrase, "scheduler", to_s3=True,
                                               include_runs=st.backup.include_runs, trigger="schedule")
                log.info("%s: automatic backup → %s", env_id, res["s3"] or res["s3_error"])
            except Exception:  # noqa: BLE001 - never stop the scheduler
                log.exception("%s: automatic backup failed", env_id)


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode()


__all__ = ["BackupMixin", "BackupCfg", "BackupError", "S3Cfg", "encrypt", "decrypt", "plan", "s3_request",
           "sanitize_rule_draft", "backup_from_env", "MANIFEST_ID", "DOC_ID"]
