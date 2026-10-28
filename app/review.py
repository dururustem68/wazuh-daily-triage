# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Review loop: recommendation inbox plus run, rule and liveness notifications."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .collector import Collector, _parse, iso
from .i18n import t
from .notify import build_message, critical_items, plain_message, recently_notified, summary_lines
from .notify import send as notify_send
from .reporting import _fmt_local, _neg_ts
from .store import now_iso

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt")


class ReviewMixin:
    async def notify_run(self, rt: EnvRuntime, run: dict, transport=None) -> dict:
        cfg = self.settings.notify_for(rt.env)
        if not cfg.enabled or not cfg.channels:
            return {}
        try:
            lang = self.lang(rt.env)
            items = critical_items(run, cfg, self.finding_key)
            if rt.env.liveness.enabled and cfg.on_liveness:   # health flags are the liveness check's job
                items = [i for i in items if i["kind"] != "flag"]
            if items:
                prev = await rt.repo.list_runs(2 * max(1, cfg.repeat_hours // 6) + 4, light=True)
                seen = recently_notified([r for r in prev if r.get("run_id") != run.get("run_id")], cfg.repeat_hours)
                items = [i for i in items if i["key"] not in seen]
            summary = []
            if cfg.on_run_summary and run.get("status") == "done":
                waiting = await self.inbox(rt.env.id)
                summary = summary_lines(run, lang, len(waiting), lambda k: t(lang, "label." + k),
                                        [w["finding"] for w in waiting])
            if not items and not summary:
                return {}
            if items:
                msg = build_message(rt.env.name, run, items, cfg, lang, rt.env.id)
                if summary:
                    msg = plain_message(msg["title"], msg["lines"] + ["—"] + summary, msg["link"])
            else:
                link = f"{cfg.ui_url.rstrip('/')}/e/{rt.env.id}/r/{run['run_id']}" if cfg.ui_url else ""
                msg = plain_message(t(lang, "notify.summary_title", env=rt.env.name,
                                      health=t(lang, "health." + (run.get("health") or "ok"))), summary, link)
            res = await notify_send(cfg, msg, transport=transport)
            run["notified"] = [{"key": i["key"], "ts": now_iso()} for i in items] + \
                ([{"key": "summary", "ts": now_iso()}] if summary else [])
            run["notify_result"] = res
            await rt.repo.save_run(run)
            log.info("%s: notified %d item(s): %s", rt.env.id, len(items), res)
            return res
        except Exception:  # noqa: BLE001 — a notification problem must never break a run
            log.exception("notification failed")
            return {}

    async def _notify_rule(self, rt: EnvRuntime, entry: dict, rec: dict, transport=None) -> dict:
        cfg = self.settings.notify_for(rt.env)
        if not (cfg.enabled and cfg.channels and cfg.on_rule_deploy):
            return {}
        try:
            lang = self.lang(rt.env)
            lines = [entry.get("title", ""), t(lang, "notify.rule_ids", ids=", ".join(rec.get("ids") or []),
                                               file=rec.get("file", ""), by=rec.get("by", ""))]
            if rec.get("error"):
                lines.append(rec["error"][:300])
            link = f"{cfg.ui_url.rstrip('/')}/e/{rt.env.id}/k?kind=rule_draft" if cfg.ui_url else ""
            msg = plain_message(t(lang, "notify.rule_title", env=rt.env.name, state=t(lang, "rd.state." + rec["state"])),
                                lines, link)
            return await notify_send(cfg, msg, transport=transport)
        except Exception:  # noqa: BLE001
            log.exception("rule notification failed")
            return {}

    # ------------------------------------------------------------ liveness
    async def liveness_state(self, env_id: str) -> dict | None:
        if env_id not in self.live_state:
            d = await self.get(env_id).store.get("knowledge", f"_live_{env_id}")
            if d:
                self.live_state[env_id] = d
        return self.live_state.get(env_id)

    async def liveness_check(self, env_id: str, transport=None) -> dict:
        """Quick health probe; notifies on new problems, reminds every repeat_hours, and on recovery."""
        rt = self.get(env_id)
        env, cfg = rt.env, rt.env.liveness
        lang = self.lang(env)
        now = datetime.now(UTC)
        probs = await Collector(env, rt.ix, rt.api, lang).liveness(now, cfg.silence_minutes or env.max_silence_minutes)
        prev = await self.liveness_state(env_id) or {}
        old = prev.get("problems") or {}
        cur: dict[str, dict] = {}
        for code, msg in probs.items():
            o = old.get(code) or {}
            cur[code] = {"msg": msg, "since": o.get("since") or iso(now), "notified": o.get("notified")}
        new = [c for c in cur if c not in old]
        resolved = {c: o for c, o in old.items() if c not in cur}
        ncfg = self.settings.notify_for(env)
        can = ncfg.enabled and ncfg.channels and ncfg.on_liveness
        link = f"{ncfg.ui_url.rstrip('/')}/" if ncfg.ui_url else ""
        sent = None
        try:
            if can and new:
                lines = [("🔴 " if c in new else "• ") + v["msg"] for c, v in cur.items()]
                sent = await notify_send(ncfg, plain_message(t(lang, "live.title_problem", env=env.name), lines, link),
                                         transport=transport)
                for v in cur.values():
                    v["notified"] = iso(now)
            elif can and cur:
                last_n = min((_parse(v["notified"]) for v in cur.values() if v.get("notified")), default=None)
                if last_n is None or (now - last_n).total_seconds() >= cfg.repeat_hours * 3600:
                    lines = [f"{v['msg']} — {t(lang, 'live.since', t=_fmt_local(v['since'], self.tz))}" for v in cur.values()]
                    sent = await notify_send(ncfg, plain_message(t(lang, "live.title_still", env=env.name), lines, link),
                                             transport=transport)
                    for v in cur.values():
                        v["notified"] = iso(now)
            if can and resolved and cfg.notify_recovery and not cur:
                lines = [t(lang, "live.lasted", text=o["msg"], m=round((now - _parse(o["since"])).total_seconds() / 60))
                         for o in resolved.values()]
                sent = await notify_send(ncfg, plain_message(t(lang, "live.title_ok", env=env.name), lines, link),
                                         transport=transport)
        except Exception:  # noqa: BLE001
            log.exception("liveness notification failed")
        if new or resolved:
            log.warning("%s liveness: new=%s resolved=%s", env_id, new, list(resolved))
        events = list(prev.get("events") or [])
        for c, o in resolved.items():  # outage history for the monthly audit report
            events.append({"code": c, "msg": o.get("msg"), "start": o.get("since"), "end": iso(now),
                           "minutes": round((now - _parse(o["since"])).total_seconds() / 60)})
        state = {"id": f"_live_{env_id}", "env": "__meta__", "kind": "liveness", "status": "closed",
                 "title": env_id, "problems": cur, "checked_at": iso(now), "created_at": prev.get("created_at") or now_iso(),
                 "updated_at": now_iso(), "last_result": sent, "events": events[-500:]}
        self.live_state[env_id] = state
        try:
            await rt.store.put("knowledge", state["id"], state)
        except Exception:  # noqa: BLE001 — the indexer may be the thing that is down
            pass
        return state

    async def _liveness_tick(self):
        loop_now = asyncio.get_running_loop().time()
        for env_id, rt in self.envs.items():
            cfg = rt.env.liveness
            if not cfg.enabled or env_id in self._live_busy:
                continue
            if loop_now - self._live_last.get(env_id, -1e9) < cfg.interval_minutes * 60:
                continue
            self._live_last[env_id] = loop_now
            self._live_busy.add(env_id)

            async def go(eid=env_id):
                try:
                    await self.liveness_check(eid, transport=self.notify_transport)
                except Exception:  # noqa: BLE001
                    log.exception("liveness check failed: %s", eid)
                finally:
                    self._live_busy.discard(eid)
            task = asyncio.create_task(go())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _retention_tick(self):
        """Prune old run documents once a day per environment (knowledge is never touched)."""
        loop_now = asyncio.get_running_loop().time()
        today = datetime.now(self.tz).strftime("%Y-%m-%d")
        for rt in self.envs.values():
            days = rt.env.run_retention_days
            key = f"{rt.env.id}:{today}"
            if days <= 0 or key in self._pruned or loop_now - self._prune_last.get(key, -1e9) < 3600:
                continue
            self._prune_last[key] = loop_now
            try:
                removed = await rt.repo.prune_runs(days)
            except Exception as e:  # noqa: BLE001 - retention must never stop the scheduler
                log.warning("%s: run retention failed: %s", rt.env.id, e)
                continue
            self._pruned.add(key)
            if removed:
                log.info("%s: removed %d run(s) older than %d days", rt.env.id, removed, days)

    async def notify_test(self, env_id: str, transport=None) -> dict:
        rt = self.get(env_id)
        cfg = self.settings.notify_for(rt.env)
        if not cfg.channels:
            return {}
        lang = self.lang(rt.env)
        fake = {"run_id": "test"}
        msg = build_message(rt.env.name, fake, [{"kind": "test", "text": t(lang, "notify.test_text")}], cfg, lang, env_id)
        msg["title"] = t(lang, "notify.test_title", env=rt.env.name)
        msg["text"] = msg["title"] + "\n\n• " + t(lang, "notify.test_text")
        msg["link"] = cfg.ui_url or ""
        return await notify_send(cfg, msg, transport=transport)

    # ------------------------------------------------------------ recommendation inbox
    INBOX_RUNS = 14            # look back over this many finished runs (7 days at 2 runs/day)
    INBOX_SKIP = {"expected", "measurement"}

    @staticmethod
    def finding_key(f: dict) -> str:
        """Groups the same finding across runs (LLM wording differs, rule ids/agents do not)."""
        rules = ",".join(sorted(f.get("rule_ids") or []))
        agents = ",".join(sorted(f.get("agents") or []))
        if rules or agents:
            return f"{f.get('label')}|{rules}|{agents}"
        return f"{f.get('label')}|{(f.get('title') or '').strip().lower()[:80]}"

    ATTENTION = {"real_incident", "investigate", "detection_gap"}

    @classmethod
    def same_finding(cls, a: dict, b: dict) -> bool:
        """Fuzzy match across runs: the model rewords titles and changes labels or rule lists between runs."""
        la, lb = a.get("label"), b.get("label")
        if la != lb and not (la in cls.ATTENTION and lb in cls.ATTENTION):
            return False
        ra, rb = set(map(str, a.get("rule_ids") or [])), set(map(str, b.get("rule_ids") or []))
        aa, ab = set(a.get("agents") or []), set(b.get("agents") or [])
        agents_ok = not aa or not ab or bool(aa & ab)
        if ra and rb:
            return bool(ra & rb) and agents_ok
        if ra or rb:
            return False
        if aa and ab and not aa & ab:
            return False
        wa = set(re.findall(r"\w{3,}", (a.get("title") or "").lower()))
        wb = set(re.findall(r"\w{3,}", (b.get("title") or "").lower()))
        return bool(wa and wb) and len(wa & wb) / len(wa | wb) >= 0.5

    async def inbox(self, env_id: str) -> list[dict]:
        """Unreviewed findings of recent runs, de-duplicated, most severe and newest first."""
        rt = self.get(env_id)
        runs = await rt.repo.list_runs(self.INBOX_RUNS, status="done", light=True)
        groups: list[dict] = []
        handled: list[dict] = []
        for r in runs:  # newest first
            for f in r.get("findings") or []:
                if f.get("label") in self.INBOX_SKIP:
                    continue
                if f.get("user_status", "new") != "new":
                    handled.append(f)  # a decision on any occurrence settles the group
                    continue
                g = next((g for g in groups if g["key"] == self.finding_key(f) or self.same_finding(g["finding"], f)),
                         None)
                if g is None:
                    g = {"key": self.finding_key(f), "finding": f, "run_id": r["run_id"],
                         "run_started": r.get("started_at"), "refs": [], "seen": 0, "first_seen": r.get("started_at")}
                    groups.append(g)
                g["refs"].append({"run_id": r["run_id"], "fid": f.get("id")})
                g["seen"] += 1
                g["first_seen"] = r.get("started_at")
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        lab = {"real_incident": 0, "detection_gap": 1, "baseline_increase": 2, "investigate": 3, "false_positive": 4}
        items = [g for g in groups
                 if not any(self.finding_key(h) == g["key"] or self.same_finding(h, g["finding"]) for h in handled)]
        items.sort(key=lambda g: (lab.get(g["finding"].get("label"), 5), sev.get(g["finding"].get("severity"), 5),
                                  _neg_ts(g["run_started"])))
        return items

    async def inbox_act(self, env_id: str, refs: list[dict], status: str, note: str | None) -> int:
        """Apply one decision to every occurrence of a finding."""
        rt = self.get(env_id)
        by_run: dict[str, list[str]] = {}
        for ref in refs[:50]:
            by_run.setdefault(ref["run_id"], []).append(ref["fid"])
        n = 0
        created = False
        for run_id, fids in by_run.items():
            async with self.run_lock(run_id):
                run = await rt.repo.get_run(run_id)
                if not run:
                    continue
                for f in run.get("findings") or []:
                    if f.get("id") in fids:
                        f["user_status"] = status
                        if note:
                            f["user_note"] = note[:2000]
                        if status == "baseline" and not created and not f.get("knowledge_id"):
                            k = await rt.repo.add_knowledge("baseline", f.get("title", ""),
                                                            (f.get("detail") or "") + (f"\n\nNote: {note}" if note else ""),
                                                            rule_ids=f.get("rule_ids"), source_run=run_id)
                            f["knowledge_id"] = k["id"]
                            created = True
                        n += 1
                await rt.repo.save_run(run)
        return n
