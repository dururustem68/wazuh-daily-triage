# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Runtime: per-environment clients, daily run orchestration, scheduler, chat, connection test."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import yaml

from . import rules as rulemod
from .agent.prompts import system_prompt, triage_user_message
from .agent.runner import run_agent
from .agent.tools import LABELS, SEVERITIES, ToolBox
from .collector import Collector, _parse, health_status, iso
from .config import DAYS, Environment, LLMConfig, Settings
from .i18n import t
from .llm.base import LLMError, make_llm
from .notify import build_message, critical_items, plain_message, recently_notified, summary_lines
from .notify import send as notify_send
from .store import KNOWLEDGE_KINDS, IndexStore, MemoryStore, Repo, new_id, now_iso
from .wazuh.api import WazuhAPI, WazuhAPIError
from .wazuh.indexer import Indexer

log = logging.getLogger("wdt")
UTC = UTC


def build_sources(env: Environment) -> dict:
    """Prometheus / Loki / Kubernetes clients for one environment (only those configured)."""
    from .sources import Kubernetes, Loki, Prometheus, SourceError
    out: dict = {}
    sc = env.sources
    if sc.prometheus:
        out["prometheus"] = Prometheus(sc.prometheus)
    if sc.loki:
        out["loki"] = Loki(sc.loki)
    if sc.kubernetes.enabled:
        try:
            out["kubernetes"] = Kubernetes(sc.kubernetes)
        except (SourceError, OSError) as e:
            log.warning("%s: Kubernetes source disabled: %s", env.id, e)
    return out


class EnvRuntime:
    def __init__(self, env: Environment, ix, api, store):
        self.env = env
        self.ix = ix
        self.api = api
        self.store = store
        self.repo = Repo(store, env.id)
        self.lock = asyncio.Lock()
        self.deploy_lock = asyncio.Lock()
        self.current_run: str | None = None
        self.sources: dict = build_sources(env) if not isinstance(store, MemoryStore) else {}


class Runtime:
    def __init__(self, settings: Settings, demo: bool = False):
        self.settings = settings
        self.demo = demo
        self.tz = ZoneInfo(settings.app.timezone)
        self.envs: dict[str, EnvRuntime] = {}
        self._llms: dict[int, object] = {}
        self._sched_task: asyncio.Task | None = None
        self._fired: set[str] = set()
        self._seeded: set[str] = set()
        self._tasks: set[asyncio.Task] = set()
        self._run_locks: dict[str, asyncio.Lock] = {}
        self.notify_transport = None       # tests inject an httpx.MockTransport here
        self.live_state: dict[str, dict] = {}
        self._live_last: dict[str, float] = {}
        self._live_busy: set[str] = set()
        for e in settings.environments:
            if demo:
                from .demo import FakeAPI, FakeIndexer
                ix, api, store = FakeIndexer(), FakeAPI(), MemoryStore()
            else:
                ix = Indexer(e.indexer)
                api = WazuhAPI(e.api) if e.api else None
                store = IndexStore(ix, e.storage_prefix)
            self.envs[e.id] = EnvRuntime(e, ix, api, store)

    # ------------------------------------------------------------ helpers
    def llm_cfg(self, env: Environment) -> LLMConfig:
        return self.settings.llm_for(env)

    def llm_for(self, env: Environment):
        cfg = self.llm_cfg(env)
        key = id(cfg)
        if key not in self._llms:
            self._llms[key] = make_llm(cfg)
        return self._llms[key]

    def lang(self, env: Environment) -> str:
        return self.settings.lang_for(env)

    def get(self, env_id: str) -> EnvRuntime:
        if env_id not in self.envs:
            raise KeyError(env_id)
        return self.envs[env_id]

    async def ensure_seed(self, rt: EnvRuntime) -> int:
        """Import seed_file entries once per environment (guarded by a marker document)."""
        if rt.env.id in self._seeded:
            return 0
        self._seeded.add(rt.env.id)
        path = rt.env.resolve(self.settings.base_dir, rt.env.seed_file)
        if not path or not path.exists():
            return 0
        marker = f"_seed_{rt.env.id}"
        if await rt.store.get("knowledge", marker):
            return 0
        items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for it in items:
            await rt.repo.add_knowledge(it["kind"], it["title"], it.get("body", ""), status=it.get("status", "active"),
                                        created_by="seed", rule_ids=it.get("rule_ids"))
        # marker doc: env "__meta__" keeps it out of every listing; deleted seed entries never come back
        await rt.store.put("knowledge", marker, {"id": marker, "env": "__meta__", "kind": "seed_marker",
                                                 "status": "closed", "title": path.name, "created_at": now_iso(),
                                                 "updated_at": now_iso()})
        log.info("%s: imported %d seed entries into the knowledge base (%s)", rt.env.id, len(items), path.name)
        return len(items)

    # ------------------------------------------------------------ knowledge import / export
    async def kb_import(self, env_id: str, items: list, update: bool = False, dry_run: bool = False,
                        created_by: str = "import") -> dict:
        """Import entries in seed format. Duplicates (same `key`, else same kind + title) are skipped,
        or updated in place with `update` (status is kept)."""
        rt = self.get(env_id)
        if not isinstance(items, list):
            raise ValueError("expected a YAML/JSON list of entries")
        existing = await rt.repo.list_knowledge(size=5000)
        by_key = {}
        for d in existing:
            by_key[d.get("import_key") or f"{d['kind']}|{d['title'].strip().lower()}"] = d
            by_key.setdefault(f"{d['kind']}|{d['title'].strip().lower()}", d)
        res = {"added": 0, "updated": 0, "skipped": 0, "errors": []}
        for n, it in enumerate(items, 1):
            if not isinstance(it, dict) or not it.get("kind") or not str(it.get("title", "")).strip():
                res["errors"].append(f"#{n}: kind and title are required")
                continue
            kind, title = str(it["kind"]), str(it["title"]).strip()
            if kind not in KNOWLEDGE_KINDS:
                res["errors"].append(f"#{n}: unknown kind {kind!r}")
                continue
            key = str(it.get("key") or f"{kind}|{title.lower()}")
            body = str(it.get("body") or "")
            rule_ids = [str(x) for x in (it.get("rule_ids") or [])]
            old = by_key.get(key) or by_key.get(f"{kind}|{title.lower()}")
            if old:
                if update and (old.get("body") != body.strip() or old.get("title") != title[:300]
                               or old.get("rule_ids") != rule_ids):
                    if not dry_run:
                        await rt.repo.update_knowledge(old["id"], title=title[:300], body=body.strip(),
                                                       rule_ids=rule_ids, import_key=key)
                    res["updated"] += 1
                else:
                    res["skipped"] += 1
                continue
            if not dry_run:
                try:
                    d = await rt.repo.add_knowledge(kind, title, body, status=str(it.get("status") or "active"),
                                                    created_by=created_by, rule_ids=rule_ids,
                                                    extra={"import_key": key, **({"xml": it["xml"]} if it.get("xml") else {})})
                except ValueError as e:
                    res["errors"].append(f"#{n}: {e}")
                    continue
                by_key[key] = d
            res["added"] += 1
        res["dry_run"] = dry_run
        return res

    async def kb_export(self, env_id: str, kinds: list[str] | None = None, status: list[str] | None = None) -> list[dict]:
        rows = await self.get(env_id).repo.list_knowledge(kinds=kinds, status=status, size=5000)
        out = []
        for d in sorted(rows, key=lambda x: (x["kind"], x.get("created_at", ""))):
            e = {"kind": d["kind"], "title": d["title"]}
            for k in ("body", "rule_ids", "xml"):
                if d.get(k):
                    e[k] = d[k]
            if d.get("status") != "active":
                e["status"] = d["status"]
            if d.get("import_key"):
                e["key"] = d["import_key"]
            out.append(e)
        return out

    # ------------------------------------------------------------ daily run
    async def start_run(self, env_id: str, trigger: str = "manual", hours: int | None = None) -> str:
        rt = self.get(env_id)
        # check-and-set without an await in between: no race inside the event loop
        if rt.current_run or rt.lock.locked():
            raise RuntimeError(t(self.lang(rt.env), "err.busy"))
        run_id = new_id(f"{env_id}-")
        rt.current_run = run_id
        task = asyncio.create_task(self._run_guarded(rt, run_id, trigger, hours))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return run_id

    async def _run_guarded(self, rt, run_id, trigger, hours):
        try:
            async with rt.lock:
                run = await self.run_triage(rt, run_id, trigger, hours)
                await self.notify_run(rt, run)
        finally:
            if rt.current_run == run_id:
                rt.current_run = None

    def run_lock(self, run_id: str) -> asyncio.Lock:
        """Serialises read-modify-write updates to one run document."""
        lk = self._run_locks.get(run_id)
        if lk is None:
            if len(self._run_locks) > 500:
                self._run_locks.clear()
            lk = self._run_locks[run_id] = asyncio.Lock()
        return lk

    async def recover_stale(self):
        """Close runs left in `running` state by a restart."""
        for rt in self.envs.values():
            try:
                for r in await rt.repo.list_runs(20, status="running"):
                    r.update(status="error", stage=None, finished_at=now_iso(), error=t(self.lang(rt.env), "run.stale"))
                    await rt.repo.save_run(r)
            except Exception as e:  # noqa: BLE001
                log.warning("%s: could not check for interrupted runs: %s", rt.env.id, e)

    def _window(self, env: Environment, last: dict | None, to: datetime, hours: int | None):
        if hours:
            return to - timedelta(hours=hours)
        if last and last.get("window", {}).get("to"):
            frm = _parse(last["window"]["to"])
            span = (to - frm).total_seconds() / 3600
            if span < env.window_min_hours:
                return to - timedelta(hours=env.window_min_hours)
            if span > env.window_max_hours:
                return to - timedelta(hours=env.window_max_hours)
            return frm
        return to - timedelta(hours=env.window_min_hours)

    async def run_triage(self, rt: EnvRuntime, run_id: str, trigger: str = "manual", hours: int | None = None) -> dict:
        env, repo, lang = rt.env, rt.repo, self.lang(rt.env)
        llm_cfg = self.llm_cfg(env)
        started = datetime.now(UTC)
        run = {"run_id": run_id, "env": env.id, "status": "running", "trigger": trigger, "lang": lang,
               "started_at": iso(started), "stage": "collecting"}
        await repo.save_run(run)
        try:
            await self.ensure_seed(rt)
            last = await repo.last_success()
            frm = self._window(env, last, started, hours)

            collected = await Collector(env, rt.ix, rt.api, lang,
                                        inventory=env.inventory_names(self.settings.base_dir)).collect(frm, started)
            try:  # live verification of deployed / approved rule drafts (best effort)
                await self.verify_rules(env.id)
            except Exception as e:  # noqa: BLE001
                log.warning("%s: rule verification failed: %s", env.id, e)
            flags = collected["flags"]
            run.update(window=collected["window"], flags=flags, health=health_status(flags),
                       metrics={"total": (collected.get("volume") or {}).get("total", 0),
                                "high": (collected.get("volume") or {}).get("high_level_total", 0)},
                       stage="analysing", collected=collected)
            await repo.save_run(run)

            knowledge = await repo.list_knowledge(status=["active", "proposed", "rejected"],
                                                  kinds=["context", "baseline", "decision", "open_item",
                                                         "lesson", "rule_draft", "answer"])
            prev = await repo.list_runs(3, status="done", light=True)
            since = last["started_at"] if last else "1970-01-01T00:00:00Z"
            answers = [k for k in knowledge if k["kind"] == "answer" and k["created_at"] >= since]
            requests = await repo.list_knowledge(kinds=["request"], status="active")

            sysmsg = system_prompt("triage", env, env.context_text(self.settings.base_dir),
                                   [k for k in knowledge if k["kind"] != "answer"], self.settings.app.timezone, lang)
            usr = triage_user_message(_compact(collected), prev, answers, requests)
            tb = ToolBox(env, rt.ix, rt.api, repo, mode="triage", run_id=run_id, sources=rt.sources)
            try:
                res = await run_agent(self.llm_for(env), sysmsg, [{"role": "user", "content": usr}], tb,
                                      llm_cfg.max_tool_steps, stop_on="submit_report")
            except LLMError as e:
                # The AI is unavailable (after retries): keep the deterministic part instead of losing the run.
                log.warning("run %s: AI analysis failed, saving deterministic report: %s", run_id, e)
                rep = flags_only_report(flags, str(e), lang)
                run.update(status="done", stage=None, finished_at=now_iso(), ai_error=str(e)[:500], **rep,
                           agent={"steps": 0, "stopped": "llm_error", "trace": [],
                                  "provider": llm_cfg.provider, "model": llm_cfg.model})
                await repo.save_run(run)  # requests stay open for the next run
                return run
            if tb.submitted is not None:
                rep = normalize_report(tb.submitted, res.text, lang)
            else:
                # No usable report (text only, truncated/invalid JSON): keep the deterministic findings.
                why = "; ".join(res.notes[-3:]) or res.stopped
                log.warning("run %s: model did not submit a valid report (%s)", run_id, why)
                rep = flags_only_report(flags, t(lang, "run.no_valid_report", why=why), lang, key="run.ai_no_report")
                run["ai_error"] = f"no valid report: {why}"[:500]
            run.update(
                status="done", stage=None, finished_at=now_iso(), **rep,
                proposals=[p["id"] for p in tb.proposals],
                agent={"steps": res.steps, "stopped": res.stopped, "trace": res.trace, "notes": res.notes,
                       "input_tokens": res.input_tokens, "output_tokens": res.output_tokens,
                       "provider": llm_cfg.provider, "model": llm_cfg.model},
            )
            await repo.save_run(run)
            for r in requests:  # requests were handed to this run
                await repo.update_knowledge(r["id"], status="closed", consumed_run=run_id)
            log.info("run done %s: %s alerts, %d findings", run_id, run["metrics"]["total"], len(run["findings"]))
        except Exception as e:  # noqa: BLE001
            log.exception("run failed %s", run_id)
            run.update(status="error", stage=None, finished_at=now_iso(), error=f"{type(e).__name__}: {e}")
            await repo.save_run(run)
        return run

    # ------------------------------------------------------------ chat
    async def chat(self, env_id: str, session: str | None, text: str, lang: str | None = None) -> dict:
        rt = self.get(env_id)
        lang = lang or self.lang(rt.env)
        session = session or uuid.uuid4().hex[:12]
        await self.ensure_seed(rt)
        hist = await rt.repo.chat_history(session, 30)
        await rt.repo.chat_add(session, "user", text)
        knowledge = await rt.repo.list_knowledge(status=["active", "proposed", "rejected"])
        sysmsg = system_prompt("chat", rt.env, rt.env.context_text(self.settings.base_dir), knowledge,
                               self.settings.app.timezone, lang)
        last = await rt.repo.last_success()
        if last:
            sysmsg += (f"\n\n# Latest daily report ({last['started_at']}, health: {last.get('health')})\n"
                       f"{last.get('summary_md', '')}\nFindings: "
                       + "; ".join(f"[{f.get('label')}] {f.get('title')}" for f in (last.get("findings") or [])[:12]))
        sysmsg += f"\n\nCurrent time (UTC): {iso(datetime.now(UTC))}"
        msgs = [{"role": m["role"], "content": m["content"]} for m in hist if m["role"] in ("user", "assistant")]
        msgs.append({"role": "user", "content": text})
        tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="chat", sources=rt.sources)
        try:
            res = await run_agent(self.llm_for(rt.env), sysmsg, msgs, tb, self.llm_cfg(rt.env).max_tool_steps)
            answer = res.text or f"_{t(lang, 'chat.empty')}_"
            trace = res.trace
        except (LLMError, ValueError) as e:
            answer, trace = f"**{t(lang, 'chat.llm_error')}** {e}", []
        await rt.repo.chat_add(session, "assistant", answer, trace)
        return {"session": session, "answer": answer, "trace": trace,
                "proposals": [p["id"] for p in tb.proposals]}

    # ------------------------------------------------------------ notifications
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

    async def inbox(self, env_id: str) -> list[dict]:
        """Unreviewed findings of recent runs, de-duplicated, most severe and newest first."""
        rt = self.get(env_id)
        runs = await rt.repo.list_runs(self.INBOX_RUNS, status="done", light=True)
        groups: dict[str, dict] = {}
        handled: set[str] = set()
        for r in runs:  # newest first
            for f in r.get("findings") or []:
                if f.get("label") in self.INBOX_SKIP:
                    continue
                key = self.finding_key(f)
                if f.get("user_status", "new") != "new":
                    handled.add(key)  # a decision on any occurrence settles the group
                    continue
                g = groups.setdefault(key, {"key": key, "finding": f, "run_id": r["run_id"],
                                            "run_started": r.get("started_at"), "refs": [], "seen": 0,
                                            "first_seen": r.get("started_at")})
                g["refs"].append({"run_id": r["run_id"], "fid": f.get("id")})
                g["seen"] += 1
                g["first_seen"] = r.get("started_at")
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        lab = {"real_incident": 0, "detection_gap": 1, "baseline_increase": 2, "investigate": 3, "false_positive": 4}
        items = [g for k, g in groups.items() if k not in handled]
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

    # ------------------------------------------------------------ rule drafts
    def deploy_ready(self, env: Environment) -> bool:
        """Deployment is on, the environment has an API, and a separate deploy user is configured."""
        cfg = env.rule_deploy
        return bool(cfg.enabled and env.api and (self.demo or cfg.username))

    def _deploy_api(self, rt: EnvRuntime):
        """Write-enabled API client (separate user) — or the demo fake. None when deployment is off."""
        cfg = rt.env.rule_deploy
        if not self.deploy_ready(rt.env):
            return None
        if self.demo:
            return rt.api
        ep = rt.env.api.model_copy(update={"username": cfg.username, "password": cfg.password,
                                           "timeout": max(rt.env.api.timeout, 60)})
        return WazuhAPI(ep)

    async def _rule_entry(self, rt: EnvRuntime, kid: str) -> dict:
        d = await rt.store.get("knowledge", kid)
        if not d or d.get("env") != rt.env.id or d.get("kind") != "rule_draft":
            raise KeyError(kid)
        return d

    async def rule_view(self, env_id: str, kid: str) -> dict:
        rt = self.envs[env_id]
        d = await self._rule_entry(rt, kid)
        xml = rulemod.extract_xml(d)
        an = await rulemod.analyse(xml, rt.env.rule_deploy, rt.api, rt.env.high_level)
        return {"analysis": an, "deploy_enabled": self.deploy_ready(rt.env),
                "file": rt.env.rule_deploy.file, "deploy": d.get("deploy"),
                "commands": rulemod.commands(kid, xml, rt.env.rule_deploy, d.get("title", ""), an["ids"],
                                             d.get("tests"))}

    async def rule_deploy(self, env_id: str, kid: str, actor: str, confirm: str = "", remove: bool = False) -> dict:
        rt = self.envs[env_id]
        api = self._deploy_api(rt)
        if api is None:
            raise PermissionError("rule deployment is off for this environment "
                                  "(rule_deploy.enabled with a separate username/password)")
        if rt.deploy_lock.locked():
            raise RuntimeError("another deployment is in progress")
        async with rt.deploy_lock:
            d = await self._rule_entry(rt, kid)
            xml = rulemod.extract_xml(d)
            an = await rulemod.analyse(xml, rt.env.rule_deploy, rt.api, rt.env.high_level)
            ids = an["ids"]
            if not remove:
                if not an["ok"]:
                    raise ValueError("; ".join(an["errors"]))
                if an["risky"] and confirm.replace(" ", "") != ",".join(ids):
                    raise PermissionError("this draft silences or lowers alerts; type the rule id(s) to confirm: "
                                          + ",".join(ids))
            rec = {"state": "running", "action": "remove" if remove else "deploy", "at": now_iso(), "by": actor,
                   "file": rt.env.rule_deploy.file, "ids": ids, "risky": an["risky"]}
            try:
                rec["steps"] = await rulemod.apply(api, rt.env.rule_deploy, kid, xml, ids, d.get("title", ""),
                                                   d.get("tests"), remove=remove,
                                                   replayable=an.get("replayable", True))
                rec["state"] = "removed" if remove else "deployed"
            except rulemod.DeployError as e:
                rec.update(state="failed", error=str(e)[:500], steps=getattr(e, "steps", None))
            except WazuhAPIError as e:  # e.g. wrong deploy credentials — nothing was written
                rec.update(state="failed", error=f"{e}"[:500],
                           steps=[{"step": "connect as " + (rt.env.rule_deploy.username or "?"), "ok": False,
                                   "detail": "nothing was changed"}])
            finally:
                if api is not rt.api:
                    await api.close()
            async with self.run_lock(f"k:{kid}"):
                d = await self._rule_entry(rt, kid)
                hist = (d.get("deploy_history") or [])[-9:]
                if d.get("deploy"):
                    hist.append({k: v for k, v in d["deploy"].items() if k != "steps"})
                patch = {"deploy": rec, "deploy_history": hist, "updated_at": now_iso()}
                if rec["state"] == "deployed":
                    patch["status"] = "active"
                elif rec["state"] == "removed":
                    patch["status"] = "closed"
                d.update(patch)
                await rt.store.put("knowledge", kid, d)
            log.info("rule %s %s by %s: %s", kid, rec["action"], actor, rec["state"])
            await self._notify_rule(rt, d, rec, transport=self.notify_transport)
            return rec

    # ------------------------------------------------------------ live verification / promotion
    async def verify_rules(self, env_id: str, kid: str | None = None) -> list[dict]:
        """Has a deployed / approved / promoted rule draft fired on real events since then?"""
        rt = self.get(env_id)
        if kid:
            rows = [await self._rule_entry(rt, kid)]
        else:
            rows = await rt.repo.list_knowledge(kinds=["rule_draft"], status=["active", "closed"], size=500)
        now = datetime.now(UTC)
        out = []
        for d in rows:
            dep, prom = d.get("deploy") or {}, d.get("promoted") or {}
            if dep.get("state") == "deployed":
                since = dep.get("at")
            elif prom.get("at"):
                since = prom["at"]
            elif d.get("status") == "active":
                since = d.get("approved_at") or d.get("updated_at")
            else:
                continue
            if not since or (not kid and (now - _parse(since)).days > 60):
                continue  # verified long ago or too old to matter
            ids = [r["id"] for r in rulemod.parse(rulemod.extract_xml(d))[0] if r.get("id")] or d.get("rule_ids") or []
            if not ids:
                continue
            r = await rt.ix.search(rt.env.alerts_index, {
                "size": 0, "query": {"bool": {"filter": [{"terms": {"rule.id": ids}},
                                                         {"range": {"timestamp": {"gte": since}}}]}},
                "aggs": {"r": {"terms": {"field": "rule.id", "size": len(ids)},
                               "aggs": {"f": {"min": {"field": "timestamp"}}, "l": {"max": {"field": "timestamp"}},
                                        "a": {"terms": {"field": "agent.name", "size": 3}}}}}})
            seen = {b["key"]: {"n": b["doc_count"], "first": b["f"].get("value_as_string"),
                               "last": b["l"].get("value_as_string"), "agents": [a["key"] for a in b["a"]["buckets"]]}
                    for b in r["aggregations"]["r"]["buckets"]}
            v = {"checked_at": iso(now), "since": since, "ids": ids, "seen": seen,
                 "state": "seen" if seen else "waiting",
                 "last": max((x["last"] or "" for x in seen.values()), default=None),
                 "waiting_days": None if seen else (now - _parse(since)).days}
            if (d.get("verify") or {}).get("state") != v["state"] and seen:
                log.info("%s: rule draft %s confirmed on live events (%s)", env_id, d["id"], ", ".join(seen))
            await rt.repo.update_knowledge(d["id"], verify=v)
            out.append({"id": d["id"], **v})
        return out

    async def promote_view(self, env_id: str, kid: str, actor: str = "") -> dict:
        from . import promote
        rt = self.get(env_id)
        d = await self._rule_entry(rt, kid)
        xml = rulemod.extract_xml(d)
        an = await rulemod.analyse(xml, rt.env.rule_deploy.model_copy(update={"id_min": 0, "id_max": 10**7}),
                                   rt.api, rt.env.high_level)
        # existing ids are fine here when they are the ones this draft deployed (file == rule_deploy.file)
        errors = [e for e in an["errors"] if "already exists in " + rt.env.rule_deploy.file not in e]
        pkg = promote.package(rt.env, d, xml, an, self.lang(rt.env), actor)
        pkg["errors"] = errors
        return pkg

    async def mark_promoted(self, env_id: str, kid: str, actor: str) -> dict:
        rt = self.get(env_id)
        d = await self._rule_entry(rt, kid)
        if (d.get("deploy") or {}).get("state") == "deployed":
            raise ValueError("remove the draft from " + rt.env.rule_deploy.file + " first")
        ids = [r["id"] for r in rulemod.parse(rulemod.extract_xml(d))[0] if r.get("id")]
        rec = {"at": iso(datetime.now(UTC)), "by": actor, "file": rt.env.promote.rules_file, "ids": ids}
        return await rt.repo.update_knowledge(kid, promoted=rec, status="closed")

    async def audit(self, env_id: str, month: str | None = None) -> dict:
        from . import audit
        return await audit.build(self, env_id, month)

    # ------------------------------------------------------------ incident records
    async def incident_draft(self, env_id: str, run_id: str, fid: str, actor: str = "", lang: str | None = None) -> dict:
        from . import incident as inc
        from .i18n import OUTPUT_LANGUAGE
        rt = self.get(env_id)
        lang = lang or self.lang(rt.env)
        run = await rt.repo.get_run(run_id)
        f = next((x for x in (run or {}).get("findings") or [] if x.get("id") == fid), None)
        if not f:
            raise KeyError(fid)
        cfg = rt.env.incident
        tpl = cfg.template or None
        p = rt.env.resolve(self.settings.base_dir, cfg.template_file)
        if p and p.exists():
            tpl = p.read_text(encoding="utf-8")
        rid = (f.get("incident") or {}).get("id") or inc.record_id(cfg.id_prefix)
        skel = inc.skeleton(lang, tpl, rid, f.get("title", ""), actor)
        sysmsg = inc.SYSTEM.format(language=OUTPUT_LANGUAGE.get(lang, "English"), tz=self.settings.app.timezone)
        ctx = rt.env.context_text(self.settings.base_dir)
        usr = (f"# Environment\n{rt.env.name}\n{ctx[:4000]}\n\n# Finding (from the daily review {run.get('started_at')})\n"
               f"{json.dumps({k: f.get(k) for k in ('title', 'label', 'severity', 'detail', 'evidence', 'rule_ids', 'agents', 'recommendation', 'user_status', 'user_note')}, ensure_ascii=False)}\n\n"
               f"# Review window\n{json.dumps(run.get('window'), ensure_ascii=False)}\n\n# TEMPLATE\n{skel}")
        tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="chat", sources=rt.sources)
        tb._handlers.pop("propose_knowledge", None)
        try:
            if self.llm_cfg(rt.env).provider == "mock":   # demo: no model to write it
                raise LLMError("demo mode")
            res = await run_agent(self.llm_for(rt.env), sysmsg, [{"role": "user", "content": usr}], tb,
                                  min(self.llm_cfg(rt.env).max_tool_steps, 12))
            md = inc.clean(res.text) or inc.deterministic(lang, tpl, rid, f, run, actor)
            ai = True
        except LLMError as e:
            log.warning("incident draft without AI: %s", e)
            md, ai = inc.deterministic(lang, tpl, rid, f, run, actor), False
        rec = {"id": rid, "md": md, "at": iso(datetime.now(UTC)), "by": actor, "ai": ai,
               **({"ticket": f["incident"]["ticket"]} if (f.get("incident") or {}).get("ticket") else {})}
        async with self.run_lock(run_id):
            run = await rt.repo.get_run(run_id)
            for x in run.get("findings") or []:
                if x.get("id") == fid:
                    x["incident"] = rec
            await rt.repo.save_run(run)
        return rec

    async def incident_ticket(self, env_id: str, run_id: str, fid: str, md: str | None = None,
                              provider: str = "zammad") -> dict:
        from . import incident as inc
        rt = self.get(env_id)
        if provider == "jira":
            cfg = rt.env.incident.jira
            if not cfg:
                raise PermissionError("Jira is not configured (incident.jira)")
        else:
            cfg = rt.env.incident.zammad
            if not cfg:
                raise PermissionError("Zammad is not configured (incident.zammad)")
        async with self.run_lock(run_id):
            run = await rt.repo.get_run(run_id)
            f = next((x for x in (run or {}).get("findings") or [] if x.get("id") == fid), None)
            if not f or not f.get("incident"):
                raise KeyError(fid)
            if f["incident"].get("ticket"):
                return f["incident"]["ticket"]
            if md:
                f["incident"]["md"] = md
            title = f"{f['incident']['id']} — {f.get('title', '')}"
            if provider == "jira":
                t = await inc.jira_ticket(cfg, title, f["incident"]["md"], transport=self.notify_transport)
                t["provider"] = "jira"
            else:
                t = await inc.zammad_ticket(cfg, title, f["incident"]["md"], transport=self.notify_transport)
                t["provider"] = "zammad"
            f["incident"]["ticket"] = t
            await rt.repo.save_run(run)
        return t

    async def chat_from_finding(self, env_id: str, run_id: str, fid: str, lang: str | None = None) -> str:
        """Open a chat session pre-filled with a finding and its manual checks (no LLM call)."""
        rt = self.get(env_id)
        lang = lang or self.lang(rt.env)
        run = await rt.repo.get_run(run_id)
        f = next((x for x in (run or {}).get("findings") or [] if x.get("id") == fid), None)
        if not f:
            raise KeyError(fid)
        session = uuid.uuid4().hex[:12]
        lines = [f"### {f.get('title')}", "", f"**{t(lang, 'label.' + f.get('label', 'investigate'))}** · "
                 f"{t(lang, 'sev.' + f.get('severity', 'medium'))} · {t(lang, 'rep.title')} {run.get('started_at', '')[:16]}",
                 "", f.get("detail") or ""]
        if f.get("evidence"):
            lines += [""] + [f"- {e}" for e in f["evidence"]]
        if f.get("recommendation"):
            lines += ["", f"**{t(lang, 'rep.recommendation')}** {f['recommendation']}"]
        checks = f.get("manual_checks") or []
        if checks:
            lines += ["", f"**{t(lang, 'inbox.checks_title')}**"]
            for c in checks:
                lines += ["", f"`{c.get('host')}` — {c.get('purpose') or ''}", "```sh", c.get("command", ""), "```"]
            lines += ["", t(lang, "inbox.paste_output")]
        else:
            lines += ["", t(lang, "inbox.ask_next")]
        await rt.repo.chat_add(session, "user", t(lang, "inbox.chat_open", title=f.get("title", "")))
        await asyncio.sleep(0.005)  # chat order is by millisecond timestamp
        await rt.repo.chat_add(session, "assistant", "\n".join(lines))
        return session

    async def chat_from_knowledge(self, env_id: str, kid: str, lang: str | None = None) -> str:
        """Open a chat session about one knowledge entry (e.g. a rule draft whose deployment failed)."""
        rt = self.get(env_id)
        lang = lang or self.lang(rt.env)
        d = await rt.store.get("knowledge", kid)
        if not d or d.get("env") != rt.env.id:
            raise KeyError(kid)
        session = uuid.uuid4().hex[:12]
        lines = [f"### {d.get('title', '')}", "", f"`{d.get('kind')}` · {d.get('status')} · id `{kid}`"]
        if d.get("rule_ids"):
            lines += ["", "Rules: " + ", ".join(d["rule_ids"])]
        if d.get("body"):
            lines += ["", d["body"]]
        xml = rulemod.extract_xml(d) if d.get("kind") == "rule_draft" else ""
        if xml:
            lines += ["", "```xml", xml.strip(), "```"]
        dep = d.get("deploy") or {}
        if dep.get("state") == "failed":
            lines += ["", f"**{t(lang, 'kb.chat_deploy_failed')}** {dep.get('error', '')}"]
            lines += [f"- {'✓' if x.get('ok') else '✗'} {x.get('step')} {x.get('detail', '')}"[:400]
                      for x in dep.get("steps") or []]
        lines += ["", t(lang, "kb.chat_ask")]
        await rt.repo.chat_add(session, "user", t(lang, "kb.chat_open", title=d.get("title", "")))
        await asyncio.sleep(0.005)
        await rt.repo.chat_add(session, "assistant", "\n".join(lines))
        return session

    # ------------------------------------------------------------ connection test
    async def check(self, env_id: str, with_llm: bool = True) -> list[dict]:
        """Checks every dependency of one environment; used by the UI button and `python -m app.check`."""
        rt = self.get(env_id)
        env = rt.env
        out: list[dict] = []

        async def step(key, coro):
            try:
                detail = await coro
                out.append({"key": key, "ok": True, "detail": detail})
            except Exception as e:  # noqa: BLE001
                out.append({"key": key, "ok": False, "detail": f"{type(e).__name__}: {e}"})

        async def indexer():
            h = await rt.ix.cluster_health()
            return f"{env.indexer.url} — cluster {h.get('cluster_name', '?')} status {h.get('status')}"

        async def alerts():
            n = await rt.ix.count(env.alerts_index, {"range": {"timestamp": {"gte": "now-24h"}}})
            if n == 0:
                raise RuntimeError(f"0 alerts in `{env.alerts_index}` — wrong index pattern or no read permission?")
            return f"{n:,} in `{env.alerts_index}`"

        async def vulns():
            n = await rt.ix.count(env.vuln_index, {"match_all": {}})
            return f"{n:,} documents in `{env.vuln_index}`" + (" (empty or not readable — optional)" if n == 0 else "")

        async def storage():
            await rt.store.ensure()
            probe = f"_probe_{env.id}"
            await rt.store.put("knowledge", probe, {"id": probe, "env": "__meta__", "kind": "probe",
                                                    "status": "closed", "title": "probe", "created_at": now_iso(),
                                                    "updated_at": now_iso()})
            await rt.store.delete("knowledge", probe)
            return f"`{env.storage_prefix}-*`"

        async def api():
            if not rt.api:
                return "not configured (optional: agent/manager health and logtest disabled)"
            info = await rt.api.info()
            return f"{env.api.url} — Wazuh {info.get('api_version')}"

        async def llm():
            cfg = self.llm_cfg(env)
            r = await self.llm_for(env).complete("Reply with the single word OK.",
                                                 [{"role": "user", "content": "ping"}], [])
            return f"{cfg.provider} {cfg.model or ''} → {r.text[:40]!r}"

        await step("indexer", indexer())
        await step("alerts", alerts())
        await step("vulns", vulns())
        await step("storage", storage())
        await step("api", api())
        src = rt.sources
        if src.get("prometheus"):
            async def prom():
                r = await src["prometheus"].query("count(up == 1)")
                return f"{src['prometheus'].c.base_url} — {r['series'][0]['value'] if r['series'] else 0} targets up"
            await step("prometheus", prom())
        if src.get("loki"):
            async def loki():
                return f"{src['loki'].c.base_url} — {len(await src['loki'].labels())} labels"
            await step("loki", loki())
        if env.sources.kubernetes.enabled:
            async def k8s():
                if not src.get("kubernetes"):
                    raise RuntimeError("Kubernetes source could not start (see the log)")
                r = await src["kubernetes"].get("nodes", limit=50)
                return f"{r['count']} nodes, " + f"{sum(1 for n in r['items'] if n.get('ready') == 'True')} ready"
            await step("kubernetes", k8s())
        if with_llm:
            await step("llm", llm())
        return out

    # ------------------------------------------------------------ scheduler
    def start_scheduler(self):
        if self._sched_task is None:
            self._sched_task = asyncio.create_task(self._scheduler())

    async def _scheduler(self):
        log.info("scheduler started (%s)", self.settings.app.timezone)
        while True:
            try:
                now = datetime.now(self.tz)
                hm = now.strftime("%H:%M")
                day = DAYS[now.weekday()]
                for rt in self.envs.values():
                    s = rt.env.schedule
                    if not (s.enabled and day in s.days and hm in s.all_times):
                        continue
                    key = f"{rt.env.id}:{now:%Y-%m-%d}:{hm}"
                    if key not in self._fired:
                        self._fired.add(key)
                        if not rt.current_run:
                            log.info("scheduled run: %s (%s)", rt.env.id, hm)
                            await self.start_run(rt.env.id, trigger="schedule")
            except Exception:  # noqa: BLE001
                log.exception("scheduler error")
            try:
                await self._liveness_tick()
            except Exception:  # noqa: BLE001
                log.exception("liveness scheduler error")
            await asyncio.sleep(20)

    def next_run(self, env: Environment, lang: str = "en") -> str | None:
        s = env.schedule
        if not s.enabled:
            return None
        now = datetime.now(self.tz)
        names = t(lang, "days").split(",")
        for i in range(8):
            for tm in s.all_times:
                hh, mm = map(int, tm.split(":"))
                d = (now + timedelta(days=i)).replace(hour=hh, minute=mm, second=0, microsecond=0)
                if d > now and DAYS[d.weekday()] in s.days:
                    return f"{d:%d.%m} {names[d.weekday()]} {d:%H:%M}"
        return None

    async def close(self):
        for rt in self.envs.values():
            await rt.ix.close()
            if rt.api:
                await rt.api.close()
            for src in rt.sources.values():
                await src.close()


def _neg_ts(ts: str | None) -> float:
    try:
        return -_parse(ts).timestamp()
    except Exception:  # noqa: BLE001
        return 0.0


# ---------------------------------------------------------------------- report normalisation
def _as_list(v) -> list:
    if isinstance(v, str):  # some models send arrays as JSON-encoded strings
        try:
            v = json.loads(v)
        except ValueError:
            return [v] if v.strip() else []
    if isinstance(v, dict):
        v = [v]
    return v if isinstance(v, list) else []


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(f"- {_s(x)}" for x in v)
    return json.dumps(v, ensure_ascii=False)


def normalize_report(sub: dict | None, fallback_text: str = "", lang: str = "en") -> dict:
    """Force model output into the schema so one malformed field cannot fail a paid run."""
    sub = sub if isinstance(sub, dict) else {}
    findings = []
    for f in _as_list(sub.get("findings")):
        if isinstance(f, str):
            f = {"title": f}
        if not isinstance(f, dict):
            continue
        f = {k: (_s(v) if k in ("title", "detail", "recommendation", "rule_draft_xml", "label", "severity") else v)
             for k, v in f.items()}
        for k in ("evidence", "rule_ids", "agents"):
            f[k] = [_s(x) for x in _as_list(f.get(k))]
        f["manual_checks"] = [{"host": _s(c.get("host")), "purpose": _s(c.get("purpose")), "command": _s(c.get("command"))}
                              for c in _as_list(f.get("manual_checks")) if isinstance(c, dict) and c.get("command")][:8]
        if f.get("label") not in LABELS:
            f["label"] = "investigate"
        if f.get("severity") not in SEVERITIES:
            f["severity"] = "medium"
        f["title"] = f.get("title") or t(lang, "untitled")
        f["id"] = f"f{len(findings) + 1}"
        f.setdefault("user_status", "new")
        findings.append(f)
    questions = []
    for q in _as_list(sub.get("questions")):
        if isinstance(q, str):
            q = {"question": q}
        if not isinstance(q, dict) or not q.get("question"):
            continue
        questions.append({"id": f"q{len(questions) + 1}", "question": _s(q.get("question")),
                          "why": _s(q.get("why")), "answer": None})
    summary = _s(sub.get("summary_md")) or fallback_text or t(lang, "run.no_report")
    return {"summary_md": summary, "health_assessment": _s(sub.get("health_assessment")),
            "findings": findings, "questions": questions,
            "open_items": [_s(x) for x in _as_list(sub.get("open_items"))],
            "closed_items": [_s(x) for x in _as_list(sub.get("closed_items"))]}


def _fmt_local(ts: str, tz) -> str:
    try:
        return _parse(ts).astimezone(tz).strftime("%d.%m %H:%M")
    except (ValueError, TypeError):
        return ts


def flags_only_report(flags: list[dict], err: str, lang: str, key: str = "run.ai_failed") -> dict:
    """Report built from deterministic flags only (used when the LLM is unavailable)."""
    findings = []
    for f in flags:
        if f.get("severity") == "info":
            continue
        crit = f.get("severity") == "critical"
        findings.append({"id": f"f{len(findings) + 1}", "label": "investigate", "severity": "high" if crit else "medium",
                         "title": f.get("message", f.get("code", "")), "detail": f"`{f.get('code')}`",
                         "evidence": [], "rule_ids": [], "agents": [], "user_status": "new"})
    return {"summary_md": t(lang, key, err=err[:300]), "health_assessment": "",
            "findings": findings, "questions": [], "open_items": [], "closed_items": []}


def _compact(c: dict) -> dict:
    """Shrink the summary sent to the LLM: hourly buckets become a plain count list."""
    c = dict(c)
    v = dict(c.get("volume") or {})
    if v.get("hourly"):
        v["hourly"] = {"start": v["hourly"][0]["t"], "step": "1h", "counts": [h["n"] for h in v["hourly"]]}
        v.pop("empty_hours", None)
    c["volume"] = v
    return c


def demo_enabled() -> bool:
    return os.environ.get("WDT_DEMO", "").lower() in ("1", "true", "yes")
