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

from .agent.prompts import system_prompt, triage_user_message
from .agent.runner import run_agent
from .agent.tools import LABELS, SEVERITIES, ToolBox
from .collector import Collector, _parse, health_status, iso
from .config import DAYS, Environment, LLMConfig, Settings
from .i18n import t
from .llm.base import LLMError, make_llm
from .store import IndexStore, MemoryStore, Repo, new_id, now_iso
from .wazuh.api import WazuhAPI
from .wazuh.indexer import Indexer

log = logging.getLogger("wdt")
UTC = UTC


class EnvRuntime:
    def __init__(self, env: Environment, ix, api, store):
        self.env = env
        self.ix = ix
        self.api = api
        self.store = store
        self.repo = Repo(store, env.id)
        self.lock = asyncio.Lock()
        self.current_run: str | None = None


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
                await self.run_triage(rt, run_id, trigger, hours)
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

            collected = await Collector(env, rt.ix, rt.api, lang).collect(frm, started)
            flags = collected["flags"]
            run.update(window=collected["window"], flags=flags, health=health_status(flags),
                       metrics={"total": (collected.get("volume") or {}).get("total", 0),
                                "high": (collected.get("volume") or {}).get("high_level_total", 0)},
                       stage="analysing", collected=collected)
            await repo.save_run(run)

            knowledge = await repo.list_knowledge(status=["active", "proposed"],
                                                  kinds=["context", "baseline", "decision", "open_item",
                                                         "lesson", "rule_draft", "answer"])
            prev = await repo.list_runs(3, status="done", light=True)
            since = last["started_at"] if last else "1970-01-01T00:00:00Z"
            answers = [k for k in knowledge if k["kind"] == "answer" and k["created_at"] >= since]
            requests = await repo.list_knowledge(kinds=["request"], status="active")

            sysmsg = system_prompt("triage", env, env.context_text(self.settings.base_dir),
                                   [k for k in knowledge if k["kind"] != "answer"], self.settings.app.timezone, lang)
            usr = triage_user_message(_compact(collected), prev, answers, requests)
            tb = ToolBox(env, rt.ix, rt.api, repo, mode="triage", run_id=run_id)
            res = await run_agent(self.llm_for(env), sysmsg, [{"role": "user", "content": usr}], tb,
                                  llm_cfg.max_tool_steps, stop_on="submit_report")
            rep = normalize_report(tb.submitted, res.text, lang)
            run.update(
                status="done", stage=None, finished_at=now_iso(), **rep,
                proposals=[p["id"] for p in tb.proposals],
                agent={"steps": res.steps, "stopped": res.stopped, "trace": res.trace,
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
        knowledge = await rt.repo.list_knowledge(status=["active", "proposed"])
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
        tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="chat")
        try:
            res = await run_agent(self.llm_for(rt.env), sysmsg, msgs, tb, self.llm_cfg(rt.env).max_tool_steps)
            answer = res.text or f"_{t(lang, 'chat.empty')}_"
            trace = res.trace
        except (LLMError, ValueError) as e:
            answer, trace = f"**{t(lang, 'chat.llm_error')}** {e}", []
        await rt.repo.chat_add(session, "assistant", answer, trace)
        return {"session": session, "answer": answer, "trace": trace,
                "proposals": [p["id"] for p in tb.proposals]}

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
                    key = f"{rt.env.id}:{now:%Y-%m-%d}:{s.time}"
                    if s.enabled and day in s.days and hm == s.time and key not in self._fired:
                        self._fired.add(key)
                        if not rt.current_run:
                            log.info("scheduled run: %s", rt.env.id)
                            await self.start_run(rt.env.id, trigger="schedule")
            except Exception:  # noqa: BLE001
                log.exception("scheduler error")
            await asyncio.sleep(20)

    def next_run(self, env: Environment, lang: str = "en") -> str | None:
        s = env.schedule
        if not s.enabled:
            return None
        now = datetime.now(self.tz)
        hh, mm = map(int, s.time.split(":"))
        names = t(lang, "days").split(",")
        for i in range(8):
            d = (now + timedelta(days=i)).replace(hour=hh, minute=mm, second=0, microsecond=0)
            if d > now and DAYS[d.weekday()] in s.days:
                return f"{d:%d.%m} {names[d.weekday()]} {d:%H:%M}"
        return None

    async def close(self):
        for rt in self.envs.values():
            await rt.ix.close()
            if rt.api:
                await rt.api.close()


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
