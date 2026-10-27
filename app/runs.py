# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Daily triage run lifecycle: start, guard, window, collect, analyse, save."""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from .agent.prompts import system_prompt, triage_user_message
from .agent.runner import run_agent
from .agent.tools import ToolBox
from .collector import Collector, _parse, health_status, iso
from .config import Environment
from .i18n import t
from .llm.base import LLMError
from .observability import metrics
from .reporting import _compact, flags_only_report, normalize_report
from .store import new_id, now_iso

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt")


class RunMixin:
    async def start_run(self, env_id: str, trigger: str = "manual", hours: int | None = None) -> str:
        rt = self.get(env_id)
        # check-and-set without an await in between: no race inside the event loop
        if rt.current_run or rt.lock.locked():
            raise RuntimeError(t(self.lang(rt.env), "err.busy"))
        run_id = new_id(f"{env_id}-")
        rt.current_run = run_id
        metrics.inc("wdt_runs_total", trigger=trigger)
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
        """Start where the last successful run ended, so consecutive runs cover the gap exactly once.

        The gap is used as it is: a run six hours after the previous one looks at six hours, not at
        ``window_min_hours``. ``window_min_hours`` is the fallback when there is no previous report,
        ``window_max_hours`` caps every window, and a manual ``hours`` value can only widen the window.
        """
        frm_last = None
        if last and last.get("window", {}).get("to"):
            try:
                frm_last = _parse(last["window"]["to"])
            except Exception:  # noqa: BLE001 - a corrupt stored timestamp falls back to the default window
                frm_last = None

        if frm_last is None:
            span_h = float(hours) if hours else float(env.window_min_hours)
            span_h = min(max(span_h, env.window_min_hours), env.window_max_hours)
            return to - timedelta(hours=span_h)

        frm = min(frm_last, to - timedelta(hours=float(hours))) if hours else frm_last
        if frm >= to:  # clock skew or two runs in the same second: do not analyse an empty window
            frm = to - timedelta(hours=env.window_min_hours)
        return max(frm, to - timedelta(hours=env.window_max_hours))

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

            sysmsg = system_prompt(env, env.context_text(self.settings.base_dir),
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
            metrics.observe("wdt_run_seconds", (datetime.now(UTC) - started).total_seconds())
            metrics.inc("wdt_runs_finished_total", status="done", health=str(run.get("health") or "ok"))
            metrics.observe("wdt_run_findings", len(run.get("findings") or []))
            agent = run.get("agent") or {}
            metrics.inc("wdt_llm_tokens_total", float(agent.get("input_tokens") or 0), direction="input")
            metrics.inc("wdt_llm_tokens_total", float(agent.get("output_tokens") or 0), direction="output")
        except Exception as e:  # noqa: BLE001
            log.exception("run failed %s", run_id)
            run.update(status="error", stage=None, finished_at=now_iso(), error=f"{type(e).__name__}: {e}")
            await repo.save_run(run)
            metrics.inc("wdt_runs_finished_total", status="error", health="error")
        return run
