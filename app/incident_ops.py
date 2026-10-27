# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Monthly audit report and incident records (draft plus ticket)."""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from .agent.runner import run_agent
from .agent.tools import ToolBox
from .collector import iso
from .i18n import OUTPUT_LANGUAGE
from .llm.base import LLMError

if TYPE_CHECKING:
    pass

log = logging.getLogger("wdt")


class IncidentMixin:
    async def audit(self, env_id: str, month: str | None = None) -> dict:
        from . import audit
        return await audit.build(self, env_id, month)

    # ------------------------------------------------------------ incident records
    async def incident_draft(self, env_id: str, run_id: str, fid: str, actor: str = "", lang: str | None = None) -> dict:
        from . import incident as inc
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
        tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="tools", sources=rt.sources)
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
