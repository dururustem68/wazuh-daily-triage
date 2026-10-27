# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Server-rendered pages."""
from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from ..rules import extract_xml
from .common import ctx as _ctx
from .common import env as _env
from .common import runtime as _rt
from .common import safe as _safe
from .common import ui_lang
from .common import visible as _visible
from .ui import tpl

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    rt = _rt(request)
    lang = ui_lang(request)
    cards = []
    for er in _visible(request):
        runs = await _safe(er.repo.list_runs(8, light=True), [], request=request)
        last = next((r for r in runs if r.get("status") == "done"), None)
        props = await _safe(er.repo.list_knowledge(status="proposed"), [], request=request)
        open_q = sum(1 for q in (last or {}).get("questions") or [] if not q.get("answer"))
        new_f = sum(1 for f in (last or {}).get("findings") or []
                    if f.get("user_status") == "new" and f.get("label") in ("real_incident", "investigate", "detection_gap"))
        inbox = await _safe(rt.inbox(er.env.id), [], request=request)
        top = [dict(it, idx=i) for i, it in enumerate(inbox)][:10]
        urgent = sum(1 for it in inbox if it["finding"].get("label") in ("real_incident", "detection_gap")
                     or it["finding"].get("severity") in ("critical", "high"))
        # unanswered questions across recent runs (newest first, same question once)
        questions, seen_q = [], set()
        for r in runs:
            for q in r.get("questions") or []:
                k = (q.get("question") or "").strip().lower()
                if not q.get("answer") and k and k not in seen_q:
                    seen_q.add(k)
                    questions.append({"q": q, "run_id": r["run_id"], "at": r.get("started_at")})
        kb = await _safe(er.repo.list_knowledge(status=["proposed", "active"], size=500), [], request=request)
        rules = sorted([k for k in kb if k["kind"] == "rule_draft"],
                       key=lambda k: (k["status"] != "proposed", ((k.get("deploy") or {}).get("state") == "deployed"),
                                      k.get("updated_at", "")), reverse=False)
        requests = [k for k in kb if k["kind"] == "request" and k["status"] == "active"]
        open_items = [k for k in kb if k["kind"] == "open_item" and k["status"] == "active"]
        other_props = [k for k in kb if k["status"] == "proposed" and k["kind"] != "rule_draft"]
        live = await _safe(rt.liveness_state(er.env.id), None, request=request) if er.env.liveness.enabled else None
        cards.append({"env": er.env, "last": last, "running": er.current_run, "next": rt.next_run(er.env, lang), "live": live,
                      "proposals": len(props), "open_q": open_q, "new_f": new_f, "inbox": len(inbox),
                      "top": top, "urgent": urgent, "questions": questions[:6], "rules": rules[:6],
                      "requests": requests[:6], "open_items": open_items[:6],
                      "report_open": (last or {}).get("open_items") or [], "other_props": other_props[:6]})
    return tpl.TemplateResponse(request, "dashboard.html", _ctx(request, cards=cards))


@router.get("/e/{env_id}", response_class=HTMLResponse)
async def env_page(request: Request, env_id: str):
    er = _env(request, env_id)
    runs = await _safe(er.repo.list_runs(60, light=True), [], request=request)
    return tpl.TemplateResponse(request, "env.html", _ctx(request, er=er, env=er.env, runs=runs,
                                                          next=_rt(request).next_run(er.env, ui_lang(request))))


@router.get("/e/{env_id}/r/{run_id}", response_class=HTMLResponse)
async def report_page(request: Request, env_id: str, run_id: str):
    er = _env(request, env_id)
    run = await er.repo.get_run(run_id)
    if not run:
        raise HTTPException(404)
    c = run.get("collected") or {}
    hourly = (c.get("volume") or {}).get("hourly") or []
    mx = max([h["n"] for h in hourly] or [1]) or 1
    props = []
    for pid in run.get("proposals") or []:
        d = await er.store.get("knowledge", pid)
        if d:
            props.append(d)
    return tpl.TemplateResponse(request, "report.html", _ctx(request, er=er, env=er.env, run=run, c=c,
                                                             hourly=hourly, hmax=mx, proposals=props))


@router.get("/e/{env_id}/inbox", response_class=HTMLResponse)
async def inbox_page(request: Request, env_id: str, i: int = 0):
    er = _env(request, env_id)
    items = await _safe(_rt(request).inbox(env_id), [], request=request)
    i = max(0, min(i, len(items) - 1)) if items else 0
    return tpl.TemplateResponse(request, "inbox.html", _ctx(request, er=er, env=er.env, items=items, i=i,
                                                            item=items[i] if items else None))


@router.get("/e/{env_id}/k", response_class=HTMLResponse)
async def knowledge_page(request: Request, env_id: str, kind: str | None = None, status: str | None = None):
    er = _env(request, env_id)
    await _safe(_rt(request).ensure_seed(er), 0, request=request)
    rows = await _safe(er.repo.list_knowledge(kinds=[kind] if kind else None, status=status or None, size=500), [],
                       request=request)
    order = {"proposed": 0, "active": 1, "closed": 2, "rejected": 3}
    rows.sort(key=lambda r: (order.get(r["status"], 9), r["kind"]))
    for r in rows:
        if r.get("kind") == "rule_draft":
            r["_xml"] = extract_xml(r)
    ctx_md = er.env.context_text(_rt(request).settings.base_dir) if kind in (None, "context") and not status else ""
    return tpl.TemplateResponse(request, "knowledge.html", _ctx(request, er=er, env=er.env, rows=rows,
                                                                kind=kind, status=status, ctx_md=ctx_md,
                                                                deploy_on=_rt(request).deploy_ready(er.env)))


@router.get("/e/{env_id}/audit", response_class=HTMLResponse)
async def audit_page(request: Request, env_id: str, month: str | None = None):
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    now = datetime.now(UTC)
    months = []
    y, m = now.year, now.month
    for _ in range(12):
        months.append(f"{y:04d}-{m:02d}")
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return tpl.TemplateResponse(request, "audit.html", _ctx(request, er=er, env=er.env, a=d, months=months))
