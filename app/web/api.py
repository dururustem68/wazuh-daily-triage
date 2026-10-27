# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""JSON API consumed by app/static/app.js and the CLI-style exports."""
from __future__ import annotations

import re

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from .. import auditlog
from ..i18n import t
from ..observability import REQUEST_ID, metrics
from ..store import KNOWLEDGE_KINDS, now_iso
from .common import AUTH_DISABLED, actor, ui_lang
from .common import env as _env
from .common import role as _role
from .common import runtime as _rt
from .ui import USER_STATUSES

router = APIRouter()


class RunReq(BaseModel):
    hours: int | None = None


@router.post("/api/e/{env_id}/run")
async def api_run(request: Request, env_id: str, body: RunReq):
    _env(request, env_id)
    if body.hours is not None and not 1 <= body.hours <= 24 * 14:
        raise HTTPException(400, t(ui_lang(request), "err.hours"))
    try:
        rid = await _rt(request).start_run(env_id, "manual", body.hours)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    return {"run_id": rid}


@router.get("/api/e/{env_id}/r/{run_id}/status")
async def api_status(request: Request, env_id: str, run_id: str):
    er = _env(request, env_id)
    run = await er.repo.get_run(run_id)
    lang = ui_lang(request)
    if not run:
        return {"status": "starting", "stage": t(lang, "run.starting")}
    stage = run.get("stage")
    return {"status": run.get("status"), "stage": t(lang, f"stage.{stage}") if stage else None, "error": run.get("error")}


@router.post("/api/e/{env_id}/check")
async def api_check(request: Request, env_id: str):
    _env(request, env_id)
    lang = ui_lang(request)
    res = await _rt(request).check(env_id)
    for r in res:
        r["label"] = t(lang, f"chk.{r['key']}")
    return {"results": res}


@router.post("/api/e/{env_id}/notify-test")
async def api_notify_test(request: Request, env_id: str):
    _env(request, env_id)
    res = await _rt(request).notify_test(env_id)
    if not res:
        return {"results": [], "message": t(ui_lang(request), "env.notify_none")}
    return {"results": [{"channel": k, "ok": v == "ok", "detail": v} for k, v in res.items()]}


class FindingReq(BaseModel):
    user_status: str | None = None
    user_note: str | None = None


@router.post("/api/e/{env_id}/r/{run_id}/f/{fid}")
async def api_finding(request: Request, env_id: str, run_id: str, fid: str, body: FindingReq):
    er = _env(request, env_id)
    async with _rt(request).run_lock(run_id):
        run = await er.repo.get_run(run_id)
        f = next((x for x in (run or {}).get("findings") or [] if x.get("id") == fid), None)
        if not f:
            raise HTTPException(404)
        if body.user_status:
            if body.user_status not in USER_STATUSES:
                raise HTTPException(400, t(ui_lang(request), "err.bad_status"))
            f["user_status"] = body.user_status
        if body.user_note is not None:
            f["user_note"] = body.user_note.strip()[:2000]
        created = None
        if body.user_status == "baseline" and not f.get("knowledge_id"):
            note = f"\n\nNote: {f['user_note']}" if f.get("user_note") else ""
            k = await er.repo.add_knowledge("baseline", f.get("title", ""), (f.get("detail") or "") + note,
                                            rule_ids=f.get("rule_ids"), source_run=run_id)
            f["knowledge_id"] = created = k["id"]
        await er.repo.save_run(run)
    return {"ok": True, "knowledge_id": created}


class InboxActReq(BaseModel):
    refs: list[dict]
    user_status: str
    user_note: str | None = None


@router.post("/api/e/{env_id}/inbox/act")
async def api_inbox_act(request: Request, env_id: str, body: InboxActReq):
    _env(request, env_id)
    if body.user_status not in USER_STATUSES:
        raise HTTPException(400, t(ui_lang(request), "err.bad_status"))
    refs = [r for r in body.refs if isinstance(r.get("run_id"), str) and isinstance(r.get("fid"), str)]
    n = await _rt(request).inbox_act(env_id, refs, body.user_status, (body.user_note or "").strip() or None)
    return {"ok": True, "updated": n}


class IncidentReq(BaseModel):
    md: str | None = None
    provider: str | None = None       # "zammad" (default) | "jira"


@router.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident")
async def api_incident(request: Request, env_id: str, run_id: str, fid: str):
    _env(request, env_id)
    try:
        return await _rt(request).incident_draft(env_id, run_id, fid, actor(request), ui_lang(request))
    except KeyError as e:
        raise HTTPException(404) from e


@router.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident/save")
async def api_incident_save(request: Request, env_id: str, run_id: str, fid: str, body: IncidentReq):
    er = _env(request, env_id)
    rt = _rt(request)
    async with rt.run_lock(run_id):
        run = await er.repo.get_run(run_id)
        f = next((x for x in (run or {}).get("findings") or [] if x.get("id") == fid), None)
        if not f or not f.get("incident"):
            raise HTTPException(404)
        f["incident"].update(md=(body.md or "")[:200000], edited_by=actor(request), edited_at=now_iso())
        await er.repo.save_run(run)
    return f["incident"]


@router.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident/ticket")
async def api_incident_ticket(request: Request, env_id: str, run_id: str, fid: str, body: IncidentReq):
    _env(request, env_id)
    try:
        return await _rt(request).incident_ticket(env_id, run_id, fid, body.md, body.provider or "zammad")
    except KeyError as e:
        raise HTTPException(404) from e
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except RuntimeError as e:
        raise HTTPException(502, str(e)) from e


class AnswerReq(BaseModel):
    answer: str


@router.post("/api/e/{env_id}/r/{run_id}/q/{qid}")
async def api_answer(request: Request, env_id: str, run_id: str, qid: str, body: AnswerReq):
    er = _env(request, env_id)
    ans = body.answer.strip()[:4000]
    if not ans:
        raise HTTPException(400, t(ui_lang(request), "err.empty"))
    async with _rt(request).run_lock(run_id):
        run = await er.repo.get_run(run_id)
        q = next((x for x in (run or {}).get("questions") or [] if x.get("id") == qid), None)
        if not q:
            raise HTTPException(404)
        q["answer"] = ans
        q["answered_at"] = now_iso()
        k = await er.repo.add_knowledge("answer", q["question"], ans, source_run=run_id,
                                        extra={"question": q["question"]})
        q["knowledge_id"] = k["id"]
        await er.repo.save_run(run)
    return {"ok": True}


class KReq(BaseModel):
    kind: str | None = None
    title: str | None = None
    body: str | None = None
    status: str | None = None
    rule_ids: list[str] | None = None
    xml: str | None = None          # rule drafts: edited rule XML


@router.post("/api/e/{env_id}/k")
async def api_k_add(request: Request, env_id: str, body: KReq):
    er = _env(request, env_id)
    if not body.kind or not (body.title or "").strip():
        raise HTTPException(400, t(ui_lang(request), "err.kind_title"))
    try:
        return await er.repo.add_knowledge(body.kind, body.title, body.body or "", status=body.status or "active",
                                           rule_ids=body.rule_ids)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/api/e/{env_id}/k/{kid}")
async def api_k_update(request: Request, env_id: str, kid: str, body: KReq):
    er = _env(request, env_id)
    try:
        d = await er.repo.update_knowledge(kid, status=body.status, title=body.title, body=body.body,
                                           approved_at=now_iso() if body.status == "active" else None,
                                           kind=body.kind if body.kind in KNOWLEDGE_KINDS else None,
                                           rule_ids=body.rule_ids,
                                           xml=body.xml.strip()[:20000] if body.xml is not None else None)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not d:
        raise HTTPException(404)
    return d


@router.delete("/api/e/{env_id}/k/{kid}")
async def api_k_delete(request: Request, env_id: str, kid: str):
    er = _env(request, env_id)
    await er.repo.delete_knowledge(kid)
    return {"ok": True}


@router.get("/api/e/{env_id}/k/{kid}/rule")
async def api_rule_view(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        return await _rt(request).rule_view(env_id, kid)
    except KeyError as e:
        raise HTTPException(404) from e


class DeployReq(BaseModel):
    confirm: str = ""


async def _deploy(request: Request, env_id: str, kid: str, confirm: str, remove: bool):
    _env(request, env_id)
    try:
        rec = await _rt(request).rule_deploy(env_id, kid, actor(request), confirm, remove=remove)
    except KeyError as e:
        raise HTTPException(404) from e
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    action = "rule.undeploy" if remove else "rule.deploy"
    metrics.inc("wdt_rule_deploy_total", state=str(rec.get("state")), action=action.split(".")[-1])
    auditlog.record(action, actor=actor(request), role=_role(request) or ("proxy" if AUTH_DISABLED else "ui"),
                    env=env_id, target=kid,
                    result=f"{rec.get('state')} (rollback: {rec.get('rollback_state', 'n/a')})",
                    request_id=REQUEST_ID.get(), method="POST", path_=request.url.path,
                    detail={"ids": rec.get("ids"), "file": rec.get("file"), "risky": rec.get("risky"),
                            "error": rec.get("error")})
    return rec


@router.post("/api/e/{env_id}/k/{kid}/deploy")
async def api_rule_deploy(request: Request, env_id: str, kid: str, body: DeployReq):
    return await _deploy(request, env_id, kid, body.confirm, remove=False)


@router.post("/api/e/{env_id}/k/{kid}/undeploy")
async def api_rule_undeploy(request: Request, env_id: str, kid: str):
    return await _deploy(request, env_id, kid, "", remove=True)


@router.post("/api/e/{env_id}/k/{kid}/verify")
async def api_rule_verify(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        res = await _rt(request).verify_rules(env_id, kid)
    except KeyError as e:
        raise HTTPException(404) from e
    return res[0] if res else {"state": "not_applicable"}


@router.get("/api/e/{env_id}/k/{kid}/promote")
async def api_rule_promote(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        return await _rt(request).promote_view(env_id, kid, actor(request))
    except KeyError as e:
        raise HTTPException(404) from e


@router.post("/api/e/{env_id}/k/{kid}/promoted")
async def api_rule_promoted(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        return await _rt(request).mark_promoted(env_id, kid, actor(request))
    except KeyError as e:
        raise HTTPException(404) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.get("/api/e/{env_id}/audit.md")
async def audit_md(request: Request, env_id: str, month: str | None = None):
    from ..audit import markdown
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    return Response(markdown(d, ui_lang(request)), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.md"'})


@router.get("/api/e/{env_id}/audit.pdf")
async def audit_pdf(request: Request, env_id: str, month: str | None = None):
    from ..pdf import audit_pdf as build_pdf
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    data = build_pdf(d, ui_lang(request))
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.pdf"'})


@router.post("/api/e/{env_id}/liveness")
async def api_liveness(request: Request, env_id: str):
    _env(request, env_id)
    return await _rt(request).liveness_check(env_id, transport=_rt(request).notify_transport)


class ImportReq(BaseModel):
    text: str
    update: bool = False
    dry_run: bool = False


@router.post("/api/e/{env_id}/kb/import")
async def api_k_import(request: Request, env_id: str, body: ImportReq):
    _env(request, env_id)
    if len(body.text) > 2_000_000:
        raise HTTPException(413, "too large")
    try:
        items = yaml.safe_load(body.text) or []
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML: {e}") from e
    try:
        return await _rt(request).kb_import(env_id, items, update=body.update, dry_run=body.dry_run,
                                            created_by=actor(request))
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.get("/api/e/{env_id}/kb/export")
async def api_k_export(request: Request, env_id: str, kind: str | None = None, status: str | None = None):
    _env(request, env_id)
    rows = await _rt(request).kb_export(env_id, kinds=[kind] if kind else None, status=[status] if status else None)
    text = yaml.safe_dump(rows, allow_unicode=True, sort_keys=False, width=120)
    return Response(text, media_type="application/yaml",
                    headers={"Content-Disposition": f'attachment; filename="knowledge-{env_id}.yaml"'})
