# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Settings, watch and backup: pages and JSON API. Everything under ``/settings`` and ``/backup`` needs the
``admin`` permission (``web.auth.explicit_perm``), including the GET routes."""
from __future__ import annotations

import base64
import binascii

import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field, ValidationError

from .. import auditlog
from ..backup import MIN_PASSPHRASE, BackupError
from ..privacy import DETECTORS, Masker
from ..settingsdoc import CHANNELS, TRIGGERS, TUNABLE, EnvSettings, MaskProfile
from .common import actor
from .common import ctx as _ctx
from .common import env as _env
from .common import runtime as _rt
from .common import safe as _safe
from .ui import tpl

router = APIRouter()
MAX_UPLOAD_B64 = 140 * 1024 * 1024


def _problem(e: Exception) -> str:
    if isinstance(e, ValidationError):
        return "; ".join(f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()[:6])
    return str(e)


def _detectors() -> list[dict]:
    return [{"kind": d.kind, "secret": d.secret} for d in DETECTORS] + [{"kind": "ip", "secret": False}]


# ------------------------------------------------------------------ pages
@router.get("/e/{env_id}/settings", response_class=HTMLResponse)
async def settings_page(request: Request, env_id: str):
    er = _env(request, env_id)
    rt = _rt(request)
    st = await _safe(rt.env_settings(er, fresh=True), EnvSettings(), request=request)
    storage = await _safe(rt.storage_status(env_id), None, request=request)
    ncfg = rt.settings.notify_for(er.env)
    bcfg = rt.backup_cfg()
    events = await _safe(er.repo.list_events(200), [], request=request)
    sugg = [e for e in events if (e.get("suggestion") or {}).get("state") == "open"]
    return tpl.TemplateResponse(request, "settings.html", _ctx(
        request, er=er, env=er.env, st=st, storage=storage, channels=ncfg.channels, all_channels=CHANNELS,
        triggers=TRIGGERS, detectors=_detectors(), suggestions=sugg, tunable=TUNABLE,
        s3_on=bcfg.s3.enabled, s3_bucket=bcfg.s3.bucket if bcfg.s3.enabled else "",
        auto_possible=bcfg.s3.enabled and len(bcfg.passphrase) >= MIN_PASSPHRASE, min_pass=MIN_PASSPHRASE,
        yaml_schedule=er.env.schedule, schedule=st.schedule(er.env.schedule),
        yaml_rules=er.env.watch_rules, yaml_groups=er.env.watch_groups, privacy_mode=er.env.privacy.mode,
        backup_age=rt._backup_age_days(storage) if storage else None))


@router.get("/e/{env_id}/watch", response_class=HTMLResponse)
async def watch_page(request: Request, env_id: str, status: str | None = None):
    er = _env(request, env_id)
    rt = _rt(request)
    st = await _safe(rt.env_settings(er), EnvSettings(), request=request)
    events = await _safe(er.repo.list_events(200, status=status or None), [], request=request)
    state = await _safe(rt.watch_state(er), {}, request=request)
    return tpl.TemplateResponse(request, "watch.html", _ctx(request, er=er, env=er.env, st=st, events=events,
                                                            state=state, status=status))


# ------------------------------------------------------------------ settings
class SettingsReq(BaseModel):
    watch: dict | None = None
    ai: dict | None = None
    backup: dict | None = None
    mask: dict | None = None
    confirm: bool = False            # required when a built-in detector is being switched off


async def _save(request: Request, env_id: str, patch: dict, confirm: bool) -> dict:
    er = _env(request, env_id)
    rt = _rt(request)
    cur = await rt.env_settings(er, fresh=True)
    if patch.get("mask") is not None:
        try:
            new_mask = MaskProfile.model_validate({**patch["mask"], "version": cur.mask.version})
        except ValidationError as e:
            raise HTTPException(400, _problem(e)) from e
        newly_off = sorted(set(new_mask.disabled) - set(cur.mask.disabled))
        if newly_off and not confirm:
            raise HTTPException(409, f"confirm: switching off {', '.join(newly_off)} sends that data to the model")
        if newly_off:
            auditlog.record("privacy.detector_disabled", actor=actor(request), role="admin", env=env_id,
                            target=",".join(newly_off), result="confirmed")
        patch["mask"] = new_mask.model_dump()
    try:
        st = await rt.save_settings(env_id, patch, actor(request))
    except (ValidationError, ValueError) as e:
        raise HTTPException(400, _problem(e)) from e
    return {"ok": True, "settings": st.model_dump(), "next": rt.next_run(er.env, "en")}


@router.get("/api/e/{env_id}/settings")
async def api_settings_get(request: Request, env_id: str):
    er = _env(request, env_id)
    return (await _rt(request).env_settings(er, fresh=True)).model_dump()


@router.post("/api/e/{env_id}/settings")
async def api_settings_save(request: Request, env_id: str, body: SettingsReq):
    patch = {k: v for k, v in body.model_dump(exclude={"confirm"}).items() if v is not None}
    if not patch:
        raise HTTPException(400, "nothing to save")
    return await _save(request, env_id, patch, body.confirm)


class PreviewReq(BaseModel):
    text: str = Field(max_length=20_000)
    mask: dict | None = None         # an unsaved profile, to try a pattern before saving it


@router.post("/api/e/{env_id}/settings/mask/preview")
async def api_mask_preview(request: Request, env_id: str, body: PreviewReq):
    """What the model would see. Runs locally; nothing is sent anywhere and nothing is stored."""
    er = _env(request, env_id)
    cur = await _rt(request).env_settings(er)
    try:
        prof = MaskProfile.model_validate(body.mask) if body.mask is not None else cur.mask
    except ValidationError as e:
        raise HTTPException(400, _problem(e)) from e
    p = er.env.privacy
    m = Masker(kinds=p.kinds or None, ips=p.ips, allow=list(p.allow) + prof.allow, scope=f"preview:{env_id}",
               custom=[(d.name, d.pattern) for d in prof.custom], disabled=prof.disabled)
    return {"masked": m.mask(body.text), "counts": m.counts, "mode": p.mode}


@router.get("/api/e/{env_id}/settings/mask.yaml")
async def api_mask_export(request: Request, env_id: str):
    er = _env(request, env_id)
    st = await _rt(request).env_settings(er, fresh=True)
    doc = {"format": "wazuh-daily-triage-mask-profile", "version": st.mask.version, **st.mask.content()}
    return Response(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), media_type="application/yaml",
                    headers={"Content-Disposition": f'attachment; filename="mask-profile-{env_id}.yaml"'})


class MaskImportReq(BaseModel):
    text: str = Field(max_length=200_000)
    confirm: bool = False


@router.post("/api/e/{env_id}/settings/mask/import")
async def api_mask_import(request: Request, env_id: str, body: MaskImportReq):
    try:
        raw = yaml.safe_load(body.text) or {}
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML: {e}") from e
    if not isinstance(raw, dict):
        raise HTTPException(400, "the file is not a masking profile")
    mask = {k: raw.get(k) or [] for k in ("custom", "allow", "disabled")}
    return await _save(request, env_id, {"mask": mask}, body.confirm)


class SuggestionReq(BaseModel):
    event_id: str
    action: str


@router.post("/api/e/{env_id}/settings/suggestion")
async def api_suggestion(request: Request, env_id: str, body: SuggestionReq):
    _env(request, env_id)
    try:
        ev = await _rt(request).watch_suggestion(env_id, body.event_id, body.action, actor(request))
    except (ValueError, ValidationError) as e:
        raise HTTPException(400, _problem(e)) from e
    return {"ok": True, "state": ev["suggestion"]["state"]}


@router.post("/api/e/{env_id}/settings/storage/ack")
async def api_storage_ack(request: Request, env_id: str):
    _env(request, env_id)
    return {"ok": True, "acknowledged": await _rt(request).storage_ack(env_id, actor(request))}


@router.post("/api/e/{env_id}/watch/scan")
async def api_watch_scan(request: Request, env_id: str):
    _env(request, env_id)
    rt = _rt(request)
    return await rt.watch_scan(env_id, transport=rt.notify_transport)


# ------------------------------------------------------------------ backup
class ExportReq(BaseModel):
    passphrase: str
    to_s3: bool = False
    include_runs: bool = True


@router.post("/api/e/{env_id}/backup/export")
async def api_backup_export(request: Request, env_id: str, body: ExportReq):
    _env(request, env_id)
    try:
        res = await _rt(request).backup_export(env_id, body.passphrase, actor(request), to_s3=body.to_s3,
                                               include_runs=body.include_runs)
    except BackupError as e:
        raise HTTPException(400, str(e)) from e
    return {"filename": res["filename"], "data_b64": base64.b64encode(res["blob"]).decode(),
            "bytes": len(res["blob"]), "counts": res["counts"], "s3": res["s3"], "s3_error": res["s3_error"]}


class ImportReq(BaseModel):
    data_b64: str = Field(max_length=MAX_UPLOAD_B64)
    passphrase: str
    mode: str = "missing"
    dry_run: bool = True


@router.post("/api/e/{env_id}/backup/import")
async def api_backup_import(request: Request, env_id: str, body: ImportReq):
    _env(request, env_id)
    try:
        blob = base64.b64decode(body.data_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise HTTPException(400, "the upload is not valid base64") from e
    try:
        return await _rt(request).backup_import(env_id, blob, body.passphrase, body.mode, body.dry_run,
                                                actor(request))
    except BackupError as e:
        raise HTTPException(400, str(e)) from e
