# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Web application (FastAPI + Jinja2, no build step)."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup
from pydantic import BaseModel

from . import __version__
from .agent.tools import LABELS, SEVERITIES
from .collector import _parse
from .config import LANGUAGES, load_settings
from .i18n import LANG_NAMES, t
from .rules import extract_xml
from .runtime import Runtime, demo_enabled
from .store import KNOWLEDGE_KINDS, now_iso

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("wdt")

HERE = Path(__file__).parent
_md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")

LABEL_COLORS = {"real_incident": "red", "investigate": "amber", "detection_gap": "purple", "false_positive": "gray",
                "baseline_increase": "orange", "measurement": "blue", "expected": "green", "correction": "teal"}
USER_STATUSES = ["new", "acknowledged", "false_positive", "closed", "baseline"]
HEALTH_COLORS = {"ok": "green", "warn": "amber", "critical": "red", "error": "red"}
# AGPL-3.0 §13: users interacting over a network must be offered the corresponding source.
SOURCE_URL = os.environ.get("SOURCE_URL", "https://github.com/dururustem68/wazuh-daily-triage")


# ----------------------------------------------------------------------- application
@asynccontextmanager
async def lifespan(app: FastAPI):
    demo = demo_enabled()
    cfg = os.environ.get("WDT_CONFIG") or ("config/demo.yaml" if demo else "config/environments.yaml")
    settings = load_settings(cfg)
    rt = Runtime(settings, demo=demo)
    app.state.rt = rt
    await rt.recover_stale()
    if os.environ.get("WDT_SCHEDULER", "true").lower() not in ("0", "false", "no"):
        rt.start_scheduler()
    log.info("wazuh-daily-triage %s started — %d environment(s)%s", __version__, len(settings.environments),
             " (DEMO)" if demo else "")
    yield
    await rt.close()


app = FastAPI(title="Wazuh Daily Triage", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
tpl = Jinja2Templates(directory=HERE / "templates")


def _fmt_ts(v, short=False):
    if not v:
        return "—"
    try:
        dt = _parse(v).astimezone(app.state.rt.tz)
    except Exception:  # noqa: BLE001
        return v
    return dt.strftime("%d.%m %H:%M" if short else "%d.%m.%Y %H:%M")


def _num(v):
    if isinstance(v, (int, float)):
        return f"{int(v):,}"
    return v if v is not None else "—"


tpl.env.filters["md"] = lambda s: Markup(_md.render(s if isinstance(s, str) else str(s or "")))
tpl.env.filters["ts"] = _fmt_ts
tpl.env.filters["tss"] = lambda v: _fmt_ts(v, True)
tpl.env.filters["n"] = _num
tpl.env.globals.update(LABEL_COLORS=LABEL_COLORS, USER_STATUSES=USER_STATUSES, HEALTH_COLORS=HEALTH_COLORS,
                       KINDS=list(KNOWLEDGE_KINDS), LANGS=LANG_NAMES, version=__version__, SOURCE_URL=SOURCE_URL,
                       LABELS=LABELS, SEVERITIES=SEVERITIES)


def ui_lang(request: Request) -> str:
    c = request.cookies.get("lang")
    if c in LANGUAGES:
        return c
    try:
        return request.app.state.rt.settings.app.language
    except AttributeError:
        return "en"


# ----------------------------------------------------------------------- authentication
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
VIEWER_PASSWORD = os.environ.get("VIEWER_PASSWORD", "")   # optional read-only role
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in ("1", "true", "yes")
SECRET = (os.environ.get("APP_SECRET") or secrets.token_hex(32)).encode()
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
COOKIE = "wdt_session"
TTL = 12 * 3600
ROLES = ("admin", "viewer")


def _sign(exp: int, role: str = "admin") -> str:
    msg = f"{exp}.{role}"
    return f"{msg}.{hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()}"


def _valid(tok: str | None) -> str | None:
    """Return the session role ("admin" | "viewer") or None when the token is invalid/expired."""
    if not tok:
        return None
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    exp, role, sig = parts
    if role not in ROLES:
        return None
    try:
        msg = f"{exp}.{role}"
        ok = hmac.compare_digest(sig, hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest())
        return role if (ok and int(exp) > time.time()) else None
    except ValueError:
        return None


def _role(request: Request) -> str | None:
    """Session role of this request (None when auth is delegated to a proxy)."""
    if AUTH_DISABLED:
        return None
    return _valid(request.cookies.get(COOKIE))


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    p = request.url.path
    public = p.startswith("/static") or p in ("/login", "/healthz", "/lang", "/mcp")   # /mcp: own bearer token
    if not public and not AUTH_DISABLED:
        if not APP_PASSWORD:
            return HTMLResponse(f"<p>{t(ui_lang(request), 'auth.no_password')}</p>", status_code=503)
        role = _valid(request.cookies.get(COOKIE))
        if not role:
            if p.startswith("/api/"):
                return JSONResponse({"error": "not authenticated"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        if role == "viewer" and request.method not in ("GET", "HEAD") and p not in ("/lang", "/logout"):
            if p.startswith("/api/"):
                return JSONResponse({"error": "read-only viewer"}, status_code=403)
            return HTMLResponse(f"<p>{t(ui_lang(request), 'auth.read_only')}</p>", status_code=403)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                                               "form-action 'self'")
    return resp


def _ctx(request: Request, **kw):
    lang = ui_lang(request)
    rt = request.app.state.rt
    return {"envs": [r.env for r in rt.envs.values()], "demo": rt.demo, "app_title": rt.settings.app.title,
            "auth": not AUTH_DISABLED, "lang": lang, "_": lambda key, **a: t(lang, key, **a),
            "deploy_any": any(rt.deploy_ready(r.env) for r in rt.envs.values()), "path": request.url.path,
            "viewer": _role(request) == "viewer", "viewer_enabled": bool(VIEWER_PASSWORD), **kw}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return tpl.TemplateResponse(request, "login.html", _ctx(request, err=None))


_fails: dict[str, list[float]] = {}


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    now = time.time()
    if len(_fails) > 2000:
        for k in [k for k, v in _fails.items() if not v or now - v[-1] > 300]:
            _fails.pop(k, None)
    hist = [x for x in _fails.get(ip, []) if now - x < 300]
    lang = ui_lang(request)
    if len(hist) >= 8:
        return tpl.TemplateResponse(request, "login.html", _ctx(request, err=t(lang, "login.throttled")), status_code=429)
    if APP_PASSWORD and hmac.compare_digest(password.encode(), APP_PASSWORD.encode()):
        _fails.pop(ip, None)
        role = "admin"
    elif VIEWER_PASSWORD and hmac.compare_digest(password.encode(), VIEWER_PASSWORD.encode()):
        _fails.pop(ip, None)
        role = "viewer"
    else:
        _fails[ip] = hist + [now]
        return tpl.TemplateResponse(request, "login.html", _ctx(request, err=t(lang, "login.wrong")), status_code=401)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(COOKIE, _sign(int(now) + TTL, role), max_age=TTL, httponly=True, samesite="strict",
                 secure=COOKIE_SECURE)
    return r


@app.post("/logout")
async def logout():
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(COOKIE)
    return r


@app.post("/lang")
async def set_lang(request: Request, lang: str = Form(...)):
    back = request.headers.get("referer") or "/"
    if not back.startswith(str(request.base_url)):
        back = "/"
    r = RedirectResponse(back, status_code=303)
    code = next((x for x in LANGUAGES if x == lang), None)   # the stored value is always one of ours
    if code:
        r.set_cookie("lang", code, max_age=365 * 86400, samesite="strict", secure=COOKIE_SECURE)
    return r


from .mcp import router as mcp_router  # noqa: E402

app.include_router(mcp_router)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "version": __version__}


# ----------------------------------------------------------------------- helpers
def _rt(request: Request) -> Runtime:
    return request.app.state.rt


def _env(request: Request, env_id: str):
    try:
        return _rt(request).get(env_id)
    except KeyError:
        raise HTTPException(404, t(ui_lang(request), "err.no_env")) from None


async def _safe(coro, default):
    try:
        return await coro
    except Exception as e:  # noqa: BLE001
        log.warning("storage read failed: %s", e)
        return default


# ----------------------------------------------------------------------- pages
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    rt = _rt(request)
    lang = ui_lang(request)
    cards = []
    for er in rt.envs.values():
        runs = await _safe(er.repo.list_runs(8, light=True), [])
        last = next((r for r in runs if r.get("status") == "done"), None)
        props = await _safe(er.repo.list_knowledge(status="proposed"), [])
        open_q = sum(1 for q in (last or {}).get("questions") or [] if not q.get("answer"))
        new_f = sum(1 for f in (last or {}).get("findings") or []
                    if f.get("user_status") == "new" and f.get("label") in ("real_incident", "investigate", "detection_gap"))
        inbox = await _safe(rt.inbox(er.env.id), [])
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
        kb = await _safe(er.repo.list_knowledge(status=["proposed", "active"], size=500), [])
        rules = sorted([k for k in kb if k["kind"] == "rule_draft"],
                       key=lambda k: (k["status"] != "proposed", ((k.get("deploy") or {}).get("state") == "deployed"),
                                      k.get("updated_at", "")), reverse=False)
        requests = [k for k in kb if k["kind"] == "request" and k["status"] == "active"]
        open_items = [k for k in kb if k["kind"] == "open_item" and k["status"] == "active"]
        other_props = [k for k in kb if k["status"] == "proposed" and k["kind"] != "rule_draft"]
        live = await _safe(rt.liveness_state(er.env.id), None) if er.env.liveness.enabled else None
        cards.append({"env": er.env, "last": last, "running": er.current_run, "next": rt.next_run(er.env, lang), "live": live,
                      "proposals": len(props), "open_q": open_q, "new_f": new_f, "inbox": len(inbox),
                      "top": top, "urgent": urgent, "questions": questions[:6], "rules": rules[:6],
                      "requests": requests[:6], "open_items": open_items[:6],
                      "report_open": (last or {}).get("open_items") or [], "other_props": other_props[:6]})
    return tpl.TemplateResponse(request, "dashboard.html", _ctx(request, cards=cards))


@app.get("/e/{env_id}", response_class=HTMLResponse)
async def env_page(request: Request, env_id: str):
    er = _env(request, env_id)
    runs = await _safe(er.repo.list_runs(60, light=True), [])
    return tpl.TemplateResponse(request, "env.html", _ctx(request, er=er, env=er.env, runs=runs,
                                                          next=_rt(request).next_run(er.env, ui_lang(request))))


@app.get("/e/{env_id}/r/{run_id}", response_class=HTMLResponse)
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


@app.get("/e/{env_id}/inbox", response_class=HTMLResponse)
async def inbox_page(request: Request, env_id: str, i: int = 0):
    er = _env(request, env_id)
    items = await _safe(_rt(request).inbox(env_id), [])
    i = max(0, min(i, len(items) - 1)) if items else 0
    return tpl.TemplateResponse(request, "inbox.html", _ctx(request, er=er, env=er.env, items=items, i=i,
                                                            item=items[i] if items else None))


@app.get("/e/{env_id}/k", response_class=HTMLResponse)
async def knowledge_page(request: Request, env_id: str, kind: str | None = None, status: str | None = None):
    er = _env(request, env_id)
    await _safe(_rt(request).ensure_seed(er), 0)
    rows = await _safe(er.repo.list_knowledge(kinds=[kind] if kind else None, status=status or None, size=500), [])
    order = {"proposed": 0, "active": 1, "closed": 2, "rejected": 3}
    rows.sort(key=lambda r: (order.get(r["status"], 9), r["kind"]))
    for r in rows:
        if r.get("kind") == "rule_draft":
            r["_xml"] = extract_xml(r)
    ctx_md = er.env.context_text(_rt(request).settings.base_dir) if kind in (None, "context") and not status else ""
    return tpl.TemplateResponse(request, "knowledge.html", _ctx(request, er=er, env=er.env, rows=rows,
                                                                kind=kind, status=status, ctx_md=ctx_md,
                                                                deploy_on=_rt(request).deploy_ready(er.env)))


@app.get("/e/{env_id}/chat", response_class=HTMLResponse)
async def chat_page(request: Request, env_id: str, s: str | None = None):
    er = _env(request, env_id)
    sessions = await _safe(er.repo.chat_sessions(), [])
    hist = await _safe(er.repo.chat_history(s, 100), []) if s else []
    return tpl.TemplateResponse(request, "chat.html", _ctx(request, er=er, env=er.env, sessions=sessions,
                                                           session=s, hist=hist))


# ----------------------------------------------------------------------- API
class RunReq(BaseModel):
    hours: int | None = None


@app.post("/api/e/{env_id}/run")
async def api_run(request: Request, env_id: str, body: RunReq):
    _env(request, env_id)
    if body.hours is not None and not 1 <= body.hours <= 24 * 14:
        raise HTTPException(400, t(ui_lang(request), "err.hours"))
    try:
        rid = await _rt(request).start_run(env_id, "manual", body.hours)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    return {"run_id": rid}


@app.get("/api/e/{env_id}/r/{run_id}/status")
async def api_status(request: Request, env_id: str, run_id: str):
    er = _env(request, env_id)
    run = await er.repo.get_run(run_id)
    lang = ui_lang(request)
    if not run:
        return {"status": "starting", "stage": t(lang, "run.starting")}
    stage = run.get("stage")
    return {"status": run.get("status"), "stage": t(lang, f"stage.{stage}") if stage else None, "error": run.get("error")}


@app.post("/api/e/{env_id}/check")
async def api_check(request: Request, env_id: str):
    _env(request, env_id)
    lang = ui_lang(request)
    res = await _rt(request).check(env_id)
    for r in res:
        r["label"] = t(lang, f"chk.{r['key']}")
    return {"results": res}


@app.post("/api/e/{env_id}/notify-test")
async def api_notify_test(request: Request, env_id: str):
    _env(request, env_id)
    res = await _rt(request).notify_test(env_id)
    if not res:
        return {"results": [], "message": t(ui_lang(request), "env.notify_none")}
    return {"results": [{"channel": k, "ok": v == "ok", "detail": v} for k, v in res.items()]}


class FindingReq(BaseModel):
    user_status: str | None = None
    user_note: str | None = None


@app.post("/api/e/{env_id}/r/{run_id}/f/{fid}")
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


@app.post("/api/e/{env_id}/inbox/act")
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


@app.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident")
async def api_incident(request: Request, env_id: str, run_id: str, fid: str):
    _env(request, env_id)
    try:
        return await _rt(request).incident_draft(env_id, run_id, fid, actor(request), ui_lang(request))
    except KeyError as e:
        raise HTTPException(404) from e


@app.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident/save")
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


@app.post("/api/e/{env_id}/r/{run_id}/f/{fid}/incident/ticket")
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


@app.post("/api/e/{env_id}/k/{kid}/chat")
async def api_knowledge_chat(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        session = await _rt(request).chat_from_knowledge(env_id, kid, ui_lang(request))
    except KeyError:
        raise HTTPException(404, "not found") from None
    return {"session": session, "url": f"/e/{env_id}/chat?s={session}"}


@app.post("/api/e/{env_id}/r/{run_id}/f/{fid}/chat")
async def api_finding_chat(request: Request, env_id: str, run_id: str, fid: str):
    _env(request, env_id)
    try:
        session = await _rt(request).chat_from_finding(env_id, run_id, fid, ui_lang(request))
    except KeyError:
        raise HTTPException(404) from None
    return {"session": session, "url": f"/e/{env_id}/chat?s={session}"}


class AnswerReq(BaseModel):
    answer: str


@app.post("/api/e/{env_id}/r/{run_id}/q/{qid}")
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


@app.post("/api/e/{env_id}/k")
async def api_k_add(request: Request, env_id: str, body: KReq):
    er = _env(request, env_id)
    if not body.kind or not (body.title or "").strip():
        raise HTTPException(400, t(ui_lang(request), "err.kind_title"))
    try:
        return await er.repo.add_knowledge(body.kind, body.title, body.body or "", status=body.status or "active",
                                           rule_ids=body.rule_ids)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@app.post("/api/e/{env_id}/k/{kid}")
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


@app.delete("/api/e/{env_id}/k/{kid}")
async def api_k_delete(request: Request, env_id: str, kid: str):
    er = _env(request, env_id)
    await er.repo.delete_knowledge(kid)
    return {"ok": True}


# ----------------------------------------------------------------------- rule drafts
USER_HEADERS = [h.strip() for h in os.environ.get(
    "USER_HEADER", "X-authentik-username,X-Forwarded-User,Remote-User,X-Auth-Request-User").split(",") if h.strip()]


def actor(request: Request) -> str:
    """Who clicked: the SSO proxy's user header when auth is delegated to it, else the shared UI login."""
    if AUTH_DISABLED:
        for h in USER_HEADERS:
            v = request.headers.get(h)
            if v:
                return v[:120]
        return "proxy-user"
    return "ui"


@app.get("/api/e/{env_id}/k/{kid}/rule")
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
    return rec


@app.post("/api/e/{env_id}/k/{kid}/deploy")
async def api_rule_deploy(request: Request, env_id: str, kid: str, body: DeployReq):
    return await _deploy(request, env_id, kid, body.confirm, remove=False)


@app.post("/api/e/{env_id}/k/{kid}/undeploy")
async def api_rule_undeploy(request: Request, env_id: str, kid: str):
    return await _deploy(request, env_id, kid, "", remove=True)


@app.post("/api/e/{env_id}/k/{kid}/verify")
async def api_rule_verify(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        res = await _rt(request).verify_rules(env_id, kid)
    except KeyError as e:
        raise HTTPException(404) from e
    return res[0] if res else {"state": "not_applicable"}


@app.get("/api/e/{env_id}/k/{kid}/promote")
async def api_rule_promote(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        return await _rt(request).promote_view(env_id, kid, actor(request))
    except KeyError as e:
        raise HTTPException(404) from e


@app.post("/api/e/{env_id}/k/{kid}/promoted")
async def api_rule_promoted(request: Request, env_id: str, kid: str):
    _env(request, env_id)
    try:
        return await _rt(request).mark_promoted(env_id, kid, actor(request))
    except KeyError as e:
        raise HTTPException(404) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@app.get("/e/{env_id}/audit", response_class=HTMLResponse)
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


@app.get("/api/e/{env_id}/audit.md")
async def audit_md(request: Request, env_id: str, month: str | None = None):
    from .audit import markdown
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    return Response(markdown(d, ui_lang(request)), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.md"'})


@app.get("/api/e/{env_id}/audit.pdf")
async def audit_pdf(request: Request, env_id: str, month: str | None = None):
    from .pdf import audit_pdf as build_pdf
    er = _env(request, env_id)
    if month and not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(400, "month must be YYYY-MM")
    d = await _rt(request).audit(env_id, month)
    data = build_pdf(d, ui_lang(request))
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="wazuh-audit-{er.env.id}-{d["month"]}.pdf"'})


@app.post("/api/e/{env_id}/liveness")
async def api_liveness(request: Request, env_id: str):
    _env(request, env_id)
    return await _rt(request).liveness_check(env_id, transport=_rt(request).notify_transport)


class ImportReq(BaseModel):
    text: str
    update: bool = False
    dry_run: bool = False


@app.post("/api/e/{env_id}/kb/import")
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


@app.get("/api/e/{env_id}/kb/export")
async def api_k_export(request: Request, env_id: str, kind: str | None = None, status: str | None = None):
    _env(request, env_id)
    rows = await _rt(request).kb_export(env_id, kinds=[kind] if kind else None, status=[status] if status else None)
    text = yaml.safe_dump(rows, allow_unicode=True, sort_keys=False, width=120)
    return Response(text, media_type="application/yaml",
                    headers={"Content-Disposition": f'attachment; filename="knowledge-{env_id}.yaml"'})


class ChatReq(BaseModel):
    text: str
    session: str | None = None


@app.post("/api/e/{env_id}/chat")
async def api_chat(request: Request, env_id: str, body: ChatReq):
    _env(request, env_id)
    text = body.text.strip()
    if not text:
        raise HTTPException(400, t(ui_lang(request), "err.empty"))
    r = await _rt(request).chat(env_id, body.session, text[:8000], ui_lang(request))
    r["html"] = _md.render(r["answer"])
    return r
