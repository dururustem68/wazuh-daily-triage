# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Session login, the authorization middleware and security headers."""
from __future__ import annotations

import hmac
import re
import time

from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import auditlog, authz
from ..config import LANGUAGES
from ..i18n import t
from ..observability import REQUEST_ID, metrics, new_request_id
from .common import (
    APP_PASSWORD,
    AUTH_DISABLED,
    COOKIE,
    COOKIE_SECURE,
    TTL,
    VIEWER_PASSWORD,
    actor,
    ctx,
    role,
    sign,
    ui_lang,
)
from .ui import tpl

router = APIRouter()


def env_from_path(path: str) -> str | None:
    m = re.match(r"^/(?:api/)?e/([^/]+)(?:/|$)", path)
    return m.group(1) if m else None


def deny(request: Request, status: int, message: str) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": message}, status_code=status)
    return HTMLResponse(f"<p>{message}</p>", status_code=status)


def required_perm(method: str, path: str) -> str:
    """Permission for this request; ``read`` for safe methods."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return authz.READ
    if path.endswith("/deploy") or path.endswith("/undeploy") or path.endswith("/promoted"):
        return authz.DEPLOY
    if path.endswith("/run") or path.endswith("/check") or path.endswith("/liveness") \
            or path.endswith("/notify-test") or path.endswith("/verify"):
        return authz.RUN
    if path.endswith("/kb/import") or path.endswith("/kb/export") or "/k/" in path or path.endswith("/k"):
        return authz.KNOWLEDGE
    if "/inbox/" in path or "/f/" in path or "/q/" in path or "/incident" in path:
        return authz.DECIDE
    return authz.READ


def finish(request: Request, resp: Response, role_: str | None, denial: str) -> Response:
    rid = REQUEST_ID.get()
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                                               "form-action 'self'")
    p = request.url.path
    if (request.method not in ("GET", "HEAD", "OPTIONS") or denial) and p not in ("/login", "/lang"):
        auditlog.record("denied" if denial else f"http.{request.method.lower()}",
                        actor=actor(request), role=role_ or ("proxy" if AUTH_DISABLED else "anonymous"),
                        env=env_from_path(p) or "", target=p, result=denial or str(resp.status_code),
                        request_id=rid, method=request.method, path_=p)
        metrics.inc("wdt_http_write_requests_total", result=denial or str(resp.status_code))
    return resp


async def handle_request(request: Request, call_next, p: str, role_: str | None) -> Response:
    public = p.startswith("/static") or p in ("/login", "/healthz", "/readyz", "/lang", "/mcp")   # /mcp: own bearer token
    resp: Response
    if not public and not AUTH_DISABLED:
        if not APP_PASSWORD:
            resp = HTMLResponse(f"<p>{t(ui_lang(request), 'auth.no_password')}</p>", status_code=503)
            return finish(request, resp, role_, "denied:no_password")
        if not role_:
            resp = deny(request, 401, "not authenticated") if p.startswith("/api/") \
                else RedirectResponse("/login", status_code=303)
            return finish(request, resp, role_, "denied:unauthenticated")
        need = required_perm(request.method, p)
        if not authz.permitted(role_, need):
            resp = deny(request, 403, t(ui_lang(request), "auth.read_only"))
            return finish(request, resp, role_, f"denied:{need}")
        env_id = env_from_path(p)
        if env_id and not authz.may_access_env(role_, env_id):
            resp = deny(request, 403, t(ui_lang(request), "err.no_env"))
            return finish(request, resp, role_, "denied:env")
    resp = await call_next(request)
    return finish(request, resp, role_, "")


async def auth_mw(request: Request, call_next):
    p = request.url.path
    rid = request.headers.get("X-Request-ID") or new_request_id()
    tok = REQUEST_ID.set(rid)
    started = time.perf_counter()
    role_ = role(request)
    resp: Response | None = None
    try:
        resp = await handle_request(request, call_next, p, role_)
        return resp
    finally:
        metrics.observe("wdt_http_request_seconds", time.perf_counter() - started, method=request.method)
        metrics.inc("wdt_http_requests_total", method=request.method,
                    status=str(resp.status_code if resp is not None else 500))
        REQUEST_ID.reset(tok)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return tpl.TemplateResponse(request, "login.html", ctx(request, err=None))


_fails: dict[str, list[float]] = {}


@router.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    now = time.time()
    if len(_fails) > 2000:
        for k in [k for k, v in _fails.items() if not v or now - v[-1] > 300]:
            _fails.pop(k, None)
    hist = [x for x in _fails.get(ip, []) if now - x < 300]
    lang = ui_lang(request)
    if len(hist) >= 8:
        return tpl.TemplateResponse(request, "login.html", ctx(request, err=t(lang, "login.throttled")), status_code=429)
    if APP_PASSWORD and hmac.compare_digest(password.encode(), APP_PASSWORD.encode()):
        _fails.pop(ip, None)
        role_ = "admin"
    elif VIEWER_PASSWORD and hmac.compare_digest(password.encode(), VIEWER_PASSWORD.encode()):
        _fails.pop(ip, None)
        role_ = "viewer"
    else:
        _fails[ip] = hist + [now]
        auditlog.record("login.failed", actor=ip, role="anonymous", result="401", request_id=REQUEST_ID.get(),
                        method="POST", path_="/login")
        return tpl.TemplateResponse(request, "login.html", ctx(request, err=t(lang, "login.wrong")), status_code=401)
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(COOKIE, sign(int(now) + TTL, role_), max_age=TTL, httponly=True, samesite="strict",
                 secure=COOKIE_SECURE)
    auditlog.record("login", actor="ui" if role_ == "admin" else "viewer", role=role_, result="ok",
                    request_id=REQUEST_ID.get(), method="POST", path_="/login")
    return r


def os_viewer_password() -> str:
    from .common import VIEWER_PASSWORD
    return VIEWER_PASSWORD


@router.post("/logout")
async def logout():
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(COOKIE)
    return r


@router.post("/lang")
async def set_lang(request: Request, lang: str = Form(...)):
    back = request.headers.get("referer") or "/"
    if not back.startswith(str(request.base_url)):
        back = "/"
    r = RedirectResponse(back, status_code=303)
    code = next((x for x in LANGUAGES if x == lang), None)   # the stored value is always one of ours
    if code:
        r.set_cookie("lang", code, max_age=365 * 86400, samesite="strict", secure=COOKIE_SECURE)
    return r


def install(app: FastAPI) -> None:
    app.middleware("http")(auth_mw)
    app.include_router(router)
