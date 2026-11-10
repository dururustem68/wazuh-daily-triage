# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Session login, the authorization middleware and security headers."""
from __future__ import annotations

import hmac
import os
import re
import time
from urllib.parse import urlsplit

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
    Throttle,
    actor,
    client_ip,
    ctx,
    proxy_problem,
    role,
    sign,
    ui_lang,
)
from .ui import tpl

router = APIRouter()
AUDIT_EXEMPT = ("/login", "/logout", "/lang", "/mcp")    # signing in must stay possible; /mcp checks per tool


def env_from_path(path: str) -> str | None:
    m = re.match(r"^/(?:api/)?e/([^/]+)(?:/|$)", path)
    return m.group(1) if m else None


def deny(request: Request, status: int, message: str) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": message}, status_code=status)
    return HTMLResponse(f"<p>{message}</p>", status_code=status)


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
TRUSTED_ORIGINS = {o.strip().lower().rstrip("/") for o in os.environ.get("WDT_TRUSTED_ORIGINS", "").split(",")
                   if o.strip()}


def _netloc(value: str) -> str:
    """``host[:port]`` of an origin/URL or a Host header, lower-cased, without a default port."""
    v = value.strip().lower()
    u = urlsplit(v if "://" in v else "//" + v)
    host = u.hostname or ""
    try:
        port = u.port
    except ValueError:
        return ""
    if port in (None, 80, 443):
        return host
    return f"{host}:{port}"


def cross_origin(request: Request) -> str:
    """Why this state-changing request is refused as cross-origin; ``""`` when it is fine.

    The session cookie is ``SameSite=Strict``, but that does not help when the browser sends no cookie at
    all (``AUTH_DISABLED`` behind an SSO proxy: the proxy's own cookie may be ``Lax``/domain-wide) and it
    treats sibling sub-domains as the *same site*. So every non-safe request must come from this origin:

    * ``Sec-Fetch-Site: same-origin`` (set by the browser, not by the page) is accepted,
    * otherwise ``Origin`` (or ``Referer``) must name the host the request was sent to (``Host`` /
      ``X-Forwarded-Host``) or an entry of ``WDT_TRUSTED_ORIGINS``,
    * a request with none of these headers is not a browser (curl, scripts) and is left to the normal
      authentication.
    """
    if request.method in SAFE_METHODS or request.url.path == "/mcp":     # /mcp: bearer token, no cookie
        return ""
    h = request.headers
    site = (h.get("sec-fetch-site") or "").strip().lower()
    if site in ("same-origin", "none"):
        return ""
    origin = (h.get("origin") or "").strip()
    if not origin:
        origin = (h.get("referer") or "").strip()
        if not origin:
            return "cross-site" if site else ""
    if origin.lower() == "null":
        return "null-origin"
    got = _netloc(origin)
    own = {_netloc(x) for x in [h.get("host") or "", *(h.get("x-forwarded-host") or "").split(",")] if x.strip()}
    own |= {_netloc(o) for o in TRUSTED_ORIGINS}
    own.discard("")
    return "" if got and got in own else "cross-origin"


def explicit_perm(method: str, path: str) -> str | None:
    """Permission of a known route; ``None`` when a state-changing route has no mapping."""
    if "/settings" in path or "/backup/" in path or path.endswith("/backup"):
        return authz.ADMINISTER          # also for GET: the settings page and the profile export are admin-only
    if method in SAFE_METHODS:
        return authz.READ
    if path.endswith("/watch/scan"):
        return authz.RUN
    if path == "/logout":
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
    return None


def required_perm(method: str, path: str) -> str:
    """Permission for this request; ``read`` for safe methods.

    Fails closed: a state-changing route nobody mapped needs the ``admin`` permission, so a route added
    later is never open to the read-only role by accident (``tests/test_v092.py`` checks every route).
    """
    return explicit_perm(method, path) or authz.ADMINISTER


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
    why = cross_origin(request)
    if why:
        resp = deny(request, 403, "cross-origin request refused")
        return finish(request, resp, role_, f"denied:{why}")
    if AUTH_DISABLED and not public and not (p == "/metrics" and os.environ.get("METRICS_TOKEN")):
        why = proxy_problem(request)
        if why:
            resp = deny(request, 401 if why == "no_user" else 403, "this request did not come through the "
                        "authenticating proxy" + (" (no user header)" if why == "no_user" else ""))
            return finish(request, resp, role_, f"denied:{why}")
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
    if request.method not in SAFE_METHODS and p not in AUDIT_EXEMPT and not auditlog.available():
        resp = deny(request, 503, "audit trail is not writable; state-changing requests are refused "
                                  "(fix AUDIT_LOG_FILE or set AUDIT_STRICT=false)")
        return finish(request, resp, role_, "denied:audit")
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


LOGIN_THROTTLE = Throttle(limit=8, window=300)


@router.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = client_ip(request)          # the client behind TRUSTED_PROXIES, else the peer
    lang = ui_lang(request)
    if LOGIN_THROTTLE.blocked(ip):
        return tpl.TemplateResponse(request, "login.html", ctx(request, err=t(lang, "login.throttled")), status_code=429)
    now = time.time()
    if APP_PASSWORD and hmac.compare_digest(password.encode(), APP_PASSWORD.encode()):
        LOGIN_THROTTLE.clear(ip)
        role_ = "admin"
    elif VIEWER_PASSWORD and hmac.compare_digest(password.encode(), VIEWER_PASSWORD.encode()):
        LOGIN_THROTTLE.clear(ip)
        role_ = "viewer"
    else:
        LOGIN_THROTTLE.add(ip)
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
