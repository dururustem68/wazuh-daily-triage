# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Session primitives, per-request helpers and the template context."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time

from fastapi import HTTPException, Request

from .. import authz
from ..config import LANGUAGES
from ..formatting import finding_text, question_text
from ..i18n import t
from ..observability import REQUEST_ID
from ..runtime import Runtime

log = logging.getLogger("wdt")

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
VIEWER_PASSWORD = os.environ.get("VIEWER_PASSWORD", "")   # optional read-only role
AUTH_DISABLED = os.environ.get("AUTH_DISABLED", "").lower() in ("1", "true", "yes")
SECRET = (os.environ.get("APP_SECRET") or secrets.token_hex(32)).encode()
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
COOKIE = "wdt_session"
TTL = 12 * 3600
ROLES = ("admin", "viewer")

USER_HEADERS = [h.strip() for h in os.environ.get(
    "USER_HEADER", "X-authentik-username,X-Forwarded-User,Remote-User,X-Auth-Request-User").split(",") if h.strip()]


def sign(exp: int, role: str = "admin") -> str:
    msg = f"{exp}.{role}"
    return f"{msg}.{hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()}"


def valid(tok: str | None) -> str | None:
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


def role(request: Request) -> str | None:
    """Session role of this request (None when auth is delegated to a proxy)."""
    if AUTH_DISABLED:
        return None
    return valid(request.cookies.get(COOKIE))


def actor(request: Request) -> str:
    """Who clicked: the SSO proxy's user header when auth is delegated to it, else the shared UI login."""
    if AUTH_DISABLED:
        for h in USER_HEADERS:
            v = request.headers.get(h)
            if v:
                return v[:120]
        return "proxy-user"
    return "ui"


def ui_lang(request: Request) -> str:
    c = request.cookies.get("lang")
    if c in LANGUAGES:
        return c
    try:
        return request.app.state.rt.settings.app.language
    except AttributeError:
        return "en"


def visible(request: Request) -> list:
    """EnvRuntime objects this session may see (role/environment scope)."""
    role_ = role(request)
    return [r for r in request.app.state.rt.envs.values() if authz.may_access_env(role_, r.env.id)]


def ctx(request: Request, **kw):
    lang = ui_lang(request)
    rt = request.app.state.rt
    role_ = role(request)
    can = {p: authz.permitted(role_, p) for p in
           (authz.READ, authz.RUN, authz.DECIDE, authz.KNOWLEDGE, authz.DEPLOY, authz.ADMINISTER)}
    return {"envs": [r.env for r in visible(request)], "demo": rt.demo, "app_title": rt.settings.app.title,
            "auth": not AUTH_DISABLED, "lang": lang, "_": lambda key, **a: t(lang, key, **a),
            "deploy_any": any(rt.deploy_ready(r.env) for r in visible(request)), "path": request.url.path,
            "viewer": role_ == "viewer", "can": can, "viewer_enabled": bool(VIEWER_PASSWORD),
            "storage_errors": getattr(request.state, "storage_errors", []), "request_id": REQUEST_ID.get(),
            "ftext": lambda f, context=None: finding_text(f, lang, context),
            "qtext": lambda q, context=None: question_text(q, lang, context), **kw}


def runtime(request: Request) -> Runtime:
    return request.app.state.rt


def env(request: Request, env_id: str):
    if not authz.may_access_env(role(request), env_id):
        raise HTTPException(404, t(ui_lang(request), "err.no_env"))
    try:
        return runtime(request).get(env_id)
    except KeyError:
        raise HTTPException(404, t(ui_lang(request), "err.no_env")) from None


async def safe(coro, default, request: Request | None = None):
    """Await a storage read; keep the page alive but surface the failure to the user and the log."""
    try:
        return await coro
    except Exception as e:  # noqa: BLE001
        log.warning("storage read failed (request_id=%s): %s", REQUEST_ID.get(), e)
        if request is not None:
            request.state.storage_errors = getattr(request.state, "storage_errors", []) + [str(e)[:200]]
        return default
