# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Session primitives, per-request helpers and the template context."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
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


def _networks(value: str) -> list:
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                log.warning("TRUSTED_PROXIES: %r is not an address or CIDR block — ignored", part)
    return out


# Reverse proxies whose X-Forwarded-For is believed and — in SSO mode — the only peers allowed to talk to the UI.
TRUSTED_PROXIES = _networks(os.environ.get("TRUSTED_PROXIES", ""))
PROXY_SECRET = os.environ.get("PROXY_SECRET", "")           # the proxy adds it as X-WDT-Proxy-Secret
SSO_REQUIRE_USER = os.environ.get("SSO_REQUIRE_USER", "true").strip().lower() not in ("0", "false", "no", "off")

# SSO roles (0.11): the proxy forwards the user's groups; membership decides the role.
GROUP_HEADERS = [h.strip() for h in os.environ.get(
    "GROUP_HEADER", "X-authentik-groups,X-Forwarded-Groups,X-Auth-Request-Groups,Remote-Groups").split(",") if h.strip()]


def _group_set(value: str) -> set[str]:
    return {_norm_group(x) for x in re.split(r"[|,;]", value or "") if x.strip()}


def _norm_group(g: str) -> str:
    """``/Admins``, ``admins`` and ``Admins`` are the same group (Keycloak sends full paths)."""
    return g.strip().lstrip("/").casefold()


SSO_ADMIN_GROUPS = _group_set(os.environ.get("SSO_ADMIN_GROUPS", ""))
SSO_VIEWER_GROUPS = _group_set(os.environ.get("SSO_VIEWER_GROUPS", ""))
SSO_DEFAULT_ROLE = (os.environ.get("SSO_DEFAULT_ROLE", "") or ("deny" if SSO_VIEWER_GROUPS else "viewer")).strip().lower()
if SSO_DEFAULT_ROLE not in ("admin", "viewer", "deny"):
    log.warning("SSO_DEFAULT_ROLE=%r is not admin, viewer or deny — using deny", SSO_DEFAULT_ROLE)
    SSO_DEFAULT_ROLE = "deny"


def _trusted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in TRUSTED_PROXIES)


def client_ip(request: Request) -> str:
    """The address of the client, not of the proxy in front of the application.

    ``X-Forwarded-For`` is only read when the connection comes from a ``TRUSTED_PROXIES`` address; then
    the right-most entry that is not itself a trusted proxy is the client. Anything else can be forged,
    so without the setting every request is attributed to the peer (behind a proxy: the proxy).
    """
    peer = request.client.host if request.client else "?"
    if not TRUSTED_PROXIES or not _trusted(peer):
        return peer
    for hop in reversed([h.strip() for h in (request.headers.get("x-forwarded-for") or "").split(",") if h.strip()]):
        if not _trusted(hop):
            return hop[:64]
    return peer


def sso_user(request: Request) -> str | None:
    for h in USER_HEADERS:
        v = request.headers.get(h)
        if v:
            return v[:120]
    return None


def proxy_problem(request: Request) -> str:
    """SSO mode only: why this request cannot have come through the authenticating proxy (``""`` = fine).

    With ``AUTH_DISABLED`` the application believes whoever reaches it. Three independent checks make
    "whoever reaches it" mean "the proxy": the peer address (``TRUSTED_PROXIES``), a shared secret the
    proxy adds (``PROXY_SECRET``) and the user header itself (``SSO_REQUIRE_USER``, on by default — a
    request without it did not pass a login).
    """
    if not AUTH_DISABLED:
        return ""
    peer = request.client.host if request.client else ""
    if TRUSTED_PROXIES and not _trusted(peer):
        return "untrusted_peer"
    if PROXY_SECRET and not hmac.compare_digest(request.headers.get("x-wdt-proxy-secret", "").encode(),
                                                PROXY_SECRET.encode()):
        return "proxy_secret"
    if SSO_REQUIRE_USER and not sso_user(request):
        return "no_user"
    return ""


class Throttle:
    """Sliding-window counter per key (login failures, MCP requests). In memory; bounded."""

    def __init__(self, limit: int, window: float, cap: int = 5000):
        self.limit, self.window, self.cap = limit, window, cap
        self.hits: dict[str, list[float]] = {}

    def _recent(self, key: str, now: float) -> list[float]:
        return [x for x in self.hits.get(key, []) if now - x < self.window]

    def blocked(self, key: str, now: float | None = None) -> bool:
        return self.limit > 0 and len(self._recent(key, now or time.time())) >= self.limit

    def add(self, key: str, now: float | None = None) -> None:
        now = now or time.time()
        if len(self.hits) > self.cap:
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > self.window]:
                self.hits.pop(k, None)
        self.hits[key] = self._recent(key, now) + [now]

    def clear(self, key: str) -> None:
        self.hits.pop(key, None)


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


def sso_groups(request: Request) -> set[str]:
    """Groups of the signed-in user as forwarded by the SSO proxy (normalised, possibly empty)."""
    out: set[str] = set()
    for h in GROUP_HEADERS:
        v = request.headers.get(h)
        if v:
            out |= _group_set(v[:4000])
    return out


def sso_role(request: Request) -> str | None:
    """Role behind an SSO proxy: ``SSO_ADMIN_GROUPS`` → admin, ``SSO_VIEWER_GROUPS`` → viewer, otherwise
    ``SSO_DEFAULT_ROLE`` (``viewer`` unless viewer groups are listed, then ``deny`` → ``None``)."""
    groups = sso_groups(request)
    if groups & SSO_ADMIN_GROUPS:
        return "admin"
    if groups & SSO_VIEWER_GROUPS:
        return "viewer"
    return None if SSO_DEFAULT_ROLE == "deny" else SSO_DEFAULT_ROLE


def role(request: Request) -> str | None:
    """Role of this request: from the signed cookie, or from the proxy's group header in SSO mode.

    ``None`` means not signed in (password mode) or no role granted (SSO mode)."""
    if AUTH_DISABLED:
        return sso_role(request)
    return valid(request.cookies.get(COOKIE))


def actor(request: Request) -> str:
    """Who clicked: the SSO proxy's user header when auth is delegated to it, else the shared UI login."""
    if AUTH_DISABLED:
        return sso_user(request) or "proxy-user"
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
            "viewer": role_ == "viewer", "can": can, "viewer_enabled": bool(VIEWER_PASSWORD), "role": role_,
            "who": sso_user(request) if AUTH_DISABLED else None,
            "storage_errors": getattr(request.state, "storage_errors", []), "request_id": REQUEST_ID.get(),
            "storage_lost": [{**x, "env": r.env.id} for r in visible(request)
                             for x in (getattr(r.store, "health", None) or {}).get("lost") or []],
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
