# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Startup validation of the security-relevant configuration.

Copying ``.env.example`` to ``.env`` and running it in production is the most common way a hardened
deployment becomes a weak one. When ``ENVIRONMENT=production`` (or ``WDT_ENV=production``) the process
refuses to start with example passwords, an unset session key, insecure cookies or disabled TLS
verification. Everything else is reported as a warning so the operator can decide.

Deliberate, documented exceptions: ``WDT_ALLOW_INSECURE_TLS=1`` and ``WDT_ALLOW_INSECURE_COOKIE=1``.
"""
from __future__ import annotations

import os

WEAK_PASSWORDS = {
    "change-me", "changeme", "change_me", "password", "passwd", "admin", "administrator", "test",
    "secret", "wdt", "demo", "1234", "12345", "123456", "12345678", "qwerty", "letmein",
}


class SecurityError(RuntimeError):
    """A fatal configuration problem; the application must not start."""


def is_production(env=os.environ) -> bool:
    return (env.get("ENVIRONMENT") or env.get("WDT_ENV") or "").strip().lower() in (
        "prod", "production", "live")


def _true(env, name: str) -> bool:
    return (env.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def validate(settings, env=os.environ, demo: bool = False) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)``; errors are fatal when production mode is on."""
    prod = is_production(env)
    errors: list[str] = []
    warnings: list[str] = []

    if not prod:
        if (env.get("APP_PASSWORD") or "").strip().lower() in WEAK_PASSWORDS:
            warnings.append("APP_PASSWORD is an example value — fine for a demo, not for a shared or "
                            "internet-facing instance (set ENVIRONMENT=production to enforce this)")
        return errors, warnings

    if demo:
        errors.append("WDT_DEMO=true in production: the demo has fixed data and no authentication value")

    auth_disabled = _true(env, "AUTH_DISABLED")
    if auth_disabled:
        warnings.append("AUTH_DISABLED=true: the app trusts the reverse proxy's user header — the UI/API "
                        "must only be reachable through that proxy (NetworkPolicy or host firewall)")
    else:
        pw = env.get("APP_PASSWORD") or ""
        if not pw:
            errors.append("APP_PASSWORD is not set (or the UI is behind an SSO proxy — set AUTH_DISABLED=true)")
        elif pw.strip().lower() in WEAK_PASSWORDS:
            errors.append("APP_PASSWORD is an example/default value; choose a unique password")
        if not env.get("APP_SECRET"):
            errors.append("APP_SECRET is not set: sessions would be re-created on every restart "
                          "(generate one with `openssl rand -hex 32`)")
        if env.get("VIEWER_PASSWORD") and env.get("VIEWER_PASSWORD") == pw:
            errors.append("VIEWER_PASSWORD must differ from APP_PASSWORD")

    if not _true(env, "COOKIE_SECURE") and not _true(env, "WDT_ALLOW_INSECURE_COOKIE"):
        errors.append("COOKIE_SECURE is false: set it to true behind HTTPS, or set "
                      "WDT_ALLOW_INSECURE_COOKIE=1 if TLS is terminated in front and you accept the risk")

    if not _true(env, "WDT_ALLOW_INSECURE_TLS"):
        insecure: list[str] = []
        if not env.get("WAZUH_CA_FILE") and (env.get("WAZUH_VERIFY_TLS") or "").lower() in ("0", "false", "no"):
            insecure.append("WAZUH_VERIFY_TLS")
        for e in getattr(settings, "environments", []):
            if getattr(e.indexer, "verify_tls", True) is False:
                insecure.append(f"{e.id}.indexer")
            if e.api and getattr(e.api, "verify_tls", True) is False:
                insecure.append(f"{e.id}.api")
        if insecure:
            errors.append("TLS verification is disabled for " + ", ".join(insecure) +
                          "; configure ca_file (or set WDT_ALLOW_INSECURE_TLS=1 for a lab)")

    for e in getattr(settings, "environments", []):
        rd = e.rule_deploy
        if not rd.enabled:
            continue
        if e.api and rd.username and rd.username == e.api.username:
            warnings.append(f"{e.id}: rule_deploy uses the same API user as the read-only client — "
                            "use a separate least-privilege deploy user (docs/rule-deployment.md)")
        if not rd.username or not rd.password:
            errors.append(f"{e.id}: rule_deploy.enabled but username/password are empty")
        elif rd.password.strip().lower() in WEAK_PASSWORDS:
            errors.append(f"{e.id}: rule_deploy password is an example/default value")

    if not _true(env, "AUDIT_LOG"):
        warnings.append("AUDIT_LOG is off: state-changing operations are not written to the audit trail")

    return errors, warnings


def check(settings, env=os.environ, demo: bool = False) -> list[str]:
    """Validate at startup: raise :class:`SecurityError` on fatal problems, return the warnings."""
    errors, warnings = validate(settings, env, demo)
    if errors:
        raise SecurityError("refusing to start in production:\n  - " + "\n  - ".join(errors))
    return warnings
