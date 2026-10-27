# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Role → permission matrix and per-environment authorization.

The web UI has two roles (``admin`` and the optional read-only ``viewer``). Files and permissions alone
do not make a security boundary when several Wazuh environments (production, staging, customers) share
one installation, so each role can additionally be limited to a list of environment ids:

===============  ==========================================================
``ADMIN_ENVS``   environments the admin role may read/change (empty = all)
``VIEWER_ENVS``  environments the viewer role may read (empty = all)
``MCP_ENVS``     environments MCP clients may query (empty = all)
===============  ==========================================================

The checks run on the server for every route (``_env``) and every MCP tool call — hiding a button is
never the control.
"""
from __future__ import annotations

import os

ADMIN = "admin"
VIEWER = "viewer"
ROLES = (ADMIN, VIEWER)

READ = "read"            # dashboards, reports, inbox, knowledge, audit
RUN = "run"              # start a triage run / liveness check / connection test
DECIDE = "decide"        # finding decisions, questions, inbox actions
KNOWLEDGE = "knowledge"  # create/update/delete knowledge entries, import
DEPLOY = "deploy"        # rule deploy / undeploy / promote
ADMINISTER = "admin"     # environment-level operations

PERMISSIONS: dict[str, frozenset[str]] = {
    VIEWER: frozenset({READ}),
    ADMIN: frozenset({READ, RUN, DECIDE, KNOWLEDGE, DEPLOY, ADMINISTER}),
}


def _csv(name: str) -> set[str]:
    return {x.strip() for x in os.environ.get(name, "").split(",") if x.strip()}


def permitted(role: str | None, permission: str) -> bool:
    """Does this role hold the permission? A missing role (auth delegated to a proxy) is an admin."""
    if role not in ROLES:
        role = ADMIN
    return permission in PERMISSIONS[role]


def env_scope(role: str | None) -> set[str] | None:
    """Environments this role may touch; ``None`` means all of them."""
    if role not in ROLES:
        role = ADMIN
    allowed = _csv("ADMIN_ENVS" if role == ADMIN else "VIEWER_ENVS")
    return allowed or None


def may_access_env(role: str | None, env_id: str) -> bool:
    scope = env_scope(role)
    return scope is None or env_id in scope


def mcp_envs(all_ids) -> set[str]:
    """Environments MCP clients may use (``MCP_ENVS``, empty = all configured ones)."""
    allowed = _csv("MCP_ENVS")
    return set(all_ids) if not allowed else {i for i in all_ids if i in allowed}


def describe() -> dict:
    """Non-secret summary for the audit trail / startup log."""
    return {"roles": list(ROLES), "admin_envs": sorted(_csv("ADMIN_ENVS")) or "all",
            "viewer_envs": sorted(_csv("VIEWER_ENVS")) or "all", "mcp_envs": sorted(_csv("MCP_ENVS")) or "all"}
