# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Is the application's own data safe from the cluster's retention rules?

Everything the application knows (knowledge base, decisions, reports, settings) lives in ``<prefix>-*``
indices of the Wazuh indexer. A site that deletes old indices with Index State Management — a policy on
``wazuh-alerts-*`` is normal, a policy on ``*`` is common — can delete them too, silently. These checks
work on any installation and never change anything:

* **prefix**: a ``storage_prefix`` that starts with ``wazuh-`` falls under Wazuh's own index patterns;
* **policy**: is an ISM policy attached to one of the indices, does it delete, and when;
* a missing permission is reported as *could not be checked*, never as "no policy".
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from .store import MAPPINGS

_AGE = re.compile(r"^(\d+)\s*([smhdw])$")
_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
RISKY_PREFIXES = ("wazuh-", "wazuh_", ".opendistro", ".kibana", "security-auditlog")


def prefix_issue(prefix: str) -> str | None:
    """Why this prefix is risky (a message key suffix), or ``None``."""
    p = (prefix or "").lower()
    if p.startswith(RISKY_PREFIXES[:2]) or p == "wazuh":
        return "wazuh"
    if p.startswith(RISKY_PREFIXES[2:]) or p.startswith("."):
        return "system"
    return None


def _age_seconds(v) -> int | None:
    m = _AGE.match(str(v or "").strip())
    return int(m.group(1)) * _SECONDS[m.group(2)] if m else None


def delete_age(policy: dict | None) -> int | None:
    """Seconds after index creation at which the policy can reach a ``delete`` action (shortest path).

    Walks the state machine from ``default_state``; only ``min_index_age`` conditions add time. A delete
    reachable through a condition that is not age-based (size, doc count, cron) returns 0: assume the worst.
    """
    if not policy:
        return None
    states = {s.get("name"): s for s in policy.get("states") or []}
    best: int | None = None
    seen: dict[str, int] = {}
    todo: list[tuple[str, int]] = [(str(policy.get("default_state")), 0)]
    while todo:
        name, age = todo.pop()
        st = states.get(name)
        if st is None or seen.get(name, 10**12) <= age:
            continue
        seen[name] = age
        if any("delete" in (a or {}) for a in st.get("actions") or []):
            best = age if best is None else min(best, age)
            continue
        for tr in st.get("transitions") or []:
            cond = tr.get("conditions") or {}
            step = _age_seconds(cond.get("min_index_age"))
            if "min_index_age" in cond and step is not None:
                nxt = max(age, step)        # min_index_age is measured from index creation, not from the state
            else:
                nxt = age                   # no condition or a non-age condition: may happen at any time
            todo.append((str(tr.get("state_name")), nxt))
    return best


async def storage_report(ix, prefix: str) -> dict:
    """Read-only report for the settings page, the health flags and the connection test."""
    out: dict = {"prefix": prefix, "prefix_issue": prefix_issue(prefix), "indices": [], "checked": True,
                 "error": None, "worst": None}
    names = [f"{prefix}-{k}" for k in MAPPINGS]
    try:
        meta = await ix.index_meta(f"{prefix}-*")
    except Exception as e:  # noqa: BLE001
        meta = {}
        out["error"] = str(e)[:200]
    try:
        explain = await ix.ism_explain(f"{prefix}-*")
    except Exception as e:  # noqa: BLE001 - 403 (no permission) or a cluster without the ISM plugin
        explain = None
        out["checked"] = False
        out["error"] = str(e)[:200]
    policies: dict[str, dict | None] = {}
    now = datetime.now(UTC)
    for name in names:
        row: dict = {"index": name, "exists": name in meta, "policy": None, "deletes": False, "deletes_on": None,
                     "state": "unchecked" if explain is None else "ok"}
        ex = (explain or {}).get(name) or {}
        pid = ex.get("index.plugins.index_state_management.policy_id") or ex.get("policy_id") \
            or ex.get("index.opendistro.index_state_management.policy_id")
        if pid:
            row["policy"] = pid
            row["state"] = "managed"
            if pid not in policies:
                try:
                    policies[pid] = await ix.ism_policy(pid)
                except Exception:  # noqa: BLE001
                    policies[pid] = None
            pol = policies[pid]
            if pol is None:
                row["state"] = "policy_unreadable"
            else:
                age = delete_age(pol)
                if age is not None:
                    row["deletes"] = True
                    row["state"] = "deletes"
                    row["delete_after_days"] = round(age / 86400, 1)
                    created = (meta.get(name) or {}).get("created")
                    if created:
                        when = datetime.fromtimestamp(created / 1000, UTC) + timedelta(seconds=age)
                        row["deletes_on"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
                        row["days_left"] = max(0, (when - now).days)
        out["indices"].append(row)
    dated = sorted(r["deletes_on"] for r in out["indices"] if r.get("deletes_on"))
    out["deletes"] = any(r["deletes"] for r in out["indices"])
    out["worst"] = dated[0] if dated else None
    return out
