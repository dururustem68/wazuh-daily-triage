# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""MITRE ATT&CK view of the alerts (deterministic, no LLM).

Wazuh rules carry an optional ``<mitre>`` block; the indexed alert then has ``rule.mitre.id`` (technique ids such
as ``T1110.001``), ``rule.mitre.tactic`` (tactic names) and ``rule.mitre.technique`` (technique names). This module
groups the alerts of a period by tactic and technique, compares them with the previous period, marks techniques
seen for the first time in the look-back window and lists tactics with no alert at all.

What a tactic without alerts means is limited: either nothing of that kind happened, or no rule that carries this
tactic matched. It is a hint for a detection gap, not a measured coverage.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

TS = "timestamp"

# Enterprise ATT&CK tactics, in kill-chain order. Wazuh writes the tactic *name* into rule.mitre.tactic.
TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"), ("TA0042", "Resource Development"), ("TA0001", "Initial Access"),
    ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_ID = {name.casefold(): tid for tid, name in TACTICS}
TACTIC_NAMES = [name for _, name in TACTICS]


def attack_url(tid: str) -> str:
    """Link to the technique (``T1110.001`` → …/techniques/T1110/001/) or tactic page on attack.mitre.org."""
    tid = (tid or "").strip().upper()
    if tid.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{tid}/"
    if tid.startswith("T"):
        return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    return "https://attack.mitre.org/"


def canonical_tactic(name: str) -> str:
    """The catalogue spelling of a tactic name (Wazuh and some rule sets vary in case)."""
    tid = TACTIC_ID.get((name or "").strip().casefold())
    return next((n for t, n in TACTICS if t == tid), name.strip()) if tid else (name or "").strip()


def _b(a: dict | None) -> list[dict]:
    return (a or {}).get("buckets") or []


def _rng(frm: datetime, to: datetime) -> dict:
    return {"range": {TS: {"gte": frm.strftime("%Y-%m-%dT%H:%M:%S"), "lt": to.strftime("%Y-%m-%dT%H:%M:%S")}}}


def _technique_name(top_hits: dict, tid: str) -> str:
    """The technique name that belongs to ``tid``: Wazuh writes ``rule.mitre.id`` and ``rule.mitre.technique`` as
    two lists in the same order, so the name is at the id's position."""
    hits = ((top_hits or {}).get("hits") or {}).get("hits") or []
    m = (((hits[0].get("_source") or {}).get("rule") or {}).get("mitre") or {}) if hits else {}
    ids, names = m.get("id") or [], m.get("technique") or []
    ids, names = (ids if isinstance(ids, list) else [ids]), (names if isinstance(names, list) else [names])
    if tid in ids and ids.index(tid) < len(names):
        return str(names[ids.index(tid)])
    return str(names[0]) if len(names) == 1 else ""


def heat_class(n: int, peak: int) -> str:
    """CSS intensity step ``h0`` … ``h5`` for a heat-map cell (log-ish so one flood does not flatten the rest)."""
    if n <= 0 or peak <= 0:
        return "h0"
    r = n / peak
    return "h5" if r > .5 else "h4" if r > .2 else "h3" if r > .07 else "h2" if r > .02 else "h1"


async def tactic_counts(env, ix, frm: datetime, to: datetime) -> dict[str, dict]:
    """Per tactic: alerts, high-level alerts, distinct techniques — for the dashboard strip."""
    r = await ix.search(env.alerts_index, {
        "size": 0, "query": {"bool": {"filter": [_rng(frm, to)]}},
        "aggs": {"t": {"terms": {"field": "rule.mitre.tactic", "size": 40},
                       "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": env.high_level}}}},
                                "tech": {"cardinality": {"field": "rule.mitre.id"}}}}}})
    out: dict[str, dict] = {}
    for b in _b(r.get("aggregations", {}).get("t")):
        name = canonical_tactic(str(b["key"]))
        cur = out.setdefault(name, {"count": 0, "high": 0, "techniques": 0})
        cur["count"] += b["doc_count"]
        cur["high"] += b["high"]["doc_count"]
        cur["techniques"] = max(cur["techniques"], int(b["tech"]["value"] or 0))
    return out


def tactic_strip(counts: dict[str, dict], prev: dict[str, dict] | None = None) -> list[dict]:
    """All 14 tactics in order with count, change and heat class; unknown tactic names are appended."""
    peak = max([c["count"] for c in counts.values()] or [0])
    rows = []
    names = TACTIC_NAMES + sorted(n for n in counts if n not in TACTIC_NAMES)
    for name in names:
        c = counts.get(name) or {"count": 0, "high": 0, "techniques": 0}
        p = (prev or {}).get(name, {}).get("count", 0) if prev is not None else None
        rows.append({"tactic": name, "id": TACTIC_ID.get(name.casefold(), ""), **c, "prev": p,
                     "heat": heat_class(c["count"], peak),
                     "trend": None if not p else round((c["count"] - p) / p, 3)})
    return rows


async def matrix(env, ix, days: int = 7, lookback_days: int = 30, now: datetime | None = None) -> dict:
    """Tactic × technique matrix for the last ``days`` days, with the previous period and first-seen techniques.

    Wazuh stores the tactics and technique ids of a rule as two independent lists, so a rule that maps to several
    tactics lists each of its techniques under each of them — the same behaviour as the Wazuh dashboard.
    """
    now = now or datetime.now(UTC)
    frm, prev = now - timedelta(days=days), now - timedelta(days=2 * days)
    hl = env.high_level
    r = await ix.search(env.alerts_index, {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [_rng(frm, now)]}},
        "aggs": {"mapped": {"filter": {"exists": {"field": "rule.mitre.id"}}},
                 "t": {"terms": {"field": "rule.mitre.tactic", "size": 40},
                       "aggs": {"x": {"terms": {"field": "rule.mitre.id", "size": 60},
                                      "aggs": {"name": {"top_hits": {"size": 1, "_source": ["rule.mitre"]}},
                                               "high": {"filter": {"range": {"rule.level": {"gte": hl}}}},
                                               "lvl": {"max": {"field": "rule.level"}},
                                               "agents": {"cardinality": {"field": "agent.name"}},
                                               "rules": {"terms": {"field": "rule.id", "size": 5}},
                                               "last": {"max": {"field": TS}}}}}}}})
    tot = r["hits"]["total"]
    total = int(tot.get("value", 0) if isinstance(tot, dict) else tot)
    mapped = int(r["aggregations"]["mapped"]["doc_count"])
    p = await ix.search(env.alerts_index, {
        "size": 0, "query": {"bool": {"filter": [_rng(prev, frm)]}},
        "aggs": {"x": {"terms": {"field": "rule.mitre.id", "size": 500}},
                 "t": {"terms": {"field": "rule.mitre.tactic", "size": 40}}}})
    before = {str(b["key"]): b["doc_count"] for b in _b(p["aggregations"]["x"])}
    before_t = {canonical_tactic(str(b["key"])): b["doc_count"] for b in _b(p["aggregations"]["t"])}
    lb = await ix.search(env.alerts_index, {
        "size": 0, "query": {"bool": {"filter": [_rng(frm - timedelta(days=lookback_days), frm)]}},
        "aggs": {"x": {"terms": {"field": "rule.mitre.id", "size": 1000}},
                 "t": {"terms": {"field": "rule.mitre.tactic", "size": 40}}}})
    known = {str(b["key"]) for b in _b(lb["aggregations"]["x"])}
    seen_t_lb = {canonical_tactic(str(b["key"])) for b in _b(lb["aggregations"]["t"])}

    cols: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    for tb in _b(r["aggregations"]["t"]):
        tname = canonical_tactic(str(tb["key"]))
        col = cols.setdefault(tname, {"tactic": tname, "id": TACTIC_ID.get(tname.casefold(), ""), "count": 0,
                                      "high": 0, "cells": []})
        col["count"] += tb["doc_count"]
        for xb in _b(tb["x"]):
            tid = str(xb["key"])
            cell = {"id": tid, "name": _technique_name(xb["name"], tid), "count": xb["doc_count"],
                    "high": xb["high"]["doc_count"], "level": int(xb["lvl"]["value"] or 0),
                    "agents": int(xb["agents"]["value"] or 0), "rules": [str(b["key"]) for b in _b(xb["rules"])],
                    "last": xb["last"].get("value_as_string") or "", "prev": before.get(tid, 0),
                    "new": tid not in known and tid not in before, "url": attack_url(tid)}
            cell["trend"] = None if not cell["prev"] else round((cell["count"] - cell["prev"]) / cell["prev"], 3)
            col["high"] += cell["high"]
            col["cells"].append(cell)
            t = techniques.setdefault(tid, {**cell, "tactics": []})
            t["tactics"].append(tname)
    peak = max([c["count"] for col in cols.values() for c in col["cells"]] or [0])
    for col in cols.values():
        col["cells"].sort(key=lambda c: -c["count"])
        for c in col["cells"]:
            c["heat"] = heat_class(c["count"], peak)
    ordered = [cols.get(n) or {"tactic": n, "id": tid, "count": 0, "high": 0, "cells": []} for tid, n in TACTICS]
    ordered += [c for n, c in sorted(cols.items()) if n not in TACTIC_NAMES]
    for col in ordered:
        col["prev"] = before_t.get(col["tactic"], 0)
        col["url"] = attack_url(col["id"]) if col["id"] else ""
    tlist = sorted(techniques.values(), key=lambda t: -t["count"])
    return {"days": days, "lookback_days": lookback_days, "high_level": hl, "total": total, "mapped": mapped,
            "mapped_share": round(mapped / total, 4) if total else 0.0, "columns": ordered,
            "techniques": tlist, "new": [t for t in tlist if t["new"]],
            "gone": sorted([k for k in before if k not in techniques]),
            "silent": [c["tactic"] for c in ordered if not c["count"] and c["tactic"] in TACTIC_NAMES],
            "silent_lookback": [n for n in TACTIC_NAMES if n not in seen_t_lb and not cols.get(n)]}


async def rule_mapping(env, ix, rule_ids: list[str], frm: datetime, to: datetime) -> dict[str, dict]:
    """``rule.id`` → ``{"ids": [...], "tactics": [...]}`` as seen in the alerts of the window."""
    ids = sorted({str(x) for x in rule_ids if x})[:200]
    if not ids:
        return {}
    r = await ix.search(env.alerts_index, {
        "size": 0, "query": {"bool": {"filter": [_rng(frm, to), {"terms": {"rule.id": ids}}]}},
        "aggs": {"r": {"terms": {"field": "rule.id", "size": len(ids)},
                       "aggs": {"x": {"terms": {"field": "rule.mitre.id", "size": 10}},
                                "t": {"terms": {"field": "rule.mitre.tactic", "size": 10}}}}}})
    return {str(b["key"]): {"ids": [str(x["key"]) for x in _b(b["x"])],
                            "tactics": [canonical_tactic(str(x["key"])) for x in _b(b["t"])]}
            for b in _b(r.get("aggregations", {}).get("r"))}


async def enrich_mitre(env, ix, findings: list[dict], frm: datetime, to: datetime) -> None:
    """Merge the ATT&CK mapping of a finding's rules into ``finding["mitre"]`` and set ``mitre_tactics``."""
    from .reporting import technique_ids
    wanted = [r for f in findings for r in f.get("rule_ids") or []]
    m = await rule_mapping(env, ix, wanted, frm, to)
    for f in findings:
        ids = list(f.get("mitre") or [])
        tactics: list[str] = []
        for rid in f.get("rule_ids") or []:
            for x in m.get(str(rid), {}).get("ids", []):
                if x not in ids:
                    ids.append(x)
            for t in m.get(str(rid), {}).get("tactics", []):
                if t not in tactics:
                    tactics.append(t)
        f["mitre"] = technique_ids(ids, limit=10)
        f["mitre_tactics"] = [n for n in TACTIC_NAMES if n in tactics] + [t for t in tactics if t not in TACTIC_NAMES]
