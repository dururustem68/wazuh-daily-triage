# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Numbers for the dashboard: alert volume over time, severity bands, top rules / agents / sources and the
ATT&CK tactic strip. Deterministic (no LLM), two indexer queries per environment, cached for a minute so a
reloaded page does not query the cluster again."""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from . import mitre

TS = "timestamp"
PERIODS = {"24h": (24, "1h"), "7d": (168, "6h"), "30d": (720, "1d")}
CRITICAL = 12          # Wazuh's own "critical" band starts at 12; level 15 is the maximum
_CACHE: dict[tuple, tuple[float, dict]] = {}
TTL = 60.0


def _b(a: dict | None) -> list[dict]:
    return (a or {}).get("buckets") or []


def _rng(frm: datetime, to: datetime) -> dict:
    return {"range": {TS: {"gte": frm.strftime("%Y-%m-%dT%H:%M:%S"), "lt": to.strftime("%Y-%m-%dT%H:%M:%S")}}}


def bands(levels: dict[int, int], high: int) -> list[dict]:
    """Alerts per severity band. ``high`` is the environment's high level (default 7)."""
    spec = [("critical", CRITICAL, 16), ("high", high, CRITICAL), ("medium", 4, high), ("low", 0, 4)]
    out = []
    for key, lo, hi in spec:
        lo, hi = min(lo, hi), hi
        out.append({"band": key, "from": lo, "to": hi - 1, "count": sum(n for lv, n in levels.items() if lo <= lv < hi)})
    return out


async def overview(env, ix, period: str = "24h", now: datetime | None = None, use_cache: bool = True) -> dict:
    hours, interval = PERIODS.get(period, PERIODS["24h"])
    key = (env.id, period)
    if use_cache and now is None and key in _CACHE and time.monotonic() - _CACHE[key][0] < TTL:
        return _CACHE[key][1]
    now = now or datetime.now(UTC)
    frm, prev = now - timedelta(hours=hours), now - timedelta(hours=2 * hours)
    hl = env.high_level
    r = await ix.search(env.alerts_index, {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [_rng(frm, now)]}},
        "aggs": {
            "hist": {"date_histogram": {"field": TS, "fixed_interval": interval, "min_doc_count": 0,
                                        "extended_bounds": {"min": frm.strftime("%Y-%m-%dT%H:%M:%S"),
                                                            "max": now.strftime("%Y-%m-%dT%H:%M:%S")}},
                     "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": hl}}}},
                              "crit": {"filter": {"range": {"rule.level": {"gte": CRITICAL}}}}}},
            "lv": {"terms": {"field": "rule.level", "size": 16}},
            "rules": {"terms": {"field": "rule.id", "size": 8},
                      "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                               "l": {"max": {"field": "rule.level"}}}},
            "hrules": {"filter": {"range": {"rule.level": {"gte": hl}}},
                       "aggs": {"r": {"terms": {"field": "rule.id", "size": 8},
                                      "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                               "l": {"max": {"field": "rule.level"}}}}}},
            "agents": {"terms": {"field": "agent.name", "size": 8},
                       "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": hl}}}}}},
            "src": {"terms": {"field": "data.srcip", "size": 8},
                    "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": hl}}}}}},
            "nagents": {"cardinality": {"field": "agent.name"}},
            "tac": {"terms": {"field": "rule.mitre.tactic", "size": 40},
                    "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": hl}}}},
                             "tech": {"cardinality": {"field": "rule.mitre.id"}}}},
        }})
    a = r.get("aggregations") or {}
    tot = r["hits"]["total"]
    total = int(tot.get("value", 0) if isinstance(tot, dict) else tot)
    p = await ix.search(env.alerts_index, {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [_rng(prev, frm)]}},
        "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": hl}}}},
                 "crit": {"filter": {"range": {"rule.level": {"gte": CRITICAL}}}},
                 "tac": {"terms": {"field": "rule.mitre.tactic", "size": 40}}}})
    ptot = p["hits"]["total"]
    prev_total = int(ptot.get("value", 0) if isinstance(ptot, dict) else ptot)
    pa = p.get("aggregations") or {}

    series = [{"t": str(x.get("key_as_string", "")), "total": x["doc_count"], "high": x["high"]["doc_count"],
               "crit": x["crit"]["doc_count"]} for x in _b(a.get("hist"))]
    levels = {int(float(b["key"])): b["doc_count"] for b in _b(a.get("lv"))}

    def _rules(buckets):
        return [{"id": str(b["key"]), "desc": (_b(b["d"])[0]["key"] if _b(b["d"]) else ""),
                 "level": int(b["l"]["value"] or 0), "count": b["doc_count"]} for b in buckets]

    tac_now: dict[str, dict] = {}
    for b in _b(a.get("tac")):
        n = mitre.canonical_tactic(str(b["key"]))
        c = tac_now.setdefault(n, {"count": 0, "high": 0, "techniques": 0})
        c["count"] += b["doc_count"]
        c["high"] += b["high"]["doc_count"]
        c["techniques"] = max(c["techniques"], int(b["tech"]["value"] or 0))
    tac_prev: dict[str, dict] = {}
    for b in _b(pa.get("tac")):
        tac_prev.setdefault(mitre.canonical_tactic(str(b["key"])), {"count": 0})["count"] += b["doc_count"]

    high = sum(s["high"] for s in series) if series else sum(n for lv, n in levels.items() if lv >= hl)
    crit = sum(s["crit"] for s in series) if series else sum(n for lv, n in levels.items() if lv >= CRITICAL)
    out = {
        "period": period, "hours": hours, "interval": interval, "from": frm.isoformat(), "to": now.isoformat(),
        "high_level": hl, "total": total, "high": high, "crit": crit, "agents": int(a.get("nagents", {}).get("value") or 0),
        "prev": {"total": prev_total, "high": int(pa.get("high", {}).get("doc_count", 0)),
                 "crit": int(pa.get("crit", {}).get("doc_count", 0))},
        "series": series, "bands": bands(levels, hl), "levels": levels,
        "top_rules": _rules(_b(a.get("rules"))), "top_high_rules": _rules(_b(a.get("hrules", {}).get("r"))),
        "top_agents": [{"name": str(b["key"]), "count": b["doc_count"], "high": b["high"]["doc_count"]}
                       for b in _b(a.get("agents"))],
        "top_sources": [{"ip": str(b["key"]), "count": b["doc_count"], "high": b["high"]["doc_count"]}
                        for b in _b(a.get("src"))],
        "tactics": mitre.tactic_strip(tac_now, tac_prev),
        "mitre_total": sum(c["count"] for c in tac_now.values()),
    }
    for k in ("total", "high", "crit"):
        old = out["prev"][k]
        out["delta_" + k] = None if not old else round((out[k] - old) / old, 3)
    if use_cache:
        _CACHE[key] = (time.monotonic(), out)
    return out
