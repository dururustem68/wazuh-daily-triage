# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Noise map: which rules produce the volume, how much of the high-level band is noise, and the trend.

Deterministic (no LLM). For the last `days` days it lists the busiest rules with their share of all alerts and
of the high-level alerts, alerts per day, the change against the previous period and the dominant agent /
location, and marks candidates for a level reduction. A 28-day daily series shows whether the high-level band
is getting cleaner.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

TS = "timestamp"


def _b(a: dict) -> list[dict]:
    return a.get("buckets") or []


def _rng(frm: datetime, to: datetime) -> dict:
    return {"range": {TS: {"gte": frm.strftime("%Y-%m-%dT%H:%M:%S"), "lt": to.strftime("%Y-%m-%dT%H:%M:%S")}}}


async def noise_map(env, ix, days: int = 7, top: int = 25, trend_days: int = 28) -> dict:
    now = datetime.now(UTC)
    frm, prev = now - timedelta(days=days), now - timedelta(days=2 * days)
    high = env.high_level
    r = await ix.search(env.alerts_index, {
        "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [_rng(frm, now)]}},
        "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": high}}}},
                 "r": {"terms": {"field": "rule.id", "size": top},
                       "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                "l": {"max": {"field": "rule.level"}},
                                "ag": {"terms": {"field": "agent.name", "size": 1}},
                                "agn": {"cardinality": {"field": "agent.name"}},
                                "loc": {"terms": {"field": "location", "size": 1}}}}}})
    tot = r["hits"]["total"]
    total = int(tot.get("value", 0) if isinstance(tot, dict) else tot)
    high_total = int(r["aggregations"]["high"]["doc_count"])
    ids = [str(b["key"]) for b in _b(r["aggregations"]["r"])]
    before: dict[str, int] = {}
    if ids:
        p = await ix.search(env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [_rng(prev, frm), {"terms": {"rule.id": ids}}]}},
            "aggs": {"r": {"terms": {"field": "rule.id", "size": len(ids)}}}})
        before = {str(b["key"]): b["doc_count"] for b in _b(p["aggregations"]["r"])}
    rules = []
    for b in _b(r["aggregations"]["r"]):
        n, lvl = b["doc_count"], int(b["l"]["value"] or 0)
        d, ag, loc = _b(b["d"]), _b(b["ag"]), _b(b["loc"])
        old = before.get(str(b["key"]), 0)
        row = {"id": str(b["key"]), "desc": d[0]["key"] if d else "", "level": lvl, "count": n,
               "per_day": round(n / days, 1), "share": round(n / total, 4) if total else 0.0,
               "high_share": round(n / high_total, 4) if high_total and lvl >= high else 0.0,
               "prev": old, "trend": round((n - old) / old, 3) if old else None,
               "agents": int(b["agn"]["value"] or 0),
               "top_agent": ag[0]["key"] if ag else "", "top_agent_share": round(ag[0]["doc_count"] / n, 3) if ag else 0,
               "top_location": loc[0]["key"] if loc else "",
               "top_location_share": round(loc[0]["doc_count"] / n, 3) if loc else 0}
        # a level-reduction candidate: high level and either a big slice of the high band or a steady flood
        row["candidate"] = lvl >= high and (row["high_share"] >= 0.05 or row["per_day"] >= 100)
        rules.append(row)
    t = await ix.search(env.alerts_index, {
        "size": 0, "query": {"bool": {"filter": [_rng(now - timedelta(days=trend_days), now)]}},
        "aggs": {"day": {"date_histogram": {"field": TS, "fixed_interval": "1d", "min_doc_count": 0},
                         "aggs": {"high": {"filter": {"range": {"rule.level": {"gte": high}}}}}}}})
    series = [{"day": str(x.get("key_as_string", ""))[:10], "total": x["doc_count"], "high": x["high"]["doc_count"],
               "ratio": round(x["high"]["doc_count"] / x["doc_count"], 4) if x["doc_count"] else 0.0}
              for x in _b(t["aggregations"]["day"])]
    cand = [x for x in rules if x["candidate"]]
    return {"days": days, "high_level": high, "total": total, "high_total": high_total,
            "high_ratio": round(high_total / total, 4) if total else 0.0,
            "candidates_high": sum(x["count"] for x in cand),
            "high_ratio_without_candidates": round((high_total - sum(x["count"] for x in cand)) / total, 4)
            if total else 0.0,
            "rules": rules, "series": series}


def next_rule_id(drafts: list[dict], cfg) -> int:
    """First free id in the rule_deploy range, above every id used by existing drafts."""
    used = {int(x) for d in drafts for x in re.findall(r'<rule[^>]*\bid="(\d+)"', d.get("xml") or d.get("body") or "")}
    used = {u for u in used if cfg.id_min <= u <= cfg.id_max}
    return max(used) + 1 if used else cfg.id_min


def skeleton(rule: dict, rid: int, level: int, lang: str = "en") -> str:
    loc = rule.get("top_location") or ""
    cond = (f'    <location>{loc}</location>\n' if loc and rule.get("top_location_share", 0) >= 0.8 and "<" not in loc
            else "")
    note = ("narrow it: add <match>, <field> or <srcip> so only the routine part is lowered" if lang != "tr"
            else "daraltın: yalnız rutin kısmı düşürmek için <match>, <field> ya da <srcip> ekleyin")
    desc = (rule.get("desc") or "").replace("<", "").replace(">", "").replace("&", "and")[:120]
    return (f'<group name="wdt_noise,">\n  <rule id="{rid}" level="{level}">\n    <if_sid>{rule["id"]}</if_sid>\n'
            f"{cond}    <!-- {note} -->\n    <description>{desc} (routine, lowered)</description>\n"
            f"  </rule>\n</group>")
