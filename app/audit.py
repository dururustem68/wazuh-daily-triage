# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Monthly audit report (ISMS evidence): deterministic, built from the index and the stored runs/decisions.

No LLM involved — every number can be traced back to a query or a stored record.
"""
from __future__ import annotations

import calendar
from datetime import UTC, datetime

from .collector import _b, _parse, iso
from .i18n import t


def month_range(month: str | None) -> tuple[datetime, datetime, str]:
    now = datetime.now(UTC)
    if month:
        y, m = (int(x) for x in month.split("-", 1))
    else:
        y, m = now.year, now.month
    start = datetime(y, m, 1, tzinfo=UTC)
    end = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=UTC)
    return start, min(end, now) if start <= now < end else end, f"{y:04d}-{m:02d}"


def _in(ts: str | None, a: datetime, b: datetime) -> bool:
    try:
        return bool(ts) and a <= _parse(ts) < b
    except (ValueError, TypeError):
        return False


async def build(runtime, env_id: str, month: str | None = None) -> dict:
    rt = runtime.get(env_id)
    env, lang = rt.env, runtime.lang(rt.env)
    start, end, label = month_range(month)
    out: dict = {"env": {"id": env.id, "name": env.name}, "month": label, "from": iso(start), "to": iso(end),
                 "generated_at": iso(datetime.now(UTC)), "errors": []}

    # --- alert volume (index) ---------------------------------------------------------------
    try:
        r = await rt.ix.search(env.alerts_index, {
            "size": 0, "query": {"range": {"timestamp": {"gte": iso(start), "lt": iso(end)}}},
            "aggs": {"lv": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
                     "day": {"date_histogram": {"field": "timestamp", "fixed_interval": "1d", "min_doc_count": 0,
                                                "extended_bounds": {"min": iso(start), "max": iso(end)}},
                             "aggs": {"hi": {"filter": {"range": {"rule.level": {"gte": env.high_level}}}}}},
                     "hi": {"filter": {"range": {"rule.level": {"gte": env.high_level}}},
                            "aggs": {"r": {"terms": {"field": "rule.id", "size": 15},
                                           "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                                    "l": {"max": {"field": "rule.level"}}}}}},
                     "ag": {"cardinality": {"field": "agent.name"}}}})
        a = r["aggregations"]
        levels = {str(b["key"]): b["doc_count"] for b in _b(a["lv"])}
        high = sum(v for k, v in levels.items() if int(k) >= env.high_level)
        out["volume"] = {
            "total": r["hits"]["total"]["value"], "high": high, "high_level": env.high_level, "levels": levels,
            "agents": (a.get("ag") or {}).get("value"),
            "daily": [{"d": b["key_as_string"][:10], "n": b["doc_count"], "hi": b["hi"]["doc_count"]}
                      for b in _b(a["day"]) if b["key_as_string"][:10] < iso(end)[:10] or b["doc_count"]],
            "top_high": [{"id": b["key"], "n": b["doc_count"], "level": int(b["l"]["value"] or 0),
                          "desc": (_b(b["d"]) or [{"key": ""}])[0]["key"]} for b in _b(a["hi"]["r"])]}
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"volume: {e}")

    # --- daily runs, findings and the operator's decisions ----------------------------------
    runs = [x for x in await rt.repo.list_runs(400, light=True) if _in(x.get("started_at"), start, end)]
    runs.sort(key=lambda x: x["started_at"])
    labels: dict[str, int] = {}
    sev: dict[str, int] = {}
    decided: dict[str, int] = {}
    notable = []
    for x in runs:
        for f in x.get("findings") or []:
            labels[f.get("label", "?")] = labels.get(f.get("label", "?"), 0) + 1
            sev[f.get("severity", "?")] = sev.get(f.get("severity", "?"), 0) + 1
            us = f.get("user_status", "new")
            decided[us] = decided.get(us, 0) + 1
            if f.get("label") in ("real_incident", "detection_gap") or f.get("severity") == "critical":
                notable.append({"run": x["run_id"], "at": x["started_at"], "title": f.get("title"),
                                "label": f.get("label"), "severity": f.get("severity"), "user_status": us,
                                "note": f.get("user_note") or ""})
    out["runs"] = {"count": len(runs), "done": sum(1 for x in runs if x.get("status") == "done"),
                   "error": sum(1 for x in runs if x.get("status") == "error"),
                   "health": {h: sum(1 for x in runs if x.get("health") == h) for h in ("ok", "warn", "critical")},
                   "ai_failed": sum(1 for x in runs if x.get("ai_error")),
                   "list": [{"run_id": x["run_id"], "at": x["started_at"], "health": x.get("health"),
                             "status": x.get("status"), "total": (x.get("metrics") or {}).get("total"),
                             "high": (x.get("metrics") or {}).get("high"),
                             "findings": len(x.get("findings") or [])} for x in runs]}
    out["findings"] = {"by_label": labels, "by_severity": sev, "by_decision": decided, "notable": notable[:60]}

    # --- knowledge: decisions, risk acceptance, rule changes --------------------------------
    kn = await rt.repo.list_knowledge(size=5000)
    changed = [k for k in kn if _in(k.get("created_at"), start, end) or _in(k.get("updated_at"), start, end)]
    out["knowledge"] = {
        kind: [{"title": k["title"], "status": k["status"], "by": k.get("created_by"), "created": k.get("created_at"),
                "updated": k.get("updated_at"), "rule_ids": k.get("rule_ids") or []}
               for k in changed if k["kind"] == kind]
        for kind in ("decision", "baseline", "lesson")}
    rule_changes = []
    for k in kn:
        if k["kind"] != "rule_draft":
            continue
        hist = list(k.get("deploy_history") or []) + ([k["deploy"]] if k.get("deploy") else [])
        for h in hist:
            if _in(h.get("at"), start, end):
                rule_changes.append({"title": k["title"], "action": h.get("action"), "state": h.get("state"),
                                     "by": h.get("by"), "at": h.get("at"), "ids": h.get("ids") or [],
                                     "risky": bool(h.get("risky")), "file": h.get("file")})
        if _in((k.get("promoted") or {}).get("at"), start, end):
            p = k["promoted"]
            rule_changes.append({"title": k["title"], "action": "promote", "state": "promoted", "by": p.get("by"),
                                 "at": p.get("at"), "ids": p.get("ids") or [], "risky": False, "file": p.get("file")})
        if k.get("status") == "rejected" and _in(k.get("updated_at"), start, end):
            rule_changes.append({"title": k["title"], "action": "reject", "state": "rejected", "by": "",
                                 "at": k.get("updated_at"), "ids": k.get("rule_ids") or [], "risky": False, "file": ""})
    out["rule_changes"] = sorted(rule_changes, key=lambda x: x.get("at") or "")
    out["open_items"] = [{"title": k["title"], "since": k.get("created_at")} for k in kn
                         if k["kind"] == "open_item" and k["status"] == "active"]

    # --- SIEM availability (liveness events) -----------------------------------------------
    live = await runtime.liveness_state(env_id) or {}
    ev = [e for e in live.get("events") or [] if _in(e.get("start"), start, end) or _in(e.get("end"), start, end)]
    for code, p in (live.get("problems") or {}).items():
        if _in(p.get("since"), start, end) or _parse(p["since"]) < start:
            ev.append({"code": code, "msg": p.get("msg"), "start": p.get("since"), "end": None, "minutes": None})
    out["liveness"] = {"enabled": env.liveness.enabled, "events": sorted(ev, key=lambda e: e.get("start") or ""),
                       "minutes": sum(e.get("minutes") or 0 for e in ev)}

    # --- snapshots from the last run of the month: coverage, vulnerabilities, mail ----------
    last = next((x for x in reversed(runs) if x.get("status") == "done"), None)
    if last:
        full = await rt.repo.get_run(last["run_id"]) or {}
        c = full.get("collected") or {}
        out["snapshot_at"] = last["started_at"]
        out["coverage"] = c.get("coverage")
        out["vulnerabilities"] = c.get("vulnerabilities")
    mail = [x for x in runs]
    sat = 0
    for x in mail:
        for f in x.get("flags") or []:
            if f.get("code") == "mail_saturated":
                sat += 1
    out["mail_saturated_runs"] = sat
    out["title"] = t(lang, "au.title", env=env.name, m=label)
    out["days_in_month"] = calendar.monthrange(start.year, start.month)[1]
    return out


def markdown(d: dict, lang: str) -> str:
    L = lang
    o = [f"# {d['title']}", "", f"{t(L, 'au.period')}: {d['from'][:10]} – {d['to'][:10]} · "
         f"{t(L, 'au.generated')}: {d['generated_at'][:16].replace('T', ' ')} UTC", ""]
    v = d.get("volume")
    if v:
        o += [f"## {t(L, 'au.volume')}", "", f"- {t(L, 'au.total')}: {v['total']:,}",
              f"- {t(L, 'au.high', l=v['high_level'])}: {v['high']:,}", f"- {t(L, 'au.agents')}: {v.get('agents')}", "",
              f"| {t(L, 'au.rule')} | {t(L, 'au.level')} | {t(L, 'au.count')} | {t(L, 'au.desc')} |", "|---|---|---|---|"]
        o += [f"| {r['id']} | {r['level']} | {r['n']:,} | {r['desc']} |" for r in v["top_high"]]
        o.append("")
    r = d["runs"]
    o += [f"## {t(L, 'au.runs')}", "", t(L, "au.runs_line", n=r["count"], ok=r["health"]["ok"], w=r["health"]["warn"],
                                           c=r["health"]["critical"], e=r["error"], a=r["ai_failed"]), ""]
    f = d["findings"]
    o += [f"## {t(L, 'au.findings')}", "",
          "- " + ", ".join(f"{t(L, 'label.' + k)} {n}" for k, n in f["by_label"].items()),
          "- " + ", ".join(f"{t(L, 'us.' + k)} {n}" for k, n in f["by_decision"].items()), ""]
    if f["notable"]:
        o += [f"| {t(L, 'au.date')} | {t(L, 'au.finding')} | {t(L, 'au.decision')} |", "|---|---|---|"]
        o += [f"| {x['at'][:10]} | {x['title']} | {t(L, 'us.' + x['user_status'])} {x['note']} |" for x in f["notable"]]
        o.append("")
    o += [f"## {t(L, 'au.rule_changes')}", ""]
    if d["rule_changes"]:
        o += [f"| {t(L, 'au.date')} | {t(L, 'au.action')} | ID | {t(L, 'au.by')} | {t(L, 'au.title_col')} |",
              "|---|---|---|---|---|"]
        o += [f"| {x['at'][:16].replace('T', ' ')} | {x['action']} → {x['state']}{' ⚠' if x['risky'] else ''} | "
              f"{', '.join(x['ids'])} | {x['by'] or ''} | {x['title']} |" for x in d["rule_changes"]]
    else:
        o.append(t(L, "au.none"))
    o.append("")
    for kind in ("decision", "baseline"):
        rows = d["knowledge"][kind]
        o += [f"## {t(L, 'kind.' + kind)}", ""]
        o += [f"- {x['title']} ({x['status']}, {(x['updated'] or '')[:10]})" for x in rows] or [t(L, "au.none")]
        o.append("")
    lv = d["liveness"]
    o += [f"## {t(L, 'au.liveness')}", ""]
    if lv["events"]:
        o += [f"- {(e['start'] or '')[:16].replace('T', ' ')} → {(e['end'] or t(L, 'au.ongoing'))[:16].replace('T', ' ')}"
              f" ({e['minutes'] or '…'} min) {e['msg']}" for e in lv["events"]]
    else:
        o.append(t(L, "au.no_outage") if lv["enabled"] else t(L, "au.live_off"))
    o.append("")
    cov = d.get("coverage")
    if cov:
        o += [f"## {t(L, 'au.coverage')}", "", "- " + ", ".join(f"{k} {n}" for k, n in cov["by_status"].items()),
              f"- {t(L, 'au.versions')}: " + ", ".join(f"{k} ×{n}" for k, n in cov["versions"].items())]
        inv = cov.get("inventory")
        if inv:
            o.append(f"- {t(L, 'au.inv_missing')}: {', '.join(inv['missing']) or '—'}")
        o.append("")
    vu = d.get("vulnerabilities")
    if vu:
        o += [f"## {t(L, 'au.vulns')}", "", "- " + ", ".join(f"{k} {n}" for k, n in vu["severity"].items())]
        for k, s in (vu.get("sla") or {}).items():
            if isinstance(s, dict):
                o.append(f"- {k}: SLA {s['days']} d — {t(L, 'au.overdue')} {s['overdue']}")
        o.append("")
    if d["open_items"]:
        o += [f"## {t(L, 'kind.open_item')}", ""] + [f"- {x['title']}" for x in d["open_items"]] + [""]
    return "\n".join(o)
