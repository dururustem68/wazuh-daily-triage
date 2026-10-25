# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Tools available to the AI — all READ-ONLY.

Nothing in Wazuh is ever changed. The only writes are adding a `proposed`
entry to this application's own knowledge base (no effect until a human
approves it) and submitting the report of a triage run.

Security note: alert contents (URLs, full_log, user names, user agents) are
attacker-controlled and may carry prompt injection. The tool set is kept
deliberately narrow: no active response, no configuration writes, no
outbound requests.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from ..collector import TS, _b, _parse, iso
from ..config import Environment
from ..redact import redact
from ..store import KNOWLEDGE_KINDS, Repo
from ..wazuh.api import WazuhAPI
from ..wazuh.indexer import Indexer

MAX_RESULT_CHARS = 14000

TIME_PROPS = {
    "from": {"type": "string", "description": "Start: ISO-8601 or OpenSearch date math (now-24h). Default now-24h"},
    "to": {"type": "string", "description": "End: ISO-8601 or now. Default now"},
}
FILTER_PROPS = {
    "query": {"type": "string", "description": "Optional Lucene query_string, e.g. data.srcip:192.0.2.10 AND rule.groups:sshd"},
    "rule_ids": {"type": "array", "items": {"type": "string"}, "description": "Rule ID filter"},
    "agent": {"type": "string", "description": "Agent name (agent.name) filter"},
    "min_level": {"type": "integer", "description": "Minimum rule.level"},
    **TIME_PROPS,
}

EVENT_FIELDS = [TS, "agent.name", "agent.id", "rule.id", "rule.level", "rule.description", "rule.groups",
                "full_log", "location", "decoder.name", "data.srcip", "data.srcuser", "data.dstuser",
                "data.url", "data.id", "data.protocol", "syscheck.path", "syscheck.event",
                "data.verb", "data.user.username", "data.objectRef", "data.responseStatus.code",
                "data.vulnerability.cve", "data.vulnerability.severity", "data.vulnerability.package.name"]


def _filters(a: dict) -> list[dict]:
    f: list[dict] = [{"range": {TS: {"gte": a.get("from") or "now-24h", "lte": a.get("to") or "now"}}}]
    if a.get("query"):
        f.append({"query_string": {"query": a["query"], "analyze_wildcard": True,
                                   "default_operator": "AND"}})
    if a.get("rule_ids"):
        f.append({"terms": {"rule.id": [str(x) for x in a["rule_ids"]]}})
    if a.get("agent"):
        f.append({"term": {"agent.name": a["agent"]}})
    if a.get("min_level") is not None:
        f.append({"range": {"rule.level": {"gte": int(a["min_level"])}}})
    return f


def _compact_event(src: dict) -> dict:
    out: dict[str, Any] = {}

    def put(path, val):
        if val in (None, "", [], {}):
            return
        if isinstance(val, str) and len(val) > 500:
            val = val[:500] + "…"
        out[path] = val

    for f in EVENT_FIELDS:
        cur: Any = src
        for p in f.split("."):
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, dict):
            cur = json.dumps(cur, ensure_ascii=False)[:300]
        put(f, cur)
    return out


class ToolBox:
    def __init__(self, env: Environment, ix: Indexer, api: WazuhAPI | None, repo: Repo,
                 mode: str = "chat", run_id: str | None = None):
        self.env = env
        self.ix = ix
        self.api = api
        self.repo = repo
        self.mode = mode
        self.run_id = run_id
        self.submitted: dict | None = None
        self.proposals: list[dict] = []
        self._handlers: dict[str, Callable[[dict], Awaitable[Any]]] = {
            "search_alerts": self.search_alerts,
            "aggregate_alerts": self.aggregate_alerts,
            "rule_timeline": self.rule_timeline,
            "ip_profile": self.ip_profile,
            "correlate_around": self.correlate_around,
            "vulnerabilities": self.vulnerabilities,
            "propose_knowledge": self.propose_knowledge,
            "validate_rule_xml": self.validate_rule_xml,
        }
        if api:
            self._handlers.update({"agent_info": self.agent_info, "rule_info": self.rule_info,
                                   "logtest": self.logtest})
        if mode == "chat":
            self._handlers.update({"list_reports": self.list_reports, "get_report": self.get_report,
                                   "knowledge": self.knowledge})
        if mode == "triage":
            self._handlers["submit_report"] = self.submit_report

    # ------------------------------------------------------------- schemas
    def specs(self) -> list[dict]:
        S = SPECS
        return [S[n] for n in self._handlers if n in S]

    async def call(self, name: str, args: dict) -> str:
        h = self._handlers.get(name)
        if not h:
            return json.dumps({"error": f"unknown tool: {name}"})
        try:
            res = await h(args or {})
        except Exception as e:  # noqa: BLE001
            res = {"error": f"{type(e).__name__}: {e}"}
        txt = json.dumps(res, ensure_ascii=False, default=str)
        if self.env.redact:
            txt = redact(txt)
        if len(txt) > MAX_RESULT_CHARS:
            txt = txt[:MAX_RESULT_CHARS] + f'… [truncated, {len(txt)} chars in total — narrow the filter]'
        return txt

    # ------------------------------------------------------------- tools
    async def search_alerts(self, a):
        size = max(1, min(int(a.get("size", 10)), 25))
        r = await self.ix.search(self.env.alerts_index, {
            "size": size, "sort": [{TS: "asc" if a.get("oldest_first") else "desc"}],
            "query": {"bool": {"filter": _filters(a)}}, "_source": EVENT_FIELDS})
        return {"total": r["hits"]["total"]["value"],
                "events": [_compact_event(h["_source"]) for h in r["hits"]["hits"]]}

    async def aggregate_alerts(self, a):
        field = a["field"]
        size = max(1, min(int(a.get("size", 20)), 50))
        agg: dict = {"terms": {"field": field, "size": size}}
        if a.get("sub_field"):
            agg["aggs"] = {"sub": {"terms": {"field": a["sub_field"], "size": 5}}}
        agg.setdefault("aggs", {})
        agg["aggs"]["first"] = {"min": {"field": TS}}
        agg["aggs"]["last"] = {"max": {"field": TS}}
        r = await self.ix.search(self.env.alerts_index, {"size": 0, "query": {"bool": {"filter": _filters(a)}},
                                                        "aggs": {"x": agg}})
        out = []
        for b in _b(r["aggregations"]["x"]):
            row = {"key": b["key"], "count": b["doc_count"], "first": b["first"].get("value_as_string"),
                   "last": b["last"].get("value_as_string")}
            if "sub" in b:
                row[a["sub_field"]] = {s["key"]: s["doc_count"] for s in _b(b["sub"])}
            out.append(row)
        return {"total": r["hits"]["total"]["value"], "field": field, "buckets": out,
                "other": r["aggregations"]["x"].get("sum_other_doc_count", 0)}

    async def rule_timeline(self, a):
        interval = a.get("interval", "1h")
        r = await self.ix.search(self.env.alerts_index, {"size": 0, "query": {"bool": {"filter": _filters(a)}},
            "aggs": {"h": {"date_histogram": {"field": TS, "fixed_interval": interval, "min_doc_count": 1}}}})
        b = [{"t": x["key_as_string"], "n": x["doc_count"]} for x in _b(r["aggregations"]["h"])]
        return {"total": r["hits"]["total"]["value"], "interval": interval, "buckets": b[-200:],
                "note": "Non-empty buckets only. Look at the distribution, not the average: everything may sit in one short window."}

    async def ip_profile(self, a):
        ip = a["ip"].strip()
        q = {"prefix": {"data.srcip": ip}} if ip.endswith((".", ":")) else {"term": {"data.srcip": ip}}
        f = _filters({k: a.get(k) for k in ("from", "to")}) + [q]
        r = await self.ix.search(self.env.alerts_index, {"size": 3, "sort": [{TS: "desc"}], "_source": EVENT_FIELDS,
            "query": {"bool": {"filter": f}}, "aggs": {
                "rules": {"terms": {"field": "rule.id", "size": 10}, "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}}}},
                "codes": {"terms": {"field": "data.id", "size": 10}},
                "urls": {"cardinality": {"field": "data.url"}},
                "top_urls": {"terms": {"field": "data.url", "size": 10}},
                "agents": {"terms": {"field": "agent.name", "size": 10}},
                "users": {"terms": {"field": "data.srcuser", "size": 10}},
                "ips": {"terms": {"field": "data.srcip", "size": 10}},
                "h": {"date_histogram": {"field": TS, "fixed_interval": a.get("interval", "30m"), "min_doc_count": 1}},
            }})
        ag = r["aggregations"]
        return {
            "total": r["hits"]["total"]["value"],
            "rules": [{"id": b["key"], "n": b["doc_count"], "desc": (_b(b["d"]) or [{"key": ""}])[0]["key"]} for b in _b(ag["rules"])],
            "status_codes": {b["key"]: b["doc_count"] for b in _b(ag["codes"])},
            "distinct_urls": ag["urls"]["value"],
            "top_urls": {b["key"]: b["doc_count"] for b in _b(ag["top_urls"])},
            "agents": {b["key"]: b["doc_count"] for b in _b(ag["agents"])},
            "users": {b["key"]: b["doc_count"] for b in _b(ag["users"])},
            "ips": {b["key"]: b["doc_count"] for b in _b(ag["ips"])},
            "timeline": [{"t": b["key_as_string"], "n": b["doc_count"]} for b in _b(ag["h"])][-100:],
            "samples": [_compact_event(h["_source"]) for h in r["hits"]["hits"]],
            "note": "data.srcip is a keyword field; use a prefix (\"203.0.113.\") for ranges, not CIDR.",
        }

    async def correlate_around(self, a):
        ts = _parse(a["timestamp"])
        m = int(a.get("minutes", 30))
        f = [{"range": {TS: {"gte": iso(ts - timedelta(minutes=m)), "lte": iso(ts + timedelta(minutes=m))}}}]
        if a.get("agent"):
            f.append({"term": {"agent.name": a["agent"]}})
        f.append({"range": {"rule.level": {"gte": int(a.get("min_level", 3))}}})
        r = await self.ix.search(self.env.alerts_index, {"size": 20, "sort": [{TS: "asc"}], "_source": EVENT_FIELDS,
            "query": {"bool": {"filter": f}},
            "aggs": {"r": {"terms": {"field": "rule.id", "size": 25},
                           "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                    "l": {"max": {"field": "rule.level"}},
                                    "a": {"terms": {"field": "agent.name", "size": 3}}}}}})
        return {"window": f"±{m} min", "total": r["hits"]["total"]["value"],
                "by_rule": [{"id": b["key"], "n": b["doc_count"], "level": int(b["l"]["value"] or 0),
                             "desc": (_b(b["d"]) or [{"key": ""}])[0]["key"],
                             "agents": [x["key"] for x in _b(b["a"])]} for b in _b(r["aggregations"]["r"])],
                "first_events": [_compact_event(h["_source"]) for h in r["hits"]["hits"]]}

    async def vulnerabilities(self, a):
        f = []
        if a.get("agent"):
            f.append({"term": {"agent.name": a["agent"]}})
        if a.get("severity"):
            f.append({"term": {"vulnerability.severity": a["severity"]}})
        r = await self.ix.search(self.env.vuln_index, {"size": 0, "query": {"bool": {"filter": f}}, "aggs": {
            "sev": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "cve": {"terms": {"field": "vulnerability.id", "size": int(min(a.get("size", 15), 40))},
                    "aggs": {"p": {"terms": {"field": "package.name", "size": 3}},
                             "a": {"cardinality": {"field": "agent.id"}}}},
            "pkg": {"terms": {"field": "package.name", "size": 15}}}})
        ag = r["aggregations"]
        return {"total": r["hits"]["total"]["value"],
                "severity": {b["key"]: b["doc_count"] for b in _b(ag["sev"])},
                "top_cves": [{"cve": b["key"], "n": b["doc_count"], "agents": b["a"]["value"],
                              "packages": [p["key"] for p in _b(b["p"])]} for b in _b(ag["cve"])],
                "top_packages": {b["key"]: b["doc_count"] for b in _b(ag["pkg"])},
                "note": "The Critical count alone is not a risk measure: leftover kernel packages and feed false positives inflate it."}

    async def agent_info(self, a):
        q = str(a["agent"])
        items = await self.api.agents(search=q, limit=5)
        cnt = await self.ix.search(self.env.alerts_index, {"size": 0, "query": {"bool": {"filter": [
            {"range": {TS: {"gte": "now-24h"}}}, {"term": {"agent.name": items[0]["name"]}}]}} if items else {"match_none": {}},
            "aggs": {"r": {"terms": {"field": "rule.id", "size": 10}}}})
        return {"agents": items, "alerts_24h": cnt["hits"]["total"]["value"],
                "top_rules_24h": {b["key"]: b["doc_count"] for b in _b(cnt.get("aggregations", {}).get("r", {}))}}

    async def rule_info(self, a):
        ids = [str(x) for x in a["rule_ids"]][:20]
        items = await self.api.rules(ids)
        return [{"id": r.get("id"), "level": r.get("level"), "description": r.get("description"),
                 "filename": r.get("filename"), "relative_dirname": r.get("relative_dirname"),
                 "groups": r.get("groups"), "details": r.get("details")} for r in items]

    async def logtest(self, a):
        d = await self.api.logtest(a["event"], a.get("log_format", "syslog"), a.get("location", "daily-triage"))
        out = d.get("output", {})
        return {"rule": out.get("rule"), "decoder": out.get("decoder"), "data": out.get("data"),
                "alert": d.get("alert"), "messages": d.get("messages")}

    async def validate_rule_xml(self, a):
        xml = a["xml"]
        res: dict[str, Any] = {}
        try:
            root = ET.fromstring(f"<root>{xml}</root>")
            ids = [r.get("id") for r in root.iter("rule")]
            res["xml_ok"] = True
            res["rule_ids"] = ids
            levels = {r.get("id"): r.get("level") for r in root.iter("rule")}
            res["levels"] = levels
            issues = []
            for r in root.iter("rule"):
                for fld in r.iter("field"):
                    t = fld.get("type", "osregex")
                    if t == "osregex" and "(" in (fld.text or "") and "|" in (fld.text or ""):
                        issues.append(f"rule {r.get('id')}: <field> OS_Regex does not support grouped alternation — use type=\"pcre2\"")
                for tag in ("id", "match", "regex"):
                    for el in r.iter(tag):
                        if el.get("type") in (None, "osregex") and "(" in (el.text or "") and "|" in (el.text or ""):
                            issues.append(f"rule {r.get('id')}: <{tag}> OS_Regex does not support grouping; write ^400$|^408$ or use pcre2")
            res["warnings"] = issues
        except ET.ParseError as e:
            return {"xml_ok": False, "error": str(e)}
        if self.api and res.get("rule_ids"):
            existing = await self.api.rules([i for i in res["rule_ids"] if i])
            res["id_collisions"] = [{"id": r["id"], "file": r.get("filename"), "description": r.get("description")}
                                    for r in existing]
        res["note"] = ("Syntax/ID check only. Before going live run wazuh-analysisd -t on the manager and "
                       "logtest with real events; this application never applies rules.")
        return res

    async def propose_knowledge(self, a):
        kind = a["kind"]
        if kind not in KNOWLEDGE_KINDS or kind in ("answer",):
            return {"error": f"invalid kind; one of: {', '.join(k for k in KNOWLEDGE_KINDS if k != 'answer')}"}
        if len(self.proposals) >= 10:
            return {"error": "at most 10 proposals per run"}
        doc = await self.repo.add_knowledge(kind, a["title"], a.get("body", ""), status="proposed",
                                            created_by="ai", rule_ids=a.get("rule_ids"), source_run=self.run_id)
        self.proposals.append(doc)
        return {"ok": True, "id": doc["id"], "status": "proposed",
                "note": "No effect until the user approves it in the UI."}

    async def list_reports(self, a):
        runs = await self.repo.list_runs(int(min(a.get("size", 10), 30)))
        return [{"run_id": r["run_id"], "started_at": r.get("started_at"), "status": r.get("status"),
                 "health": r.get("health"), "window": r.get("window"), "metrics": r.get("metrics"),
                 "headline": (r.get("summary_md") or "")[:200]} for r in runs]

    async def get_report(self, a):
        if a.get("run_id"):
            r = await self.repo.get_run(a["run_id"])
        else:
            r = await self.repo.last_success()
        if not r:
            return {"error": "report not found"}
        return {k: r.get(k) for k in ("run_id", "started_at", "window", "health", "metrics", "summary_md",
                                       "findings", "questions", "flags")}

    async def knowledge(self, a):
        rows = await self.repo.list_knowledge(kinds=a.get("kinds"), status=a.get("status") or ["active", "proposed"])
        return [{"id": r["id"], "kind": r["kind"], "status": r["status"], "title": r["title"],
                 "body": r["body"][:600], "rule_ids": r.get("rule_ids")} for r in rows]

    async def submit_report(self, a):
        self.submitted = a
        return {"ok": True}


# --------------------------------------------------------------------------- schemas
def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


LABELS = ["real_incident", "investigate", "detection_gap", "false_positive", "baseline_increase",
          "measurement", "expected", "correction"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]

FINDING = _obj({
    "label": {"type": "string", "enum": LABELS,
              "description": "real_incident=confirmed or very likely incident; investigate=evidence insufficient; "
                             "detection_gap=something that should alert but does not; false_positive=noise, "
                             "level-lowering candidate; baseline_increase=known noise with abnormal volume; "
                             "measurement=result of a watched rule/metric; expected=explained/verified; "
                             "correction=corrects an earlier assessment"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "title": {"type": "string", "description": "One-line title"},
    "detail": {"type": "string", "description": "Evidence and reasoning (markdown, short)"},
    "evidence": {"type": "array", "items": {"type": "string"}, "description": "Concrete numbers / times / IPs"},
    "rule_ids": {"type": "array", "items": {"type": "string"}},
    "agents": {"type": "array", "items": {"type": "string"}},
    "recommendation": {"type": "string", "description": "Recommended manual action or next step"},
    "rule_draft_xml": {"type": "string", "description": "Optional Wazuh rule draft (XML). Never applied, suggestion only."},
}, ["label", "severity", "title", "detail"])

SPECS: dict[str, dict] = {
    "search_alerts": {"name": "search_alerts", "description":
        "Search the alerts index; returns compact events (max 25). Use it to look at raw samples.",
        "parameters": _obj({**FILTER_PROPS, "size": {"type": "integer"},
                            "oldest_first": {"type": "boolean"}})},
    "aggregate_alerts": {"name": "aggregate_alerts", "description":
        "Count filtered alerts by a field (terms). Fields: rule.id, agent.name, data.srcip, data.url, "
        "data.id (HTTP status), rule.groups, data.srcuser, data.dstuser, syscheck.path, location, decoder.name, "
        "data.user.username, data.verb, data.objectRef.resource ... Optional sub_field for a second split.",
        "parameters": _obj({**FILTER_PROPS, "field": {"type": "string"}, "sub_field": {"type": "string"},
                            "size": {"type": "integer"}}, ["field"])},
    "rule_timeline": {"name": "rule_timeline", "description":
        "Time distribution (date_histogram) of matching alerts. Use it BEFORE interpreting a rule's volume.",
        "parameters": _obj({**FILTER_PROPS, "interval": {"type": "string", "description": "10m, 1h, 1d"}})},
    "ip_profile": {"name": "ip_profile", "description":
        "Profile of one IP or a prefix ('203.0.113.' / '2001:db8:0:'): rules, HTTP codes, distinct paths, "
        "users, timeline, samples.",
        "parameters": _obj({"ip": {"type": "string"}, "interval": {"type": "string"}, **TIME_PROPS}, ["ip"])},
    "correlate_around": {"name": "correlate_around", "description":
        "Other alerts within ±N minutes (default 30) of a timestamp, optionally on the same agent.",
        "parameters": _obj({"timestamp": {"type": "string"}, "agent": {"type": "string"},
                            "minutes": {"type": "integer"}, "min_level": {"type": "integer"}}, ["timestamp"])},
    "vulnerabilities": {"name": "vulnerabilities", "description":
        "Vulnerability state index summary (severity, top CVEs, packages); optional agent/severity filter.",
        "parameters": _obj({"agent": {"type": "string"}, "severity": {"type": "string"}, "size": {"type": "integer"}})},
    "agent_info": {"name": "agent_info", "description":
        "Agent details from the Wazuh API (status, version, OS, last keepalive) plus a 24 h alert summary.",
        "parameters": _obj({"agent": {"type": "string", "description": "agent name or id"}}, ["agent"])},
    "rule_info": {"name": "rule_info", "description": "Rule definitions (level, description, file, groups, conditions).",
        "parameters": _obj({"rule_ids": {"type": "array", "items": {"type": "string"}}}, ["rule_ids"])},
    "logtest": {"name": "logtest", "description":
        "Run a log line through the manager's CURRENT ruleset (wazuh-logtest API) and see which decoder/rule/level "
        "matches. Cannot test a new draft rule (it is not loaded).",
        "parameters": _obj({"event": {"type": "string"}, "log_format": {"type": "string"},
                            "location": {"type": "string"}}, ["event"])},
    "validate_rule_xml": {"name": "validate_rule_xml", "description":
        "Check a rule draft for XML syntax, OS_Regex pitfalls and rule ID collisions. Never applies it.",
        "parameters": _obj({"xml": {"type": "string"}}, ["xml"])},
    "propose_knowledge": {"name": "propose_knowledge", "description":
        "Add a PROPOSAL to the knowledge base (baseline, decision, open item, lesson, rule draft). It has no "
        "effect until the user approves it. Only for durable, reusable knowledge.",
        "parameters": _obj({"kind": {"type": "string", "enum": [k for k in KNOWLEDGE_KINDS if k != "answer"]},
                            "title": {"type": "string"}, "body": {"type": "string"},
                            "rule_ids": {"type": "array", "items": {"type": "string"}}}, ["kind", "title"])},
    "list_reports": {"name": "list_reports", "description": "List of recent daily triage reports.",
        "parameters": _obj({"size": {"type": "integer"}})},
    "get_report": {"name": "get_report", "description": "A full report (the last successful one if run_id is omitted).",
        "parameters": _obj({"run_id": {"type": "string"}})},
    "knowledge": {"name": "knowledge", "description": "Knowledge base entries (baseline, decisions, open items...).",
        "parameters": _obj({"kinds": {"type": "array", "items": {"type": "string"}},
                            "status": {"type": "array", "items": {"type": "string"}}})},
    "submit_report": {"name": "submit_report", "description":
        "Submit the daily diagnostic report. The LAST step of the run; call it exactly once.",
        "parameters": _obj({
            "summary_md": {"type": "string", "description": "2-6 sentence executive summary (markdown): volume, is there real risk, what awaits approval."},
            "health_assessment": {"type": "string", "description": "One paragraph on infrastructure health (SIEM flow, agents, disk)."},
            "findings": {"type": "array", "items": FINDING},
            "questions": {"type": "array", "description": "Questions for the user (e.g. 'Was this SSH login yours?'). Answers become context for the next run.",
                          "items": _obj({"question": {"type": "string"}, "why": {"type": "string"}}, ["question"])},
            "open_items": {"type": "array", "items": {"type": "string"}, "description": "Still open / to measure next run"},
            "closed_items": {"type": "array", "items": {"type": "string"}, "description": "Open items from the knowledge base that this run shows as closed (use their titles)"},
        }, ["summary_md", "findings"])},
}
