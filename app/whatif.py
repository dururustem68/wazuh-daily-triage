# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
""""What would this rule draft have done?" — replay a draft against the last N days of real alerts.

For each draft rule that hangs below existing rules (`if_sid`), the parent rules' alerts of the window are
counted, a random sample is fetched, and the draft's conditions are evaluated on every sampled alert in Python.
The matched share is scaled to the full count. The result answers, before anything is deployed:

* how many alerts a day the draft would take over, and at which level they would end up,
* how many of them were at or above the environment's high level (alerts that would stop standing out),
* which agents, source IPs and log locations are affected, with a few example lines.

It is an estimate: Wazuh matches `<match>`/`<regex>` against the decoded log, here the stored `full_log` and
`data.*` are used; CDB lists, time windows and frequency (`if_matched_sid`) are not replayed — they are listed
under `not_evaluated`, and the numbers are then an upper bound.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from .rules import parse

TS = "timestamp"
SOURCE = ["full_log", "data", "agent.name", "location", "rule.id", "rule.level", "rule.groups",
          "decoder.name", "decoder.parent", "predecoder.hostname", "predecoder.program_name", TS]

# condition tag → where the value lives in an alert document
FIELD_OF = {
    "srcip": ["data.srcip"], "dstip": ["data.dstip"], "user": ["data.srcuser", "data.dstuser", "data.user"],
    "srcuser": ["data.srcuser"], "dstuser": ["data.dstuser"], "url": ["data.url"], "id": ["data.id"],
    "status": ["data.status"], "action": ["data.action"], "protocol": ["data.protocol"],
    "srcport": ["data.srcport"], "dstport": ["data.dstport"], "extra_data": ["data.extra_data"],
    "system_name": ["data.system_name"], "data": ["data.data"], "hostname": ["predecoder.hostname"],
    "program_name": ["predecoder.program_name"], "location": ["location"],
}
UNSUPPORTED = {"list", "time", "weekday", "same_source_ip", "same_srcip", "same_dstip", "same_user", "same_id",
               "same_location", "same_field", "different_srcip", "different_field", "not_same_source_ip",
               "if_fts", "check_diff", "category", "mitre", "info", "options", "description", "group",
               "if_matched_group", "if_matched_sid"}
PUNCT = r"""[!"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]"""


def _get(doc: dict, path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _flat(v: Any) -> str:
    if isinstance(v, list):
        return " ".join(_flat(x) for x in v)
    return "" if v is None else str(v)


def os_regex(pattern: str) -> re.Pattern:
    """Translate Wazuh OS_Regex to Python: `\\.` is any char, `.` is literal, `\\p` punctuation, no {n}."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            n = pattern[i + 1]
            out.append({".": ".", "p": PUNCT, "w": r"[A-Za-z0-9@_-]", "W": r"[^A-Za-z0-9@_-]", "d": r"\d",
                        "D": r"\D", "s": r"\s", "S": r"\S", "t": r"\t", "$": r"\$", "(": r"\(", ")": r"\)",
                        "\\": r"\\", "|": r"\|", "<": "<", ">": ">"}.get(n, re.escape(n)))
            i += 2
            continue
        out.append({".": r"\.", "{": r"\{", "}": r"\}", "[": r"\[", "]": r"\]", "?": r"\?"}.get(c, c))
        i += 1
    return re.compile("".join(out))


def os_match(pattern: str):
    """Wazuh OS_Match: literal substrings, `|` = or, `^`/`$` anchors, `!` negation; case-insensitive."""
    neg = pattern.startswith("!")
    alts = [a.lower() for a in (pattern[1:] if neg else pattern).split("|")]

    def test(s: str) -> bool:
        s = s.lower()
        hit = False
        for a in alts:
            if a.startswith("^") and a.endswith("$") and len(a) > 1:
                hit = s == a[1:-1]
            elif a.startswith("^"):
                hit = s.startswith(a[1:])
            elif a.endswith("$"):
                hit = s.endswith(a[:-1])
            else:
                hit = a in s
            if hit:
                break
        return hit != neg
    return test


def _matcher(tag: str, attrs: dict, text: str):
    """(test(doc) -> bool) for one condition element, or None when it cannot be evaluated here."""
    neg = attrs.get("negate") == "yes"
    typ = attrs.get("type", "")
    text = (text or "").strip()

    def textual(value_of):
        if typ in ("pcre2", "PCRE2"):
            rx = re.compile(text)
            return lambda d: bool(rx.search(value_of(d))) != neg
        if tag in ("match",) or typ == "osmatch":
            m = os_match(text)
            return lambda d: m(value_of(d)) != neg
        rx = os_regex(text)
        return lambda d: bool(rx.search(value_of(d))) != neg

    if tag in ("match", "regex"):
        return textual(lambda d: _flat(_get(d, "full_log")))
    if tag == "field":
        name = attrs.get("name", "")
        return textual(lambda d: _flat(_get(d, "data." + name) if _get(d, "data." + name) is not None
                                       else _get(d, name)))
    if tag in ("srcip", "dstip"):
        try:
            nets = [ipaddress.ip_network(x.strip().lstrip("!"), strict=False) for x in text.split(",") if x.strip()]
        except ValueError:
            return None
        neg = neg or text.startswith("!")

        def ipt(d, path=FIELD_OF[tag][0]):
            try:
                ip = ipaddress.ip_address(_flat(_get(d, path)).strip())
            except ValueError:
                return neg
            return any(ip in n for n in nets) != neg
        return ipt
    if tag in FIELD_OF:
        paths = FIELD_OF[tag]
        return textual(lambda d: " ".join(_flat(_get(d, p)) for p in paths))
    if tag == "decoded_as":
        return lambda d: (text in (_get(d, "decoder.name"), _get(d, "decoder.parent"))) != neg
    if tag == "if_group":
        return lambda d: (text in (_get(d, "rule.groups") or [])) != neg
    if tag == "if_level":
        return lambda d: int(_get(d, "rule.level") or 0) >= int(text or 0)
    return None


def compile_rule(rule_el) -> tuple[list, list[str]]:
    tests, skipped = [], []
    # Wazuh keeps every <srcip>/<dstip> of a rule in one list and fires when any of them matches: OR, not AND.
    for tag in ("srcip", "dstip"):
        texts = [(el.text or "").strip() for el in rule_el if el.tag == tag and not el.attrib]
        if len(texts) > 1:
            m = _matcher(tag, {}, ",".join(texts))
            if m is None:
                skipped.append(f"<{tag}>")
            else:
                tests.append(m)
    multi = {t for t in ("srcip", "dstip") if sum(1 for el in rule_el if el.tag == t and not el.attrib) > 1}
    for el in rule_el:
        if el.tag in ("if_sid",) or el.tag in multi:
            continue
        if el.tag in UNSUPPORTED:
            if el.tag not in ("description", "options", "mitre", "info", "group"):
                skipped.append(f"<{el.tag}>")
            continue
        try:
            m = _matcher(el.tag, dict(el.attrib), el.text or "")
        except re.error as e:
            skipped.append(f"<{el.tag}> (regex: {e})")
            continue
        if m is None:
            skipped.append(f"<{el.tag}>")
        else:
            tests.append(m)
    return tests, skipped


async def simulate(env, ix, xml: str, days: int = 14, sample: int = 2000) -> dict:
    """Replay the draft against the last `days` days; see the module docstring."""
    from defusedxml import ElementTree as SafeET

    from .rules import _normalise
    rules, errors = parse(xml)
    if errors:
        return {"ok": False, "errors": errors}
    root = SafeET.fromstring(f"<root>{_normalise(xml)}</root>")
    els = {r.get("id"): r for r in root.iter("rule")}
    now = datetime.now(UTC)
    frm = now - timedelta(days=days)
    rng = {"range": {TS: {"gte": frm.strftime("%Y-%m-%dT%H:%M:%S"), "lte": now.strftime("%Y-%m-%dT%H:%M:%S")}}}
    out = []
    for r in rules:
        parents = [p for p in r["parents"] if p.isdigit()]
        el = els.get(r["id"])
        tests, skipped = compile_rule(el) if el is not None else ([], ["rule element"])
        if r.get("frequency") or any(c.tag == "if_matched_sid" for c in (el if el is not None else [])):
            skipped.append("frequency / if_matched_sid (counts candidate events, not firings)")
        res: dict[str, Any] = {"id": r["id"], "level": r["level"], "description": r["description"],
                               "parents": parents, "not_evaluated": skipped}
        if not parents:
            res["note"] = "no if_sid parent — only child rules can be replayed"
            out.append(res)
            continue
        q = {"bool": {"filter": [rng, {"terms": {"rule.id": parents}}]}}
        agg = await ix.search(env.alerts_index, {
            "size": 0, "track_total_hits": True, "query": q,
            "aggs": {"lvl": {"terms": {"field": "rule.level", "size": 20}},
                     "day": {"date_histogram": {"field": TS, "fixed_interval": "1d", "min_doc_count": 0}}}})
        total = int((agg["hits"]["total"] or {}).get("value", 0)) if isinstance(agg["hits"]["total"], dict) \
            else int(agg["hits"]["total"])
        res["parent_events"] = total
        res["parent_levels"] = {str(b["key"]): b["doc_count"] for b in agg["aggregations"]["lvl"]["buckets"]}
        if not total:
            res.update(matched_sample=0, sampled=0, estimated=0, per_day=0.0)
            out.append(res)
            continue
        hits = (await ix.search(env.alerts_index, {
            "size": min(sample, total), "_source": SOURCE,
            "query": {"function_score": {"query": q, "random_score": {"seed": 42, "field": "_seq_no"}}}}))["hits"]["hits"]
        docs = [h.get("_source") or {} for h in hits]
        hit = [all(t(d) for t in tests) for d in docs]
        matched = [d for d, h in zip(docs, hit, strict=True) if h]
        share = len(matched) / len(docs) if docs else 0.0
        est = round(total * share)
        high = env.high_level
        hi_matched = [d for d in matched if int(_get(d, "rule.level") or 0) >= high]
        new_level = int(r["level"]) if (r["level"] or "").isdigit() else None
        res.update(
            sampled=len(docs), matched_sample=len(matched), share=round(share, 4), estimated=est,
            exact=len(docs) >= total, per_day=round(est / days, 1),
            new_level=new_level,
            high_level=high,
            high_before=round(total * len(hi_matched) / len(docs)) if docs else 0,
            high_after=(round(total * len(hi_matched) / len(docs)) if new_level is not None and new_level >= high
                        else 0) if docs else 0,
            top_agents=Counter(_flat(_get(d, "agent.name")) for d in matched).most_common(5),
            top_srcips=Counter(_flat(_get(d, "data.srcip")) for d in matched if _get(d, "data.srcip")).most_common(5),
            top_locations=Counter(_flat(_get(d, "location")) for d in matched).most_common(3),
            examples=[_flat(_get(d, "full_log"))[:240] for d in matched[:3]],
            unmatched_examples=[_flat(_get(d, "full_log"))[:240] for d, h in zip(docs, hit, strict=True) if not h][:2],
        )
        out.append(res)
    return {"ok": True, "days": days, "from": frm.isoformat(timespec="seconds"), "to": now.isoformat(timespec="seconds"),
            "rules": out}
