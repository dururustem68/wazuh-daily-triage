# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Guard rails for every query the AI (or an MCP client) can send to the indexer.

Limiting the number of returned documents alone does not make a query cheap: a 90-day window, an
arbitrary `query_string` or a one-minute histogram over two weeks can put far more load on
OpenSearch than any number of hits. These helpers enforce:

* an allow-list for field names used in filters and aggregations,
* an upper bound on the time range of one tool call,
* bucket / document / terms limits,
* a minimum histogram interval (and with it a bucket count limit).

Everything fails closed: an unparseable timestamp, an unknown field or an oversized window raises
:class:`QueryError` instead of being passed through to the cluster.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

_INTERVAL = re.compile(r"^(\d+)([smhdw])$")
_REL = re.compile(r"^now(?:([+-])(\d+)([smhdwMy]))?$")
_UNIT_HOURS = {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24, "w": 168, "M": 720, "y": 8760}
_INTERVAL_MINUTES = {"s": 1 / 60, "m": 1, "h": 60, "d": 1440, "w": 10080}

# Fields the built-in tools may filter on or aggregate by. Keep this list tight: an event field that is
# not here cannot be named by the model, so attacker-controlled text in a log line cannot turn into a
# query against an arbitrary field.
BASE_FIELDS: frozenset[str] = frozenset({
    "timestamp", "agent.name", "agent.id", "agent.ip", "manager.name", "rule.id", "rule.level",
    "rule.description", "rule.groups", "rule.mitre.id", "rule.mitre.tactic", "full_log", "location",
    "decoder.name", "data.srcip", "data.srcuser", "data.dstuser", "data.dstip", "data.url", "data.id",
    "data.protocol", "data.verb", "data.user.username", "data.objectRef", "data.objectRef.resource",
    "data.responseStatus.code", "data.vulnerability.cve", "data.vulnerability.id",
    "data.vulnerability.severity", "data.vulnerability.package.name", "syscheck.path", "syscheck.event",
    "vulnerability.severity", "vulnerability.id", "package.name", "package.version",
})


class QueryError(ValueError):
    """The query is outside the configured limits (reported to the model, never sent to the cluster)."""


def _now() -> datetime:
    return datetime.now(UTC)


def parse_time(value: str | None, now: datetime | None = None) -> datetime:
    """ISO-8601 or OpenSearch date math (now, now-24h, now-7d, now+1h). Raises QueryError otherwise."""
    now = now or _now()
    if value is None or str(value).strip() == "":
        return now
    s = str(value).strip()
    m = _REL.match(s)
    if m:
        if not m.group(1):
            return now
        hours = int(m.group(2)) * _UNIT_HOURS[m.group(3)]
        delta = timedelta(hours=hours)
        return now + delta if m.group(1) == "+" else now - delta
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise QueryError(f"invalid time {value!r}: use ISO-8601 or date math such as now-6h") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def time_range(frm: str | None, to: str | None, max_hours: int,
               now: datetime | None = None) -> tuple[datetime, datetime]:
    """Validate and clamp one tool call's window. Returns (from, to) as aware datetimes."""
    now = now or _now()
    a, b = parse_time(frm, now), parse_time(to, now)
    if a > b:
        raise QueryError("`from` is after `to`")
    span = (b - a).total_seconds() / 3600
    if span > max_hours:
        raise QueryError(f"time range is {span:.0f} h; the maximum for one query is {max_hours} h — "
                         f"narrow `from`/`to` (e.g. now-24h)")
    return a, b


def interval_minutes(value: str, minimum: str = "1m") -> float:
    """Validate a histogram interval ('10m', '1h', '1d') and enforce the configured minimum."""
    m = _INTERVAL.match(str(value or "").strip())
    if not m:
        raise QueryError(f"invalid interval {value!r}: use 30s, 1m, 1h, 1d")
    mins = int(m.group(1)) * _INTERVAL_MINUTES[m.group(2)]
    floor = interval_minutes_raw(minimum)
    if mins < floor:
        raise QueryError(f"interval {value!r} is smaller than the minimum {minimum}")
    return mins


def interval_minutes_raw(value: str) -> float:
    m = _INTERVAL.match(str(value or "").strip())
    if not m:
        return 1.0
    return int(m.group(1)) * _INTERVAL_MINUTES[m.group(2)]


def check_interval(value: str, minimum: str, span_hours: float, max_buckets: int) -> str:
    """Validate the interval and the resulting bucket count for a window of `span_hours`."""
    mins = interval_minutes(value, minimum)
    buckets = max(1, (span_hours * 60) / mins)
    if buckets > max_buckets:
        need = span_hours * 60 / max_buckets
        hint = f"{max(1, int(need + 0.999))}m" if need < 60 else f"{max(1, int(need / 60 + 0.999))}h"
        raise QueryError(f"{value!r} over {span_hours:.0f} h makes {buckets:.0f} buckets (limit {max_buckets}); "
                         f"use an interval of at least {hint} or a narrower window")
    return value


def field(name: str, extra: list[str] | None = None) -> str:
    """Allow-list check for a filter/aggregation field."""
    f = str(name or "").strip()
    if not f or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,120}", f):
        raise QueryError(f"invalid field name {name!r}")
    if f not in BASE_FIELDS and f not in set(extra or ()):
        raise QueryError(f"field {f!r} is not allow-listed for queries; use e.g. rule.id, agent.name, "
                         f"data.srcip, data.url, rule.level")
    return f


def size(value, cap: int, what: str = "size") -> int:
    """Clamp a requested bucket/document count into [1, cap]."""
    try:
        n = int(value if value is not None else cap)
    except (TypeError, ValueError) as e:
        raise QueryError(f"{what} must be an integer") from e
    if n < 1:
        raise QueryError(f"{what} must be >= 1")
    return min(n, cap)


def query_string(value: str | None) -> str | None:
    """Basic sanity check for a free-text Lucene query (length and balanced brackets)."""
    if not value:
        return None
    q = str(value).strip()
    if not q:
        return None
    if len(q) > 2000:
        raise QueryError("query is too long (max 2000 characters); narrow it with filters instead")
    for a, b in (("(", ")"), ('"', '"')):
        if q.count(a) != q.count(b):
            raise QueryError(f"unbalanced {a}{b} in query")
    if len(re.findall(r"\b(?:regexp|wildcard)\b", q, re.I)) > 3:
        raise QueryError("too many regexp/wildcard clauses; use exact terms")
    return q


def histogram_buckets(body: dict, span_hours: float, limits) -> None:
    """Walk the aggregation tree once: cap terms buckets and validate date_histogram intervals."""
    max_terms = int(getattr(limits, "max_terms_size", 50))
    max_buckets = int(getattr(limits, "max_buckets", 200))
    min_interval = getattr(limits, "min_interval", "1m")

    def walk(node, depth=0):
        if depth > 6 or not isinstance(node, dict):
            return
        for name, spec in node.items():
            if name == "aggs" or name == "aggregations":
                walk(spec, depth + 1)
                continue
            if not isinstance(spec, dict):
                continue
            terms = spec.get("terms")
            if isinstance(terms, dict):
                if "size" in terms:
                    terms["size"] = size(terms["size"], max_terms, f"{name}.terms.size")
                else:
                    terms["size"] = max_terms
                if terms.get("field"):
                    field(terms["field"], getattr(limits, "extra_fields", None))
            dh = spec.get("date_histogram")
            if isinstance(dh, dict):
                iv = dh.get("fixed_interval") or dh.get("calendar_interval") or min_interval
                check_interval(str(iv), min_interval, span_hours, max_buckets)
                if dh.get("field"):
                    field(dh["field"], getattr(limits, "extra_fields", None))
            for nested in ("aggs", "aggregations"):
                if nested in spec:
                    walk(spec[nested], depth + 1)

    walk(body.get("aggs") or {})
