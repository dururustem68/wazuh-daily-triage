# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""What an error looks like to a party outside the trust boundary (the LLM, an MCP client).

Exception texts carry internals: endpoint URLs, index names, raw indexer/API responses, file paths.
The model and external MCP clients only need to know *what kind* of failure happened and what to do
next; the operator gets the full text and traceback in the log, joined by a short reference.
"""
from __future__ import annotations

import re
import secrets

PUBLIC = {
    "timeout": "the data source timed out — narrow the time window or the filter",
    "busy": "the data source is overloaded (too many requests) — retry later with a narrower query",
    "bad_query": "the data source rejected the query — check the query syntax and field names",
    "not_found": "the data source does not have the requested object",
    "auth": "the data source refused access — this needs the operator (credentials/permissions)",
    "unreachable": "the data source is unreachable — this needs the operator",
    "internal": "the tool failed with an internal error",
}


_STATUS = re.compile(r"(?<![\d.:])([45]\d\d)(?![\d.])")


def classify(e: BaseException) -> str:
    """Map an exception to one of the PUBLIC categories without exposing its text."""
    name = type(e).__name__
    text = str(e).lower()
    if "timeout" in name.lower() or "timed out" in text:
        return "timeout"
    if name not in ("IndexerError", "WazuhAPIError", "SourceError"):
        return "internal"
    if "cannot reach" in text:
        return "unreachable"
    if "authorization error" in text or "authentication failed" in text:
        return "auth"
    m = _STATUS.search(text)
    code = int(m.group(1)) if m else 0
    if code == 429:
        return "busy"
    if code in (401, 403):
        return "auth"
    if code == 404:
        return "not_found"
    if code in (400, 422):
        return "bad_query"
    return "internal"


def public_error(e: BaseException) -> tuple[dict, str]:
    """``({"error", "kind", "ref"}, ref)`` — log the real exception together with ``ref``."""
    kind = classify(e)
    ref = secrets.token_hex(4)
    return {"error": PUBLIC[kind], "kind": kind, "ref": ref}, ref
