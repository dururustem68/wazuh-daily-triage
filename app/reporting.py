# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Normalise model output into the report schema used by the UI and notifications."""
from __future__ import annotations

import json
import os

from .agent.tools import LABELS, SEVERITIES
from .collector import _parse
from .i18n import t


def demo_enabled() -> bool:
    return os.environ.get("WDT_DEMO", "").lower() in ("1", "true", "yes")


def _neg_ts(ts: str | None) -> float:
    if not ts:
        return 0.0
    try:
        return -_parse(ts).timestamp()
    except Exception:  # noqa: BLE001
        return 0.0


def _as_list(v) -> list:
    if isinstance(v, str):  # some models send arrays as JSON-encoded strings
        try:
            v = json.loads(v)
        except ValueError:
            return [v] if v.strip() else []
    if isinstance(v, dict):
        v = [v]
    return v if isinstance(v, list) else []


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "\n".join(f"- {_s(x)}" for x in v)
    return json.dumps(v, ensure_ascii=False)


def normalize_report(sub: dict | None, fallback_text: str = "", lang: str = "en") -> dict:
    """Force model output into the schema so one malformed field cannot fail a paid run."""
    sub = sub if isinstance(sub, dict) else {}
    findings: list[dict] = []
    for f in _as_list(sub.get("findings")):
        if isinstance(f, str):
            f = {"title": f}
        if not isinstance(f, dict):
            continue
        f = {k: (_s(v) if k in ("title", "detail", "recommendation", "rule_draft_xml", "label", "severity") else v)
             for k, v in f.items()}
        for k in ("evidence", "rule_ids", "agents"):
            f[k] = [_s(x) for x in _as_list(f.get(k))]
        f["manual_checks"] = [{"host": _s(c.get("host")), "purpose": _s(c.get("purpose")), "command": _s(c.get("command"))}
                              for c in _as_list(f.get("manual_checks")) if isinstance(c, dict) and c.get("command")][:8]
        if f.get("label") not in LABELS:
            f["label"] = "investigate"
        if f.get("severity") not in SEVERITIES:
            f["severity"] = "medium"
        f["title"] = f.get("title") or t(lang, "untitled")
        f["id"] = f"f{len(findings) + 1}"
        f.setdefault("user_status", "new")
        findings.append(f)
    questions: list[dict] = []
    for q in _as_list(sub.get("questions")):
        if isinstance(q, str):
            q = {"question": q}
        if not isinstance(q, dict) or not q.get("question"):
            continue
        questions.append({"id": f"q{len(questions) + 1}", "question": _s(q.get("question")),
                          "why": _s(q.get("why")), "answer": None})
    summary = _s(sub.get("summary_md")) or fallback_text or t(lang, "run.no_report")
    return {"summary_md": summary, "health_assessment": _s(sub.get("health_assessment")),
            "findings": findings, "questions": questions,
            "open_items": [_s(x) for x in _as_list(sub.get("open_items"))],
            "closed_items": [_s(x) for x in _as_list(sub.get("closed_items"))]}


def _fmt_local(ts: str, tz) -> str:
    try:
        return _parse(ts).astimezone(tz).strftime("%d.%m %H:%M")
    except (ValueError, TypeError):
        return ts


def flags_only_report(flags: list[dict], err: str, lang: str, key: str = "run.ai_failed") -> dict:
    """Report built from deterministic flags only (used when the LLM is unavailable)."""
    findings: list[dict] = []
    for f in flags:
        if f.get("severity") == "info":
            continue
        crit = f.get("severity") == "critical"
        findings.append({"id": f"f{len(findings) + 1}", "label": "investigate", "severity": "high" if crit else "medium",
                         "title": f.get("message", f.get("code", "")), "detail": f"`{f.get('code')}`",
                         "evidence": [], "rule_ids": [], "agents": [], "user_status": "new"})
    return {"summary_md": t(lang, key, err=err[:300]), "health_assessment": "",
            "findings": findings, "questions": [], "open_items": [], "closed_items": []}


def _compact(c: dict) -> dict:
    """Shrink the summary sent to the LLM: hourly buckets become a plain count list."""
    c = dict(c)
    v = dict(c.get("volume") or {})
    if v.get("hourly"):
        v["hourly"] = {"start": v["hourly"][0]["t"], "step": "1h", "counts": [h["n"] for h in v["hourly"]]}
        v.pop("empty_hours", None)
    c["volume"] = v
    return c
