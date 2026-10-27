# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Plain-text versions of findings and questions for the UI copy buttons.

The text is meant to be pasted into a ticket, a mail or a terminal: no HTML, no
Markdown decoration beyond simple labels and bullets.
"""
from __future__ import annotations

from .i18n import t

# A copy button renders its payload into an HTML attribute; keep that bounded so a long rule draft or a
# model that ignores the length guidance cannot produce a multi-hundred-KB page.
MAX_COPY_CHARS = 12_000


def _join(items) -> str:
    return ", ".join(str(x) for x in items)


def _clip(text: str) -> str:
    """Keep copy payloads small; the tail is cut with an explicit marker."""
    if len(text) <= MAX_COPY_CHARS:
        return text
    return text[:MAX_COPY_CHARS].rstrip() + "\n…"


def _header(context: str | None) -> list[str]:
    return [context.strip(), ""] if context and context.strip() else []


def finding_text(f: dict, lang: str, context: str | None = None) -> str:
    """One finding as plain text (title, classification, evidence, recommendation, checks)."""
    label = f.get("label") or "investigate"
    severity = f.get("severity") or "medium"
    title = str(f.get("title") or "").strip()
    lines = _header(context) + ([title] if title else [])
    lines += ["", f"{t(lang, 'label.' + label)} · {t(lang, 'sev.' + severity)}"]

    detail = str(f.get("detail") or "").strip()
    if detail:
        lines += ["", detail]
    evidence = f.get("evidence") or []
    if evidence:
        lines += ["", *[f"- {e}" for e in evidence]]
    if f.get("rule_ids"):
        lines += ["", f"{t(lang, 'rep.rules')}: {_join(f['rule_ids'])}"]
    if f.get("agents"):
        lines += ["", f"{t(lang, 'rep.agents')}: {_join(f['agents'])}"]
    recommendation = str(f.get("recommendation") or "").strip()
    if recommendation:
        lines += ["", f"{t(lang, 'rep.recommendation')} {recommendation}"]

    checks = f.get("manual_checks") or []
    if checks:
        lines += ["", f"{t(lang, 'rep.manual_checks')}:"]
        for c in checks:
            head = " — ".join(x for x in (str(c.get("host") or "").strip(), str(c.get("purpose") or "").strip()) if x)
            lines += [""]
            if head:
                lines.append(head)
            command = str(c.get("command") or "").strip()
            if command:
                lines.append(command)

    xml = str(f.get("rule_draft_xml") or "").strip()
    if xml:
        lines += ["", f"{t(lang, 'rep.rule_draft')}:", "", xml]
    return _clip("\n".join(lines).strip())


def question_text(q: dict, lang: str = "en", context: str | None = None) -> str:
    """One question as plain text, including why it was asked, any answer and where it came from."""
    lines = _header(context) + [str(q.get("question") or "").strip()]
    why = str(q.get("why") or "").strip()
    if why:
        lines += ["", why]
    answer = str(q.get("answer") or "").strip()
    if answer:
        lines += ["", f"✓ {answer}"]
    return _clip("\n".join(lines).strip())
