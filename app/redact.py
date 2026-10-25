# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Best-effort masking of text sent to the LLM (when env.redact is true).

IP addresses are kept because the analysis needs them. The goal is to reduce
e-mail addresses, passwords, tokens and card numbers reaching an external LLM;
this is not a full DLP solution.
"""
from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"(?i)(pass(word)?|pwd|secret|token|api[_-]?key)(\s*[=:]\s*|\"\s*:\s*\")([^\s\"&,;]+)"),
     lambda m: f"{m.group(1)}{m.group(3)}<redacted>"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), "Bearer <redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "<jwt>"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<card?>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<private-key>"),
]


def redact(text: str) -> str:
    for rx, rep in _PATTERNS:
        text = rx.sub(rep, text)
    return text
