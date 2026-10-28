# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Best-effort masking of text sent to the LLM (when env.redact is true).

IP addresses are kept because the analysis needs them. The goal is to reduce
e-mail addresses, passwords, tokens and card numbers reaching an external LLM;
this is not a full DLP solution.
"""
from __future__ import annotations

import re


def redact(text: str) -> str:
    """Irreversible masking (kept for compatibility; the app now uses :mod:`app.privacy`)."""
    from .privacy import Masker
    out = Masker().mask(text)
    return re.sub(r"<([a-z_]+):[0-9a-f]{6,12}>", r"<\1>", out)
