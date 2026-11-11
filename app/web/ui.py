# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Jinja environment, template filters and the UI's static vocabularies."""
from __future__ import annotations

import os
from datetime import UTC
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup

from .. import __version__, charts
from ..agent.tools import LABELS, SEVERITIES
from ..collector import _parse
from ..i18n import LANG_NAMES
from ..mitre import attack_url as _attack_url
from ..store import KNOWLEDGE_KINDS

APP_DIR = Path(__file__).parent.parent

_md = MarkdownIt("commonmark", {"html": False, "linkify": False}).enable("table")

LABEL_COLORS = {"real_incident": "red", "investigate": "amber", "detection_gap": "purple", "false_positive": "gray",
                "baseline_increase": "orange", "measurement": "blue", "expected": "green", "correction": "teal"}
USER_STATUSES = ["new", "acknowledged", "false_positive", "closed", "baseline"]
HEALTH_COLORS = {"ok": "green", "warn": "amber", "critical": "red", "error": "red"}
# AGPL-3.0 §13: users interacting over a network must be offered the corresponding source.
SOURCE_URL = os.environ.get("SOURCE_URL", "https://github.com/dururustem68/wazuh-daily-triage")

_tz = UTC


def set_timezone(tz) -> None:
    """Use the configured timezone for template timestamps (called from the lifespan)."""
    global _tz
    _tz = tz


def fmt_ts(v, short=False):
    if not v:
        return "—"
    try:
        dt = _parse(v).astimezone(_tz)
    except Exception:  # noqa: BLE001
        return v
    return dt.strftime("%d.%m %H:%M" if short else "%d.%m.%Y %H:%M")


def num(v):
    if isinstance(v, (int, float)):
        return f"{int(v):,}"
    return v if v is not None else "—"


def _xlabel(period: str):
    fmt = "%H:%M" if period == "24h" else "%d.%m"

    def f(p):
        try:
            return _parse(p.get("t")).astimezone(_tz).strftime(fmt if period != "7d" else "%d.%m %H")
        except Exception:  # noqa: BLE001
            return str(p.get("t", ""))[5:16]
    return f


def volume_chart(series, period: str, names: dict, label: str, height: int = 200):
    """Alert volume over time: all alerts, high level and critical, as overlaid areas."""
    return charts.area(series, [("total", "c-total", names["total"]), ("high", "c-high", names["high"]),
                                ("crit", "c-crit", names["crit"])], label, height=height, xlabel=_xlabel(period))


def hourly_chart(hourly, label: str, name: str):
    """The report's hourly series ({t, n}) as one area."""
    return charts.area([{"t": h.get("t"), "n": h.get("n", 0)} for h in hourly or []], [("n", "c-total", name)], label,
                       height=150, xlabel=_xlabel("24h"))


def delta(v):
    """``+12 %`` / ``−8 %`` for a ratio, ``—`` when there is no previous value."""
    if v is None:
        return "—"
    pct = round(v * 100)
    return ("+" if pct > 0 else "−" if pct < 0 else "±") + f"{abs(pct)} %"


tpl = Jinja2Templates(directory=APP_DIR / "templates")
tpl.env.filters["md"] = lambda s: Markup(_md.render(s if isinstance(s, str) else str(s or "")))
tpl.env.filters["ts"] = fmt_ts
tpl.env.filters["tss"] = lambda v: fmt_ts(v, True)
tpl.env.filters["n"] = num
tpl.env.globals.update(LABEL_COLORS=LABEL_COLORS, USER_STATUSES=USER_STATUSES, HEALTH_COLORS=HEALTH_COLORS,
                       KINDS=list(KNOWLEDGE_KINDS), LANGS=LANG_NAMES, version=__version__, SOURCE_URL=SOURCE_URL,
                       LABELS=LABELS, SEVERITIES=SEVERITIES, chart=charts, volume_chart=volume_chart,
                       hourly_chart=hourly_chart, delta=delta, attack_url=_attack_url)
