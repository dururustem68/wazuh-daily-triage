# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""PDF rendering (reportlab, pure Python) for the monthly audit report.

Uses a bundled TrueType font when available so non-Latin characters (Turkish
ş/ğ/ı, Spanish accents, German umlauts) render correctly; falls back to the
built-in Helvetica otherwise.
"""
from __future__ import annotations

import io
import os

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .i18n import t

_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"

_PREFERRED = [
    ("Vera.ttf", "VeraBd.ttf"),
    ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf"),
]


def _register_font():
    """Register a Unicode TTF (Turkish/accents) when one is bundled with reportlab."""
    global _FONT, _FONT_BOLD
    base = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
    for regular, bold in _PREFERRED:
        p = os.path.join(base, regular)
        if os.path.exists(p):
            try:
                pdfmetrics.registerFont(TTFont("Wdt", p))
                b = os.path.join(base, bold)
                if os.path.exists(b):
                    pdfmetrics.registerFont(TTFont("Wdt-Bold", b))
                else:
                    pdfmetrics.registerFont(TTFont("Wdt-Bold", p))
                pdfmetrics.registerFontFamily("Wdt", normal="Wdt", bold="Wdt-Bold",
                                              italic="Wdt", boldItalic="Wdt-Bold")
                _FONT, _FONT_BOLD = "Wdt", "Wdt-Bold"
                return
            except Exception:  # noqa: BLE001 — font is a nicety, never fail the PDF
                continue


_register_font()

_INK = colors.HexColor("#1a1a2e")
_ACCENT = colors.HexColor("#2563eb")
_MUTED = colors.HexColor("#555555")
_GRID = colors.HexColor("#d0d4dc")
_HEAD_BG = colors.HexColor("#eef1f6")


def _esc(s) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles():
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName=_FONT_BOLD, fontSize=18, textColor=_INK, spaceAfter=4)
    sub = ParagraphStyle("sub", parent=ss["Normal"], fontName=_FONT, fontSize=8.5, textColor=_MUTED, spaceAfter=10)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName=_FONT_BOLD, fontSize=12.5, textColor=_ACCENT,
                        spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("body", parent=ss["Normal"], fontName=_FONT, fontSize=9.5, leading=13)
    cell = ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11)
    return h1, sub, h2, body, cell


def _table(headers: list[str], rows: list[list], cell, widths, col_widths=None):
    data = [[Paragraph(_esc(h), cell) for h in headers]] + \
           [[Paragraph(_esc(c), cell) for c in row] for row in rows]
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _HEAD_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), _INK),
        ("FONTNAME", (0, 0), (-1, 0), _FONT_BOLD),
        ("GRID", (0, 0), (-1, -1), 0.4, _GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    tbl.setStyle(TableStyle(style))
    return tbl, widths


def _kv(story, h2, body, label, value):
    story.append(Paragraph(f"<b>{_esc(label)}</b> {_esc(value)}", body))


def audit_pdf(d: dict, lang: str = "en") -> bytes:
    """Render the monthly audit dict to a PDF, in the given UI language."""
    L = lang
    h1, sub, h2, body, cell = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=_esc(d.get("title", "Wazuh Daily Triage")),
                            leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    story = []
    story.append(Paragraph(_esc(d.get("title", "")), h1))
    story.append(Paragraph(_esc(f"{t(L, 'au.period')}: {str(d.get('from', ''))[:10]} – {str(d.get('to', ''))[:10]}  ·  "
                                f"{t(L, 'au.generated')}: {str(d.get('generated_at', ''))[:16].replace('T', ' ')} UTC"), sub))

    v = d.get("volume") or {}
    if v:
        story.append(Paragraph(_esc(t(L, "au.volume")), h2))
        _kv(story, h2, body, f"{t(L, 'au.total')}:", f"{v.get('total', 0):,}")
        _kv(story, h2, body, f"{t(L, 'au.high', l=v.get('high_level', ''))}:", f"{v.get('high', 0):,}")
        _kv(story, h2, body, f"{t(L, 'au.agents')}:", str(v.get("agents") or "—"))
        levels = v.get("levels") or {}
        if levels:
            rows = [[str(k), f"{n:,}"] for k, n in sorted(levels.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else -1)]
            story.append(_table([t(L, "au.level"), t(L, "au.count")], rows, cell, [60 * mm, 40 * mm], [60 * mm, 40 * mm])[0])
        if v.get("top_high"):
            story.append(Spacer(1, 6))
            story.append(Paragraph(_esc(t(L, "au.top_high", l=v.get('high_level', ''))), h2))
            rows = [[str(r.get("id", "")), str(r.get("level", "")), f"{r.get('n', 0):,}", str(r.get("desc", ""))] for r in v["top_high"]]
            story.append(_table([t(L, "au.rule"), t(L, "au.level"), t(L, "au.count"), t(L, "au.desc")], rows,
                                cell, [20 * mm, 16 * mm, 22 * mm, 122 * mm],
                                [20 * mm, 16 * mm, 22 * mm, 122 * mm])[0])

    r = d.get("runs") or {}
    story.append(Paragraph(_esc(t(L, "au.runs")), h2))
    _kv(story, h2, body, "", t(L, "au.runs_line", n=r.get("count", 0), ok=r.get("health", {}).get("ok", 0),
                                 w=r.get("health", {}).get("warn", 0), c=r.get("health", {}).get("critical", 0),
                                 e=r.get("error", 0), a=r.get("ai_failed", 0)))

    f = d.get("findings") or {}
    story.append(Paragraph(_esc(t(L, "au.findings")), h2))
    by_label = ", ".join(f"{t(L, 'label.' + k)} {n}" for k, n in (f.get("by_label") or {}).items())
    by_dec = ", ".join(f"{t(L, 'us.' + k)} {n}" for k, n in (f.get("by_decision") or {}).items())
    _kv(story, h2, body, "", by_label or "—")
    _kv(story, h2, body, "", by_dec or "—")
    if f.get("notable"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(_esc(t(L, "au.notable")), h2))
        rows = [[str(x.get("at", ""))[:10], str(x.get("title", "")), t(L, "us." + str(x.get("user_status", "")))] for x in f["notable"]]
        story.append(_table([t(L, "au.date"), t(L, "au.finding"), t(L, "au.decision")], rows, cell,
                            [24 * mm, 128 * mm, 28 * mm], [24 * mm, 128 * mm, 28 * mm])[0])

    rc = d.get("rule_changes") or []
    story.append(Paragraph(_esc(t(L, "au.rule_changes")), h2))
    if rc:
        rows = [[str(x.get("at", ""))[:16].replace("T", " "), f"{x.get('action', '')} → {x.get('state', '')}",
                 ", ".join(str(i) for i in (x.get("ids") or [])), str(x.get("by", "")), str(x.get("title", ""))] for x in rc]
        story.append(_table([t(L, "au.date"), t(L, "au.action"), "ID", t(L, "au.by"), t(L, "au.title_col")], rows, cell,
                            [28 * mm, 34 * mm, 34 * mm, 30 * mm, 54 * mm], [28 * mm, 34 * mm, 34 * mm, 30 * mm, 54 * mm])[0])
    else:
        story.append(Paragraph(_esc(t(L, "au.none")), body))

    lv = d.get("liveness") or {}
    story.append(Paragraph(_esc(t(L, "au.liveness")), h2))
    if lv.get("events"):
        rows = [[f"{str(e.get('start', ''))[:16].replace('T', ' ')} → {str(e.get('end') or t(L, 'au.ongoing'))[:16].replace('T', ' ')}",
                 f"{e.get('minutes') or '…'} min", str(e.get("msg", ""))] for e in lv["events"]]
        story.append(_table([t(L, "au.period"), "min", ""], rows, cell, [44 * mm, 16 * mm, 120 * mm],
                            [44 * mm, 16 * mm, 120 * mm])[0])
    else:
        story.append(Paragraph(_esc(t(L, "au.no_outage") if lv.get("enabled") else t(L, "au.live_off")), body))

    cov = d.get("coverage")
    if cov:
        story.append(Paragraph(_esc(t(L, "au.coverage")), h2))
        _kv(story, h2, body, "", ", ".join(f"{k} {n}" for k, n in (cov.get("by_status") or {}).items()) or "—")
        inv = cov.get("inventory") or {}
        if inv.get("missing"):
            _kv(story, h2, body, t(L, "au.inv_missing") + ":", ", ".join(inv["missing"]))

    vu = d.get("vulnerabilities")
    if vu:
        story.append(Paragraph(_esc(t(L, "au.vulns")), h2))
        _kv(story, h2, body, "", ", ".join(f"{k} {n}" for k, n in (vu.get("severity") or {}).items()) or "—")
        for sev, s in (vu.get("sla") or {}).items():
            if isinstance(s, dict):
                _kv(story, h2, body, f"{sev}:", f"SLA {s.get('days')} d — {t(L, 'au.overdue')} {s.get('overdue', 0)}")

    if d.get("open_items"):
        story.append(Paragraph(_esc(t(L, "kind.open_item")), h2))
        for it in d["open_items"]:
            story.append(Paragraph("• " + _esc(it.get("title", "")), body))

    doc.build(story)
    return buf.getvalue()
