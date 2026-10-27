# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""PDF rendering (reportlab, pure Python) for the monthly audit report.

A clean, printable layout: a coloured title band, a row of KPI cards, section
rules, zebra tables and a page footer. A bundled TrueType font is registered
when available so Turkish ş/ğ/ı, Spanish accents and German umlauts render
correctly; the built-in Helvetica is the fallback.
"""
from __future__ import annotations

import io
import os
from functools import partial

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .i18n import t

_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"

INK = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#2563eb")
MUTED = colors.HexColor("#64748b")
GRID = colors.HexColor("#e2e8f0")
HEAD_BG = colors.HexColor("#1e293b")
ZEBRA = colors.HexColor("#f8fafc")
CARD_BG = colors.HexColor("#f1f5f9")
WHITE = colors.white

_PREFERRED = [("Vera.ttf", "VeraBd.ttf"), ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf")]


def _register_font():
    global _FONT, _FONT_BOLD
    base = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
    for regular, bold in _PREFERRED:
        p = os.path.join(base, regular)
        if not os.path.exists(p):
            continue
        try:
            pdfmetrics.registerFont(TTFont("Wdt", p))
            b = os.path.join(base, bold)
            pdfmetrics.registerFont(TTFont("Wdt-Bold", b if os.path.exists(b) else p))
            pdfmetrics.registerFontFamily("Wdt", normal="Wdt", bold="Wdt-Bold",
                                          italic="Wdt", boldItalic="Wdt-Bold")
            _FONT, _FONT_BOLD = "Wdt", "Wdt-Bold"
            return
        except Exception:  # noqa: BLE001 — the font is a nicety, never fail the PDF
            continue


_register_font()

PAGE_W, PAGE_H = A4
MARGIN = 15 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


def _esc(v) -> str:
    return str(v if v is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles():
    ss = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=ss["Title"], fontName=_FONT_BOLD, fontSize=19, leading=23,
                             textColor=WHITE, spaceAfter=0, alignment=0),
        "sub": ParagraphStyle("sub", parent=ss["Normal"], fontName=_FONT, fontSize=8.5, leading=11,
                              textColor=colors.HexColor("#cbd5e1")),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName=_FONT_BOLD, fontSize=11.5, leading=14,
                             textColor=ACCENT, spaceBefore=2, spaceAfter=1),
        "body": ParagraphStyle("body", fontName=_FONT, fontSize=9, leading=12.5, textColor=INK),
        "muted": ParagraphStyle("muted", fontName=_FONT, fontSize=8, leading=11, textColor=MUTED),
        "cell": ParagraphStyle("cell", fontName=_FONT, fontSize=8.2, leading=10.5, textColor=INK),
        "cellr": ParagraphStyle("cellr", fontName=_FONT, fontSize=8.2, leading=10.5, textColor=INK, alignment=TA_RIGHT),
        "th": ParagraphStyle("th", fontName=_FONT_BOLD, fontSize=8.2, leading=10.5, textColor=WHITE),
        "thr": ParagraphStyle("thr", fontName=_FONT_BOLD, fontSize=8.2, leading=10.5, textColor=WHITE, alignment=TA_RIGHT),
    }


def _section(story, title, S):
    story.append(Spacer(1, 9))
    story.append(Paragraph(_esc(title), S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.7, color=GRID, spaceBefore=1, spaceAfter=5))


def _kpi_row(cards, S):
    cells = [[Paragraph(f'<font size="15" color="#2563eb"><b>{_esc(value)}</b></font><br/>'
                        f'<font size="7.2" color="#64748b">{_esc(label)}</font>', S["body"])]
             for value, label in cards]
    width = CONTENT_W / max(1, len(cards))
    tbl = Table([cells], colWidths=[width] * len(cards))
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, GRID),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return tbl


def _table(headers, rows, S, widths=None, numeric=()):
    if widths is None:
        widths = [CONTENT_W / len(headers)] * len(headers)
    head = [Paragraph(_esc(h), S["thr"] if i in numeric else S["th"]) for i, h in enumerate(headers)]
    data = [head]
    for r in rows:
        data.append([Paragraph(_esc(c), S["cellr"] if i in numeric else S["cell"]) for i, c in enumerate(r)])
    tbl = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    tbl.setStyle(TableStyle(style))
    return tbl


def _band(title, subtitle, S):
    tbl = Table([[Paragraph(_esc(title), S["h1"])], [Paragraph(_esc(subtitle), S["sub"])]], colWidths=[CONTENT_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HEAD_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (0, 0), 9),
        ("BOTTOMPADDING", (0, 0), (0, 0), 2),
        ("TOPPADDING", (0, 1), (0, 1), 0),
        ("BOTTOMPADDING", (0, 1), (0, 1), 9),
    ]))
    return tbl


class _NumberedCanvas(canvas.Canvas):
    """Page footer with `page X / Y` (two-pass numbering)."""

    def __init__(self, *args, label: str = "", **kwargs):
        self._label = label
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._footer(total)
            super().showPage()
        super().save()

    def _footer(self, total: int) -> None:
        self.saveState()
        self.setStrokeColor(GRID)
        self.setLineWidth(0.4)
        self.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
        self.setFont(_FONT, 7.5)
        self.setFillColor(MUTED)
        self.drawString(MARGIN, 8 * mm, "Wazuh Daily Triage — " + self._label)
        self.drawRightString(PAGE_W - MARGIN, 8 * mm, f"page {self._pageNumber} / {total}")
        self.restoreState()


def audit_pdf(d: dict, lang: str = "en") -> bytes:
    """Render the monthly audit dict to a PDF in the given UI language."""
    L = lang
    S = _styles()
    env = (d.get("env") or {}).get("name") or (d.get("env") or {}).get("id") or ""
    month = str(d.get("month") or "")
    from_date = str(d.get("from") or "")[:10]
    to_date = str(d.get("to") or "")[:10]
    generated = str(d.get("generated_at") or "")[:16].replace("T", " ")

    title = t(L, "au.title", env=env, m=month) if (env and month) else d.get("title", "")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=_esc(title),
                            author="Wazuh Daily Triage", margins=(MARGIN, MARGIN, 18 * mm, 16 * mm))
    story = []

    subtitle = f"{t(L, 'au.period')}: {from_date} – {to_date}   ·   {t(L, 'au.generated')}: {generated} UTC"
    story.append(_band(title, subtitle, S))

    v = d.get("volume") or {}
    runs = d.get("runs") or {}
    findings = d.get("findings") or {}
    rule_changes = d.get("rule_changes") or []
    liveness = d.get("liveness") or {}
    coverage = d.get("coverage") or {}
    vulns = d.get("vulnerabilities") or {}
    open_items = d.get("open_items") or []

    n_findings = sum((findings.get("by_label") or {}).values())
    n_outages = len(liveness.get("events") or [])

    story.append(Spacer(1, 8))
    story.append(_kpi_row([
        (f"{int(v.get('total') or 0):,}", t(L, "au.total")),
        (f"{int(v.get('high') or 0):,}", t(L, "au.high", l=v.get("high_level", ""))),
        (f"{int(runs.get('count') or 0):,}", t(L, "au.runs")),
        (f"{int(n_findings):,}", t(L, "au.findings")),
        (f"{len(rule_changes):,}", t(L, "au.rule_changes")),
        (f"{n_outages:,}", t(L, "au.liveness")),
    ], S))

    if v:
        _section(story, t(L, "au.volume"), S)
        story.append(Paragraph(
            f"{t(L, 'au.agents')}: <b>{_esc(v.get('agents') or '—')}</b>   ·   "
            f"{t(L, 'au.high', l=v.get('high_level', ''))}: <b>{int(v.get('high') or 0):,}</b>", S["body"]))
        levels = v.get("levels") or {}
        if levels:
            total = int(v.get("total") or 0)
            rows = []
            for k, n in levels.items():
                n = int(n)
                rows.append((str(k), f"{n:,}", f"{n * 100 / total:.1f}%" if total else "—"))
            rows.sort(key=lambda x: int(x[0]) if x[0].isdigit() else -1)
            story.append(Spacer(1, 5))
            story.append(_table([t(L, "au.level"), t(L, "au.count"), "%"], rows, S,
                                widths=[CONTENT_W * 0.3, CONTENT_W * 0.35, CONTENT_W * 0.35], numeric=(1, 2)))
        if v.get("top_high"):
            story.append(Spacer(1, 7))
            story.append(Paragraph(_esc(t(L, "au.top_high", l=v.get("high_level", ""))), S["h2"]))
            rows = [[str(r.get("id", "")), str(r.get("level", "")), f"{int(r.get('n') or 0):,}",
                     str(r.get("desc", ""))] for r in v["top_high"]]
            story.append(_table([t(L, "au.rule"), t(L, "au.level"), t(L, "au.count"), t(L, "au.desc")],
                                rows, S, widths=[CONTENT_W * 0.13, CONTENT_W * 0.10, CONTENT_W * 0.15,
                                                 CONTENT_W * 0.62], numeric=(1, 2)))

    _section(story, t(L, "au.runs"), S)
    story.append(Paragraph(_esc(t(
        L, "au.runs_line", n=runs.get("count", 0), ok=(runs.get("health") or {}).get("ok", 0),
        w=(runs.get("health") or {}).get("warn", 0), c=(runs.get("health") or {}).get("critical", 0),
        e=runs.get("error", 0), a=runs.get("ai_failed", 0))), S["body"]))

    _section(story, t(L, "au.findings"), S)
    by_label = ", ".join(f"{t(L, 'label.' + k)} {n}" for k, n in (findings.get("by_label") or {}).items())
    by_dec = ", ".join(f"{t(L, 'us.' + k)} {n}" for k, n in (findings.get("by_decision") or {}).items())
    story.append(Paragraph(f"<b>{t(L, 'au.by_label')}:</b> {_esc(by_label or '—')}", S["body"]))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f"<b>{t(L, 'au.decisions')}:</b> {_esc(by_dec or '—')}", S["body"]))
    if findings.get("notable"):
        story.append(Spacer(1, 7))
        story.append(Paragraph(_esc(t(L, "au.notable")), S["h2"]))
        rows = [[str(x.get("at", ""))[:10], str(x.get("title", "")),
                 t(L, "us." + str(x.get("user_status", "")))] for x in findings["notable"]]
        story.append(_table([t(L, "au.date"), t(L, "au.finding"), t(L, "au.decision")], rows, S,
                            widths=[CONTENT_W * 0.16, CONTENT_W * 0.66, CONTENT_W * 0.18]))

    _section(story, t(L, "au.rule_changes"), S)
    if rule_changes:
        rows = [[str(x.get("at", ""))[:16].replace("T", " "), f"{x.get('action', '')} → {x.get('state', '')}",
                 ", ".join(str(i) for i in (x.get("ids") or [])), str(x.get("by", "")),
                 str(x.get("title", ""))] for x in rule_changes]
        story.append(_table([t(L, "au.date"), t(L, "au.action"), "ID", t(L, "au.by"), t(L, "au.title_col")],
                            rows, S, widths=[CONTENT_W * 0.20, CONTENT_W * 0.20, CONTENT_W * 0.18,
                                             CONTENT_W * 0.16, CONTENT_W * 0.26]))
    else:
        story.append(Paragraph(_esc(t(L, "au.none")), S["muted"]))

    _section(story, t(L, "au.liveness"), S)
    if liveness.get("events"):
        rows = [[str(e.get("start", ""))[:16].replace("T", " "),
                 str(e.get("end") or t(L, "au.ongoing"))[:16].replace("T", " "),
                 f"{e.get('minutes') or '…'}", str(e.get("msg", ""))] for e in liveness["events"]]
        story.append(_table([t(L, "au.period"), "", "min", ""], rows, S,
                            widths=[CONTENT_W * 0.26, CONTENT_W * 0.26, CONTENT_W * 0.10, CONTENT_W * 0.38],
                            numeric=(2,)))
    else:
        story.append(Paragraph(_esc(t(L, "au.no_outage") if liveness.get("enabled") else t(L, "au.live_off")),
                               S["muted"]))

    if coverage:
        _section(story, t(L, "au.coverage"), S)
        story.append(Paragraph(", ".join(f"{k} {n}" for k, n in (coverage.get("by_status") or {}).items()) or "—",
                               S["body"]))
        inv = coverage.get("inventory") or {}
        if inv.get("missing"):
            story.append(Spacer(1, 2))
            story.append(Paragraph(f"<b>{_esc(t(L, 'au.inv_missing'))}:</b> {_esc(', '.join(inv['missing']))}",
                                   S["body"]))

    if vulns:
        _section(story, t(L, "au.vulns"), S)
        story.append(Paragraph(", ".join(f"{k} {n}" for k, n in (vulns.get("severity") or {}).items()) or "—",
                               S["body"]))
        sla = vulns.get("sla") or {}
        if sla and not sla.get("unavailable"):
            rows = [[sev, f"{int(s.get('days') or 0)} d", f"{int(s.get('overdue') or 0):,}",
                     ", ".join(f"{a} {n}" for a, n in (s.get("by_agent") or {}).items())]
                    for sev, s in sla.items() if isinstance(s, dict)]
            if rows:
                story.append(Spacer(1, 5))
                story.append(_table([t(L, "au.severity"), "SLA", t(L, "au.overdue"), t(L, "au.top_agents")],
                                    rows, S, widths=[CONTENT_W * 0.16, CONTENT_W * 0.10, CONTENT_W * 0.14,
                                                     CONTENT_W * 0.60], numeric=(1, 2)))
        elif sla:
            story.append(Paragraph(_esc(t(L, "au.sla_unavailable")), S["muted"]))

    if open_items:
        _section(story, t(L, "kind.open_item"), S)
        for it in open_items:
            story.append(Paragraph("•  " + _esc(it.get("title", "")), S["body"]))

    doc.build(story, canvasmaker=partial(_NumberedCanvas, label=f"{env} · {month}"))
    return buf.getvalue()
