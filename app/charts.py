# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Small server-rendered SVG charts.

No JavaScript and no inline ``style``: colours come from CSS classes (``.c-total``, ``.c-high`` …), so the strict
Content-Security-Policy stays as it is, the charts follow the light/dark theme, and the same markup works in the
PDF export. Hover text is the native SVG ``<title>``. Every chart has ``role="img"`` and an ``aria-label``; the
numbers it shows are also on the page as text.
"""
from __future__ import annotations

import math
from collections.abc import Sequence

from markupsafe import Markup, escape


def _f(x: float) -> str:
    return f"{x:.1f}".rstrip("0").rstrip(".")


def nice_max(v: float) -> float:
    """Round the axis maximum up to 1, 2, 2.5 or 5 × 10ⁿ."""
    if v <= 0:
        return 1
    e = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * e:
            return m * e
    return 10 * e


def compact(n: float) -> str:
    n = float(n)
    for div, suf in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs(n) >= div:
            return _f(n / div) + suf
    return _f(n)


def area(series: Sequence[dict], keys: Sequence[tuple[str, str, str]], label: str, *, width: int = 720,
         height: int = 180, xlabel=None, ticks: int = 6) -> Markup:
    """Overlaid areas, one per ``(key, css_class, name)``; the first key is drawn first (the largest)."""
    n = len(series)
    if not n:
        return Markup("")
    pl, pr, pt, pb = 40, 8, 10, 22
    w, h = width - pl - pr, height - pt - pb
    top = nice_max(max((s.get(k, 0) for s in series for k, _, _ in keys), default=0))
    step = w / max(n - 1, 1)

    def x(i):
        return pl + (i * step if n > 1 else w / 2)

    def y(v):
        return pt + h - (v / top) * h

    parts = [f'<svg class="chart area" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(label)}">']
    for g in range(5):
        gy = pt + h * g / 4
        parts.append(f'<line class="gl" x1="{pl}" x2="{width - pr}" y1="{_f(gy)}" y2="{_f(gy)}"/>')
        parts.append(f'<text class="ax" x="{pl - 6}" y="{_f(gy + 3)}" text-anchor="end">{compact(top * (4 - g) / 4)}</text>')
    for k, cls, _ in keys:
        pts = [f"{_f(x(i))},{_f(y(s.get(k, 0)))}" for i, s in enumerate(series)]
        line = " ".join(pts)
        poly = f"{_f(x(0))},{_f(pt + h)} {line} {_f(x(n - 1))},{_f(pt + h)}"
        parts.append(f'<polygon class="fill {cls}" points="{poly}"/>')
        parts.append(f'<polyline class="stroke {cls}" points="{line}"/>')
    every = max(1, round(n / ticks))
    for i, s in enumerate(series):
        if xlabel and (i % every == 0 or i == n - 1) and (i == n - 1 or n - 1 - i >= every / 2):
            parts.append(f'<text class="ax" x="{_f(x(i))}" y="{height - 6}" text-anchor="middle">{escape(xlabel(s))}</text>')
        tip = (escape(xlabel(s)) if xlabel else "") + "".join(f" · {escape(nm)}: {s.get(k, 0):,}" for k, _, nm in keys)
        x0 = x(i) - step / 2 if n > 1 else pl
        parts.append(f'<rect class="hit" x="{_f(max(pl, x0))}" y="{pt}" width="{_f(min(step, w))}" height="{h}">'
                     f"<title>{tip}</title></rect>")
    parts.append("</svg>")
    return Markup("".join(parts))


def spark(values: Sequence[float], cls: str = "c-total", label: str = "", width: int = 120, height: int = 30) -> Markup:
    n = len(values)
    if n < 2:
        return Markup("")
    top = max(values) or 1
    pts = " ".join(f"{_f(i * width / (n - 1))},{_f(height - 2 - (v / top) * (height - 4))}" for i, v in enumerate(values))
    return Markup(f'<svg class="spark-mini" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" '
                  f'aria-label="{escape(label)}"><polyline class="stroke {cls}" points="{pts}"/></svg>')


def donut(segments: Sequence[tuple[str, float, str]], label: str, center: str = "", sub: str = "",
          size: int = 150) -> Markup:
    """``(name, value, css_class)`` segments as a ring; empty segments are skipped."""
    total = sum(v for _, v, _ in segments)
    r, sw = 54, 18
    c = 2 * math.pi * r
    parts = [f'<svg class="chart donut" viewBox="0 0 {size} {size}" role="img" aria-label="{escape(label)}">',
             f'<circle class="track" cx="{size / 2}" cy="{size / 2}" r="{r}" stroke-width="{sw}"/>']
    off = 0.0
    if total:
        for name, v, cls in segments:
            if v <= 0:
                continue
            ln = c * v / total
            parts.append(f'<circle class="seg {cls}" cx="{size / 2}" cy="{size / 2}" r="{r}" stroke-width="{sw}" '
                         f'stroke-dasharray="{_f(ln)} {_f(c - ln)}" stroke-dashoffset="{_f(-off)}" '
                         f'transform="rotate(-90 {size / 2} {size / 2})"><title>{escape(name)}: {int(v):,} '
                         f'({_f(100 * v / total)}%)</title></circle>')
            off += ln
    parts.append(f'<text class="big" x="{size / 2}" y="{size / 2 + 2}" text-anchor="middle">{escape(center)}</text>')
    if sub:
        parts.append(f'<text class="ax" x="{size / 2}" y="{size / 2 + 18}" text-anchor="middle">{escape(sub)}</text>')
    parts.append("</svg>")
    return Markup("".join(parts))


def meter(value: float, top: float, cls: str = "c-total", second: float | None = None, cls2: str = "c-high") -> Markup:
    """A thin horizontal bar (0…top); ``second`` overlays a part of it (e.g. the high-level share)."""
    top = top or 1
    w1 = max(0.6, 100 * value / top) if value else 0
    out = (f'<svg class="meter" viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">'
           f'<rect class="track" width="100" height="6" rx="3"/>'
           f'<rect class="{cls}" width="{_f(w1)}" height="6" rx="3"/>')
    if second:
        out += f'<rect class="{cls2}" width="{_f(max(0.6, 100 * second / top))}" height="6" rx="3"/>'
    return Markup(out + "</svg>")
