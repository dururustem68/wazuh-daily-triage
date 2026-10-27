# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Correlation ids and a small Prometheus exposition (no extra dependency).

Every HTTP request gets an ``X-Request-ID`` (the client's, when it sends one) that is also attached to
the log records produced while it is handled and to the audit trail. Counters and histograms are kept
in memory: they are meant for "is the pipeline healthy" questions (runs, errors, durations, query
timeouts, LLM tokens, deploy/rollback outcomes), not for long-term storage.
"""
from __future__ import annotations

import contextvars
import itertools
import logging
import time
from collections import defaultdict, deque

REQUEST_ID = contextvars.ContextVar("wdt_request_id", default="-")
_seq = itertools.count(1)


def new_request_id() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S')}-{next(_seq):06d}"


class RequestIdFilter(logging.Filter):
    """Adds ``request_id`` to every log record (``-`` outside a request)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = REQUEST_ID.get()
        return True


def install_logging(level: str = "INFO", fmt: str | None = None) -> None:
    """Configure the root handler once, with the request id in every line."""
    root = logging.getLogger()
    root.setLevel(level)
    if not any(getattr(h, "_wdt", False) for h in root.handlers):
        h = logging.StreamHandler()
        h._wdt = True
        h.setFormatter(logging.Formatter(
            fmt or "%(asctime)s %(levelname)s %(name)s [%(request_id)s]: %(message)s",
            defaults={"request_id": "-"}))
        h.addFilter(RequestIdFilter())
        root.addHandler(h)
    else:
        for h in root.handlers:
            h.addFilter(RequestIdFilter())


class Metrics:
    """Counter + histogram registry with a Prometheus text renderer.

    Histograms keep cumulative ``count``/``sum`` plus a bounded window of recent values for the
    quantiles, so a long-running process cannot grow without limit.
    """

    WINDOW = 1024

    def __init__(self):
        self._c: dict[tuple, float] = defaultdict(float)
        self._h: dict[tuple, dict] = {}
        self.started = time.time()

    @staticmethod
    def _key(name: str, labels: dict | None) -> tuple:
        return (name, tuple(sorted((labels or {}).items())))

    def inc(self, name: str, value: float = 1, **labels):
        self._c[self._key(name, labels)] += value

    def observe(self, name: str, value: float, **labels):
        k = self._key(name, labels)
        h = self._h.get(k)
        if h is None:
            h = self._h[k] = {"count": 0, "sum": 0.0, "vals": deque(maxlen=self.WINDOW)}
        h["count"] += 1
        h["sum"] += float(value)
        h["vals"].append(float(value))

    def render(self) -> str:
        out = ["# HELP wdt_build_info Build information.", "# TYPE wdt_build_info gauge"]
        out.append(f'wdt_build_info{{version="{self._v()}"}} 1')
        out.append("# TYPE wdt_uptime_seconds gauge")
        out.append(f"wdt_uptime_seconds {time.time() - self.started:.0f}")
        counters: dict[str, list] = {}
        for (name, labels), v in sorted(self._c.items()):
            counters.setdefault(name, []).append((labels, v))
        for name, rows in counters.items():
            out.append(f"# TYPE {name} counter")
            out.extend(f"{name}{self._fmt(labels)} {self._num(v)}" for labels, v in rows)
        histograms: dict[str, list] = {}
        for (name, labels), h in sorted(self._h.items()):
            histograms.setdefault(name, []).append((labels, h))
        for name, rows in histograms.items():
            out.append(f"# TYPE {name} summary")
            for labels, h in rows:
                s = sorted(h["vals"])
                p95 = s[min(len(s) - 1, int(len(s) * 0.95))] if s else 0
                out.append(f"{name}_count{self._fmt(labels)} {h['count']}")
                out.append(f"{name}_sum{self._fmt(labels)} {self._num(h['sum'])}")
                q = tuple(sorted(labels + (("quantile", "0.95"),)))
                out.append(f"{name}{self._fmt(q)} {self._num(p95)}")
        return "\n".join(out) + "\n"

    @staticmethod
    def _v() -> str:
        try:
            from . import __version__
            return __version__
        except Exception:  # noqa: BLE001
            return "unknown"

    @staticmethod
    def _num(v: float) -> str:
        return str(int(v)) if float(v).is_integer() else f"{v:.6g}"

    @staticmethod
    def _fmt(labels: tuple) -> str:
        if not labels:
            return ""
        inner = ",".join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in labels)
        return "{" + inner + "}"


metrics = Metrics()
