# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Provider-independent tool-use agent loop."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

from ..llm.base import LLM
from .tools import ToolBox

log = logging.getLogger("wdt.agent")

FINAL_ATTEMPTS = 2   # extra forced calls of the stop tool after the budget, if no valid submission yet
TRUNCATED = ("length", "max_tokens")


@dataclass
class RunResult:
    text: str = ""
    messages: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    steps: int = 0
    stopped: str = ""
    notes: list[str] = field(default_factory=list)


def _accepted(tools: ToolBox, stop_on: str | None) -> bool:
    return bool(stop_on) and getattr(tools, "submitted", None) is not None


async def run_agent(llm: LLM, system: str, messages: list[dict], tools: ToolBox, max_steps: int,
                    stop_on: str | None = None) -> RunResult:
    """The loop ends when the `stop_on` tool (triage: submit_report) has been called with a valid report.

    Tools are offered for `max_steps` calls; the last one offers only `stop_on`. If the model still has not
    submitted a usable report (text only, invalid / truncated arguments), up to FINAL_ATTEMPTS extra calls
    force `stop_on` with feedback on what went wrong.
    """
    res = RunResult(messages=list(messages))
    specs = tools.specs()
    stop_specs = [s for s in specs if s["name"] == stop_on] if stop_on else []
    total = max_steps + (FINAL_ATTEMPTS if stop_on else 0)
    for step in range(total):
        res.steps = step + 1
        final = bool(stop_on) and step >= max_steps - 1
        use_specs = stop_specs if final else specs
        if final:
            res.messages.append({"role": "user", "content":
                                 f"Tool budget exhausted. Call `{stop_on}` now with the data you have. Keep it "
                                 "compact: at most 8 findings, a few sentences per detail."})
        t0 = time.time()
        r = await llm.complete(system, res.messages, use_specs, force_tool=stop_on if final else None)
        res.input_tokens += r.input_tokens
        res.output_tokens += r.output_tokens
        res.messages.append({"role": "assistant", "content": r.text or None,
                             "tool_calls": [{"id": c.id, "name": c.name, "input": c.input} for c in r.tool_calls]})
        if r.text:
            res.text = r.text
        if r.stop_reason in TRUNCATED:
            res.notes.append(f"step {step + 1}: output limit reached")
        if not r.tool_calls:
            res.stopped = "text"
            if stop_on:
                res.messages.append({"role": "user", "content": f"Please submit the report with the `{stop_on}` tool."})
                continue
            break
        for c in r.tool_calls:
            t1 = time.time()
            out = await tools.call(c.name, c.input)
            res.trace.append({"tool": c.name, "input": c.input, "ms": int((time.time() - t1) * 1000),
                              "result_chars": len(out), "result_preview": out[:300]})
            log.info("tool %s %s (%d chars, llm %.1fs)", c.name, json.dumps(c.input, ensure_ascii=False)[:200],
                     len(out), t1 - t0)
            res.messages.append({"role": "tool", "tool_call_id": c.id, "name": c.name, "content": out})
            if stop_on and c.name == stop_on and not _accepted(tools, stop_on):
                res.notes.append(f"step {step + 1}: {stop_on} rejected: {out[:160]}")
        if _accepted(tools, stop_on):
            res.stopped = stop_on
            break
    else:
        res.stopped = "max_steps"
    return res
