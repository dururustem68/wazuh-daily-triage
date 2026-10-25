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


@dataclass
class RunResult:
    text: str = ""
    messages: list[dict] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    steps: int = 0
    stopped: str = ""


async def run_agent(llm: LLM, system: str, messages: list[dict], tools: ToolBox, max_steps: int,
                    stop_on: str | None = None) -> RunResult:
    """The loop ends when the `stop_on` tool is called (triage: submit_report)."""
    res = RunResult(messages=list(messages))
    specs = tools.specs()
    for step in range(max_steps):
        res.steps = step + 1
        # on the last step only offer the submit tool so the model writes the report
        last = step == max_steps - 1
        use_specs = [s for s in specs if s["name"] == stop_on] if (last and stop_on) else specs
        if last and stop_on:
            res.messages.append({"role": "user", "content":
                                 f"Tool budget exhausted. Call `{stop_on}` now with the data you have."})
        t0 = time.time()
        r = await llm.complete(system, res.messages, use_specs)
        res.input_tokens += r.input_tokens
        res.output_tokens += r.output_tokens
        res.messages.append({"role": "assistant", "content": r.text or None,
                             "tool_calls": [{"id": c.id, "name": c.name, "input": c.input} for c in r.tool_calls]})
        if r.text:
            res.text = r.text
        if not r.tool_calls:
            res.stopped = "text"
            if stop_on and not last:
                res.messages.append({"role": "user", "content": f"Please submit the report with the `{stop_on}` tool."})
                continue
            break
        done = False
        for c in r.tool_calls:
            t1 = time.time()
            out = await tools.call(c.name, c.input)
            res.trace.append({"tool": c.name, "input": c.input, "ms": int((time.time() - t1) * 1000),
                              "result_chars": len(out), "result_preview": out[:300]})
            log.info("tool %s %s (%d chars, llm %.1fs)", c.name, json.dumps(c.input, ensure_ascii=False)[:200],
                     len(out), t1 - t0)
            res.messages.append({"role": "tool", "tool_call_id": c.id, "name": c.name, "content": out})
            if stop_on and c.name == stop_on:
                done = True
        if done:
            res.stopped = stop_on
            break
    else:
        res.stopped = "max_steps"
    return res
