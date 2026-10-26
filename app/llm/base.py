# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Provider-independent message/tool model.

Messages:
  {"role": "user", "content": str}
  {"role": "assistant", "content": str | None, "tool_calls": [{"id", "name", "input"}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}
Tool: {"name", "description", "parameters": <JSON Schema>}
"""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Protocol

import httpx

log = logging.getLogger("wdt.llm")
RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    stop_reason: str = ""


class LLMError(RuntimeError):
    pass


async def post_with_retry(client: httpx.AsyncClient, url: str, *, content: str, headers: dict,
                          retries: int = 4, base_delay: float = 2.0, max_delay: float = 60.0,
                          label: str = "LLM") -> httpx.Response:
    """POST with retries on transient errors (overload, rate limit, gateway, network).

    Honours Retry-After (seconds) when the provider sends it; otherwise exponential backoff with jitter.
    Non-transient errors (400, 401, 403, 404...) are returned immediately.
    """
    attempt = 0
    while True:
        try:
            r = await client.post(url, content=content, headers=headers)
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            if attempt >= retries:
                raise LLMError(f"cannot reach {label} ({url}) after {attempt + 1} attempts: {e}") from e
            delay = min(max_delay, base_delay * 2 ** attempt) * (0.75 + random.random() / 2)
            log.warning("%s network error (%s); retry %d/%d in %.0fs", label, type(e).__name__, attempt + 1, retries, delay)
        else:
            if r.status_code not in RETRY_STATUS or attempt >= retries:
                return r
            ra = r.headers.get("retry-after")
            try:
                delay = min(max_delay, float(ra)) if ra else None
            except ValueError:
                delay = None
            if delay is None:
                delay = min(max_delay, base_delay * 2 ** attempt) * (0.75 + random.random() / 2)
            log.warning("%s HTTP %d; retry %d/%d in %.0fs", label, r.status_code, attempt + 1, retries, delay)
        attempt += 1
        await asyncio.sleep(delay)


class LLM(Protocol):
    name: str

    async def complete(self, system: str, messages: list[dict], tools: list[dict],
                       force_tool: str | None = None) -> LLMResponse: ...


def make_llm(cfg) -> LLM:
    if cfg.provider == "anthropic":
        from .anthropic import AnthropicLLM
        return AnthropicLLM(cfg)
    if cfg.provider == "openai":
        from .openai_compat import OpenAICompatLLM
        return OpenAICompatLLM(cfg)
    if cfg.provider == "mock":
        from .mock import MockLLM
        return MockLLM()
    raise ValueError(f"unknown LLM provider: {cfg.provider}")
