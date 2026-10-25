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

from dataclasses import dataclass, field
from typing import Protocol


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


class LLM(Protocol):
    name: str

    async def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


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
