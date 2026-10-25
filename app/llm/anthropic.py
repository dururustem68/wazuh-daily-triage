# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Anthropic Messages API (plain HTTP, no SDK dependency)."""
from __future__ import annotations

import json

import httpx

from .base import LLMError, LLMResponse, ToolCall


class AnthropicLLM:
    name = "anthropic"

    def __init__(self, cfg):
        if not cfg.api_key:
            raise LLMError("LLM_API_KEY is not set")
        if not cfg.model:
            raise LLMError("llm.model is not set")
        self.cfg = cfg
        self.url = (cfg.base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        self.client = httpx.AsyncClient(timeout=cfg.timeout)

    @staticmethod
    def _convert(messages: list[dict]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["input"]})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "…"}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list) \
                        and out[-1]["content"] and out[-1]["content"][0].get("type") == "tool_result":
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    async def complete(self, system, messages, tools):
        body = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            # The system prompt (context + knowledge base) is identical on every step: cache it.
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": self._convert(messages),
        }
        if self.cfg.temperature is not None:
            body["temperature"] = self.cfg.temperature
        body.update(self.cfg.extra_body or {})
        if tools:
            body["tools"] = [{"name": t["name"], "description": t["description"],
                              "input_schema": t["parameters"]} for t in tools]
        try:
            r = await self.client.post(self.url, content=json.dumps(body), headers={
                "x-api-key": self.cfg.api_key, "anthropic-version": "2023-06-01",
                "content-type": "application/json"})
        except httpx.HTTPError as e:
            raise LLMError(f"cannot reach Anthropic API: {e}") from e
        if r.status_code >= 400:
            raise LLMError(f"Anthropic API {r.status_code}: {r.text[:500]}")
        d = r.json()
        res = LLMResponse(stop_reason=d.get("stop_reason", ""))
        texts = []
        for b in d.get("content", []):
            if b["type"] == "text":
                texts.append(b["text"])
            elif b["type"] == "tool_use":
                res.tool_calls.append(ToolCall(b["id"], b["name"], b.get("input") or {}))
        res.text = "\n".join(texts).strip()
        u = d.get("usage", {})
        res.input_tokens = u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) + u.get("cache_creation_input_tokens", 0)
        res.output_tokens = u.get("output_tokens", 0)
        return res
