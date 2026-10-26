# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""OpenAI-compatible Chat Completions (OpenAI, Azure OpenAI, Ollama, vLLM, LM Studio, LiteLLM...)."""
from __future__ import annotations

import json

import httpx

from .base import LLMError, LLMResponse, ToolCall, post_with_retry


class OpenAICompatLLM:
    name = "openai"

    def __init__(self, cfg):
        if not cfg.model:
            raise LLMError("llm.model is not set")
        self.cfg = cfg
        base = (cfg.base_url or "https://api.openai.com/v1").rstrip("/")
        # A full endpoint URL is accepted too (Azure: .../chat/completions?api-version=...)
        self.url = base if ("/chat/completions" in base) else base + "/chat/completions"
        self.client = httpx.AsyncClient(timeout=cfg.timeout)
        self._no_force = False

    @staticmethod
    def _convert(system: str, messages: list[dict]) -> list[dict]:
        out = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg = {"role": "assistant", "content": m.get("content") or ("" if m.get("tool_calls") else "…")}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [{"id": tc["id"], "type": "function",
                                          "function": {"name": tc["name"],
                                                       "arguments": json.dumps(tc["input"], ensure_ascii=False)}}
                                         for tc in m["tool_calls"]]
                out.append(msg)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        return out

    async def complete(self, system, messages, tools, force_tool=None):
        body = {"model": self.cfg.model, "messages": self._convert(system, messages),
                self.cfg.token_param: self.cfg.max_tokens}
        if self.cfg.temperature is not None:
            body["temperature"] = self.cfg.temperature
        body.update(self.cfg.extra_body or {})
        if tools:
            body["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                              "parameters": t["parameters"]}} for t in tools]
            if force_tool and not self._no_force:
                body["tool_choice"] = {"type": "function", "function": {"name": force_tool}}
        headers = {"content-type": "application/json"}
        if self.cfg.api_key:
            headers["authorization"] = f"Bearer {self.cfg.api_key}"
            headers["api-key"] = self.cfg.api_key  # Azure OpenAI
        try:
            r = await post_with_retry(self.client, self.url, content=json.dumps(body), headers=headers,
                                      retries=self.cfg.max_retries, label="LLM endpoint")
        except httpx.HTTPError as e:
            raise LLMError(f"cannot reach LLM endpoint ({self.url}): {e}") from e
        if r.status_code == 400 and "tool_choice" in body and "tool_choice" in r.text:
            self._no_force = True     # backend does not support a forced tool: ask without it
            return await self.complete(system, messages, tools)
        if r.status_code >= 400:
            raise LLMError(f"LLM {r.status_code}: {r.text[:500]}")
        d = r.json()
        ch = d["choices"][0]
        msg = ch.get("message", {})
        res = LLMResponse(text=(msg.get("content") or "").strip(), stop_reason=ch.get("finish_reason", ""))
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_raw": fn.get("arguments")}
            res.tool_calls.append(ToolCall(tc.get("id") or fn.get("name"), fn.get("name"), args))
        u = d.get("usage") or {}
        res.input_tokens = u.get("prompt_tokens", 0)
        res.output_tokens = u.get("completion_tokens", 0)
        return res
