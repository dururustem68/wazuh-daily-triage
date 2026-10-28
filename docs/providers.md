# AI providers

Wazuh Daily Triage talks to two API styles: **Anthropic Messages** (`LLM_PROVIDER=anthropic`) and
**OpenAI Chat Completions** (`LLM_PROVIDER=openai`, any compatible endpoint). The model must support
**tool / function calling** — the agent drives its investigation through tools.

Model names change often. The names below were taken from each provider's documentation in October 2026;
always check the linked page for the current list.

All settings work either in `.env` (single environment) or in the `llm:` block of
`config/environments.yaml` (global or per environment).

| `.env` variable | YAML key | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `provider` | `anthropic`, `openai` or `mock` |
| `LLM_MODEL` | `model` | model id |
| `LLM_API_KEY` | `api_key` | your key |
| `LLM_BASE_URL` | `base_url` | endpoint (OpenAI-compatible providers) |
| `LLM_TEMPERATURE` | `temperature` | number, or `none` to omit it (reasoning models) |
| `LLM_TOKEN_PARAM` | `token_param` | `max_tokens` (default) or `max_completion_tokens` |
| `LLM_MAX_TOKENS` | `max_tokens` | output token limit (default 4096) |
| `LLM_REASONING_EFFORT` | `extra_body.reasoning_effort` | e.g. `low`, `medium`, `high` |
| `LLM_EXTRA_BODY` | `extra_body` | JSON object passed to the provider verbatim |
| `LLM_MAX_TOOL_STEPS` | `max_tool_steps` | tool-call budget per run (cost ceiling, default 14) |
| `LLM_MAX_RETRIES` | `max_retries` | retries on 429/5xx/overload with backoff (default 4) |

After changing anything run `docker compose exec triage python -m app.check` — the last line tests the model.

---

## Claude (Anthropic)

Keys: <https://console.anthropic.com/> · Models: <https://platform.claude.com/docs/en/models/overview>

```sh
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-5-5
LLM_API_KEY=sk-ant-...
```

- Model ids from the docs: `claude-sonnet-5-5` (speed/intelligence balance — a good default),
  `claude-opus-5-5` (most capable), `claude-haiku-5-5` (fast, low cost).
- The system prompt (environment context + knowledge base) is sent with prompt caching, so repeated tool
  steps in one run are cheaper.
- Also available through Amazon Bedrock or Google Vertex AI behind an OpenAI-compatible gateway such as
  LiteLLM (`LLM_PROVIDER=openai`, `LLM_BASE_URL=<gateway>`).

## OpenAI

Keys: <https://platform.openai.com/api-keys> · Models: <https://developers.openai.com/api/docs/models>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-6.1-sol
LLM_API_KEY=sk-...
LLM_TOKEN_PARAM=max_completion_tokens
LLM_TEMPERATURE=none
LLM_REASONING_EFFORT=medium
```

- Model ids from the docs: `gpt-6-astra` (flagship), `gpt-6.1-sol` (near-flagship at lower cost — a good
  default), `gpt-6-luna` (small, high volume). All support function calling.
- OpenAI reasoning models expect `max_completion_tokens` instead of `max_tokens` and generally reject a custom
  `temperature`; the two settings above handle both. If you get a `400` mentioning either parameter, this is
  the fix.
- **Azure OpenAI:** put the full deployment URL in `LLM_BASE_URL`, e.g.
  `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<version>`;
  the key is sent as both `Authorization: Bearer` and `api-key`.

## Google Gemini

Keys: <https://aistudio.google.com/apikey> · Docs: <https://ai.google.dev/gemini-api/docs/openai>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-3.8-flash
LLM_API_KEY=AIza...
# optional: LLM_REASONING_EFFORT=low|medium|high
```

- Uses Gemini's OpenAI-compatible endpoint; function calling is supported. Google marks this compatibility
  layer as **beta**.
- `gemini-3.8-flash` is the model used in Google's examples; pick a larger one from AI Studio for harder
  environments.
- `reasoning_effort` maps to Gemini's thinking levels. Do not set it together with `thinking_config` in
  `LLM_EXTRA_BODY`.

## DeepSeek

Keys: <https://platform.deepseek.com/api_keys> · Docs: <https://api-docs.deepseek.com/>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-flash
LLM_API_KEY=sk-...
```

- Model ids from the docs: `deepseek-flash` (fast, low cost) and `deepseek-v4-pro` (stronger).
- Thinking mode can be enabled with `LLM_EXTRA_BODY={"thinking": {"type": "enabled"}}` and
  `LLM_REASONING_EFFORT=high`.
- DeepSeek also offers an Anthropic-compatible endpoint (`LLM_PROVIDER=anthropic`,
  `LLM_BASE_URL=https://api.deepseek.com/anthropic`); the OpenAI-compatible one above is the tested path.
- **Data location:** the hosted DeepSeek API is operated from China. Consider where your alert data may go
  (GDPR, KVKK, sector rules) — the open-weight DeepSeek models can instead be run locally with Ollama/vLLM.

## Local models (Ollama, vLLM, LM Studio)

```sh
docker compose --profile ollama up -d
docker exec -it ollama ollama pull qwen3:14b
```

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=http://ollama:11434/v1
LLM_MODEL=qwen3:14b
LLM_API_KEY=
```

No alert data leaves your network. Choose a model with reliable tool calling; small models may stop early or
skip `submit_report` — the agent nudges them and falls back to a text summary, but report quality drops.

## Different model per environment

```yaml
llm:                       # default for every environment
  provider: anthropic
  model: claude-sonnet-5-5
  api_key: ${LLM_API_KEY}

environments:
  - id: regulated
    # ...
    llm:                   # this environment never sends data to a hosted model
      provider: openai
      base_url: http://ollama:11434/v1
      model: qwen3:14b
```

## Choosing

- Start with a mid-tier hosted model (Claude Sonnet, GPT Sol, Gemini Flash, DeepSeek Flash) and look at a
  week of reports before optimising cost.
- A daily run is typically 5–15 model calls; `max_tool_steps` caps it. Token counts per run are shown at the
  top of every report.
- For regulated data prefer a local model or `privacy.mode: mask` ([privacy.md](privacy.md)); read your provider's
  data-retention terms.
