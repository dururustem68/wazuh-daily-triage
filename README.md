# Wazuh Daily Triage

**AI-assisted daily review for [Wazuh](https://wazuh.com) SIEM.** Every morning it checks that your SIEM is
actually alive, separates real risk from known noise, writes a short diagnostic report back into your Wazuh
Indexer, asks you only what needs a human decision — and remembers your answers next time.

Bring your own AI: Anthropic, OpenAI, Azure OpenAI or any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio,
LiteLLM). One Docker container, read-only towards Wazuh.

[Türkçe README](README.tr.md) · [AI providers](docs/providers.md) · [Permissions & network](docs/permissions.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

![Report](docs/screenshot-report.png)

## Why

If your mornings start with the same Wazuh routine — *is data flowing, are agents connected, what is at level
7+, which of it is the usual noise, which of it is real* — this tool does the legwork and calls you only where
a decision is needed. It encodes hard-won review habits: health before alerts, distributions instead of
averages, "same count on every agent = feed event", "zero does not mean the rule works", level-lowering instead
of silencing.

## Features

- **Scheduled daily run** per environment (time + weekdays). The window is "since the last successful run", so
  Monday morning covers the weekend.
- **Deterministic collection first** — independent of the AI: last alert time and empty hours (blind spots),
  indexer health and disk, manager daemons, inactive agents, `ossec.log` errors, level distribution, high-level
  groups (rule × agent × first/last seen × source IP × sample), comparison with the previous window, rule IDs
  **seen for the first time in 14 days**, watched rules, vulnerability summary.
- **AI diagnosis** — the model reads the summary plus your knowledge base, digs deeper with read-only tools
  (time distribution, IP profile, ±30 min correlation, logtest, rule definitions) and submits a structured
  report: *real incident, investigate, detection gap, false positive, baseline increase…* It can draft Wazuh
  rules (never applies them) and checks them for XML errors, OS_Regex pitfalls and ID collisions.
- **It asks you** — "Was this SSH login yours?" Your answer goes into the knowledge base and is context for the
  next run.
- **Knowledge base** — known noise, decisions ("don't suggest X"), open items, lessons, "look at this tomorrow"
  requests. AI proposals have **no effect until you approve them**.
- **Chat** — ask questions about an environment; answers use the same tools and show their tool calls.
- **Stored in Wazuh itself** — `daily-triage-runs`, `daily-triage-knowledge`, `daily-triage-chat` indices in
  each environment's own indexer. No extra database.
- **Multi-environment, multi-language** (English, Turkish), per-environment AI override (e.g. a local model for
  regulated data), connection test in the UI and CLI.

## Quick start

### 1. Try the demo (no Wazuh needed)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git && cd wazuh-daily-triage
cp .env.example .env
sed -i 's/^WDT_DEMO=.*/WDT_DEMO=true/; s/^LLM_PROVIDER=.*/LLM_PROVIDER=mock/' .env
docker compose up -d --build
# open http://127.0.0.1:8080 — password: APP_PASSWORD from .env
```

The demo uses synthetic data (Jenkins Basic-Auth brute force, SSH attempts, a disconnected agent, a
post-update vulnerability burst…). `mock` does no real analysis; set the `LLM_*` variables to try a real model
on the same data.

### 2. Connect your Wazuh — one environment, no YAML

Create the read-only accounts described in **[docs/permissions.md](docs/permissions.md)**, then in `.env`:

```sh
WDT_DEMO=false
LLM_PROVIDER=anthropic          # or openai
LLM_MODEL=<model id from your provider>
LLM_API_KEY=<your key>
WAZUH_INDEXER_URL=https://wazuh-indexer.example.internal:9200
WAZUH_INDEXER_USER=daily-triage
WAZUH_INDEXER_PASSWORD=...
WAZUH_API_URL=https://wazuh-manager.example.internal:55000   # optional
WAZUH_API_USER=daily-triage
WAZUH_API_PASSWORD=...
WAZUH_CA_FILE=/app/config/certs/root-ca.pem                   # copy your CA into ./config/certs/
```

```sh
docker compose up -d
docker compose exec triage python -m app.check    # or "Test connections" on the environment page
```

### 3. Several environments

```sh
cp config/environments.example.yaml config/environments.yaml
vi config/environments.yaml        # one block per Wazuh; secrets as ${VARS} from .env
vi config/context/<env>.md         # a few lines describing the environment
```

`config/environments.yaml`, `config/context/*`, `config/seed/*`, `config/certs/` and `.env` are git-ignored.

## AI providers

Bring your own key. Full setup for each provider, including model names and parameter quirks:
**[docs/providers.md](docs/providers.md)**.

| Provider | `LLM_PROVIDER` | `LLM_BASE_URL` | Example `LLM_MODEL` |
|---|---|---|---|
| Claude (Anthropic) | `anthropic` | — | `claude-sonnet-5-5` |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-6.1-sol` ¹ |
| Google Gemini | `openai` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-3.8-flash` |
| DeepSeek | `openai` | `https://api.deepseek.com` | `deepseek-flash` |
| Azure OpenAI | `openai` | full deployment URL with `?api-version=` | your deployment |
| Ollama / vLLM / LM Studio / LiteLLM | `openai` | e.g. `http://ollama:11434/v1` | e.g. `qwen3:14b` |

¹ OpenAI reasoning models also need `LLM_TOKEN_PARAM=max_completion_tokens` and `LLM_TEMPERATURE=none`.

The model must support tool (function) calling. Each environment can override the model (`llm:` block) — e.g.
a local model for an environment whose data must not leave your network. `max_tool_steps` caps cost per run.

## Compatibility

- Wazuh **4.x** (developed against 4.14) — all-in-one, distributed, Docker and Kubernetes deployments.
- Wazuh Indexer / OpenSearch 2.x with the standard `wazuh-alerts-*` template. Index patterns are configurable.
- Wazuh server API is optional; without it agent/daemon health, rule info and logtest are disabled.
- Basic auth, private CA (`ca_file`) and mutual TLS (`client_cert`/`client_key`) are supported.

## Security model

- **Read-only towards Wazuh.** No active response, no rule/config writes, no agent commands. The only index
  writes go to its own `daily-triage-*` indices.
- **Prompt injection.** Alert content (URLs, `full_log`, user agents, user names) is attacker-controlled. The
  prompt marks it as data, and even a fooled model can at most add a *proposal* to the knowledge base, which
  does nothing until you approve it.
- **Data leaving your network.** With a hosted LLM, alert summaries and sample log lines are sent to that
  provider. For regulated data use a local model or `redact: true` (masks e-mails, passwords, tokens, card
  numbers; IP addresses are kept for analysis; not a full DLP).
- **Web UI.** Password + signed `HttpOnly`/`SameSite=Strict` cookie, login throttling, strict CSP (no inline
  scripts), model output rendered as markdown with HTML disabled. The container runs as non-root with a
  read-only filesystem and all capabilities dropped. Put it behind TLS; with an SSO proxy set
  `AUTH_DISABLED=true`.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Architecture

```
          ┌──────────────── wazuh-daily-triage (one container) ─────────────────┐
schedule  │ Collector ──► deterministic summary + health flags                   │
 / button │      │                                                               │
          │      ▼                                                               │
          │ Agent loop ◄──► LLM (Anthropic / OpenAI-compatible)                  │
          │   tools: search · aggregate · timeline · ip_profile · correlate ·    │
          │   vulns · agent · rule · logtest · validate_rule_xml · propose        │
          │      │                                                               │
          │      ▼                                                               │
          │ submit_report ──► daily-triage-runs                                  │
          │ Web UI / chat ◄──► daily-triage-knowledge / -chat                    │
          └───────────┬──────────────────────────────┬───────────────────────────┘
                      │ HTTPS 9200                   │ HTTPS 55000
               Wazuh Indexer                  Wazuh server API
```

Python 3.12, FastAPI, Jinja2, httpx. No provider SDKs, no front-end build step.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

`app/demo.py` contains a tiny OpenSearch query engine and synthetic data, so the collector and tools are tested
without a cluster. Adding a UI language = adding a dictionary to `app/i18n.py`.

## Roadmap

- Expose the tools as an **MCP server** (use them from Claude Desktop and other MCP clients)
- Notifications on critical flags (e-mail, Slack, Teams, webhook)
- Rule lifecycle: draft → approval → `analysisd -t` + logtest + apply, in a separate privileged component
- OIDC login, multiple users and an approval audit trail
- Weekly vulnerability/SCA digest, streaming chat answers

## Acknowledgements

- [Wazuh — Threat hunting with agentic AI](https://wazuh.com/blog/threat-hunting-with-agentic-ai/) (least-privilege roles, correlation window)
- [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server), [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh)

## License

Copyright © 2026 Rüstem Duru. Licensed under the **GNU Affero General Public License v3.0** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE). If you run a modified version for users over a network, you must
offer them its source code (set `SOURCE_URL` to your fork).

Wazuh is a trademark of Wazuh, Inc. This project is independent and not affiliated with Wazuh, Inc.
