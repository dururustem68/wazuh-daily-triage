# Wazuh Daily Triage

**AI-assisted daily review for [Wazuh](https://wazuh.com) SIEM.** Every morning it checks that your SIEM is
actually alive, separates real risk from known noise, writes a short diagnostic report back into your Wazuh
Indexer, asks you only what needs a human decision — and remembers your answers next time.

Bring your own AI: Anthropic, OpenAI, Azure OpenAI or any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio,
LiteLLM). One Docker container, read-only towards Wazuh by default. Critical alerts and run summaries go to
e-mail, Telegram, Microsoft Teams, Slack, Discord, ntfy or a generic webhook.

[Türkçe README](README.tr.md) · [AI providers](docs/providers.md) · [Notifications](docs/notifications.md) · [Permissions & network](docs/permissions.md) · [Rule deployment](docs/rule-deployment.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

![Report](docs/screenshot-report.png)

| Recommendation inbox | Knowledge base and rule drafts |
|---|---|
| ![Inbox](docs/screenshot-inbox.png) | ![Knowledge base](docs/screenshot-knowledge.png) |

## Why

If your mornings start with the same Wazuh routine — *is data flowing, are agents connected, what is at level
7+, which of it is the usual noise, which of it is real* — this tool does the legwork and calls you only where
a decision is needed. It encodes hard-won review habits: health before alerts, distributions instead of
averages, "same count on every agent = feed event", "zero does not mean the rule works", level-lowering instead
of silencing.

## Features

- **Scheduled runs** per environment (one or more times a day + weekdays). The window is "since the last successful run", so
  Monday morning covers the weekend.
- **Deterministic collection first** — independent of the AI: last alert time and empty hours (blind spots),
  indexer health and disk, manager daemons, inactive agents, `ossec.log` errors, level distribution, high-level
  groups (rule × agent × first/last seen × source IP × sample), comparison with the previous window, rule IDs
  **seen for the first time in 14 days**, watched rules, vulnerability summary.
- **AI diagnosis** — the model reads the summary plus your knowledge base, digs deeper with read-only tools
  (time distribution, IP profile, ±30 min correlation, logtest, rule definitions) and submits a structured
  report: *real incident, investigate, detection gap, false positive, baseline increase…* It drafts Wazuh
  rules and checks them for XML errors, OS_Regex pitfalls and ID collisions.
- **Rule drafts you can ship** — every draft comes with copy-paste commands for the manager (backup,
  `wazuh-analysisd -t`, restart, roll back). Optionally, **Approve and deploy** writes it to one dedicated rules
  file through the Wazuh API, validates, restarts, checks it loaded, runs a two-way logtest and rolls back on any
  failure; drafts that silence or lower alerts need a typed second confirmation
  ([docs/rule-deployment.md](docs/rule-deployment.md)). Off by default.
- **It asks you** — "Was this SSH login yours?" Your answer goes into the knowledge base and is context for the
  next run.
- **Knowledge base** — known noise, decisions ("don't suggest X"), open items, lessons, "look at this tomorrow"
  requests. AI proposals have **no effect until you approve them**. Bring your existing notes with YAML
  import/export (UI or `python -m app.kb`), repeatable without duplicates.
- **Recommendation inbox** — findings one at a time, de-duplicated across runs; one decision settles every
  occurrence. Findings that need a look on a server carry exact read-only commands, and **Investigate in chat**
  opens a conversation where you paste the output and get the next step.
- **Notifications by e-mail, Telegram, Microsoft Teams, Slack, Discord, ntfy or a generic webhook** — critical
  situations (SIEM silent, indexer red, real incidents) without repeating the same item every run, an optional
  short summary after every run, and rule deployments ([docs/notifications.md](docs/notifications.md)).
- **Live verification** — a deployed, approved or promoted rule is checked against real events after every run:
  "confirmed live 12× (last …)" or "not seen for 5 days". `logtest passed` is not proof; a real event is.
- **Make permanent** — for a tested draft, a promotion package for *your* configuration management: the rule
  block with provenance, a script (backup → append → `wazuh-analysisd -t` on the running manager → roll out with
  `kubectl apply -k` or a restart → check it loaded) and a draft § for your alert catalogue.
- **Mail channel saturation** — with `mail:` set, each run shows the hours a flood exceeded `email_maxperhour`
  and the other rules that fired in those hours and may never have been mailed.
- **Coverage and vulnerability SLA** — agents per status/version/node, expected-but-missing agents from an
  inventory list, and active vulnerabilities open longer than the SLA per severity.
- **Monthly audit report** — alert volume, runs, findings and your decisions, rule changes (who, when, what was
  lowered), SIEM outages from the liveness check, coverage and vulnerability SLA. Deterministic (no AI), printable
  as PDF or downloadable as Markdown — evidence for ISO 27001 / ISMS reviews.
- **Anomalies without AI** — every run compares rule × agent counts with the previous 14 days: spikes (z-score)
  and rules firing on an agent for the first time; the AI starts from there.
- **Beyond Wazuh (optional)** — read-only Prometheus, Loki and Kubernetes tools (pods, restarts, OOM kills, node
  pressure, events, pod logs; never secrets) so the cause of an alert can be checked, not guessed
  ([docs/sources.md](docs/sources.md)).
- **Incident record drafts** — one click on a finding: the AI gathers the evidence and fills your incident
  template (timeline, root cause, impact, evidence queries, actions); edit, download, or open it as a Zammad or
  Jira ticket.
- **MCP server** — the same read-only tools for Claude Desktop or any MCP client, so you can investigate with live
  data from your own assistant ([docs/mcp.md](docs/mcp.md)).
- **Evaluation** — `python -m app.eval` replays days you reviewed yourself and scores the AI (recall, noise
  reported as incidents, tokens): compare models and prompts with numbers ([docs/eval.md](docs/eval.md)).
- **Chat** — ask questions about an environment; answers use the same tools and show their tool calls.
- **Stored in Wazuh itself** — `daily-triage-runs`, `daily-triage-knowledge`, `daily-triage-chat` indices in
  each environment's own indexer. No extra database.
- **Multi-environment, multi-language** (English, Turkish, Spanish, German), per-environment AI override (e.g. a
  local model for regulated data), connection test in the UI and CLI.

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

### Kubernetes

A **[Helm chart](deploy/helm/wazuh-daily-triage)** and a kustomize base, example overlay and optional components in
**[deploy/kubernetes](deploy/kubernetes/README.md)** — single replica, non-root, read-only filesystem, no PVC
(state lives in the Wazuh Indexer). Components: `networkpolicy`, `ingress-nginx` (TLS, cert-manager, oauth2-proxy
option) and `ingress-traefik-authentik` (SSO).

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

## Notifications — e-mail, Telegram, Teams, Slack, Discord, ntfy, webhook

| When | Setting (default) |
|---|---|
| SIEM silent, indexer red, manager daemon down, indexer disk ≥ 90 % | `on_critical_flags: true` |
| Finding labelled *real incident* / severity *critical* | `on_real_incident: true`, `on_critical_findings: true` |
| The run itself failed | `on_run_error: false` |
| Short summary after **every** run (health, counts, recommendations waiting) | `on_run_summary: false` |
| A rule draft was deployed, rolled back or removed | `on_rule_deploy: true` |
| **Liveness check every 10 min** (no AI): indexer/API unreachable, daemon down, SIEM silent, disk ≥ 90 % — problem, reminder, recovered | `on_liveness: true`, `liveness.interval_minutes` |

The same critical item is not repeated within `repeat_hours` (24). A channel is active as soon as its fields are
set; **Test notifications** on the environment page checks all of them.

```sh
# .env — any combination of channels
NOTIFY_UI_URL=https://triage.example.internal      # link in messages
NOTIFY_ON_RUN_SUMMARY=true

TELEGRAM_BOT_TOKEN=123456789:AA...                 # @BotFather → /newbot
TELEGRAM_CHAT_ID=-1001234567890                    # see below

TEAMS_WEBHOOK_URL=https://...                      # channel → Workflows → "Post to a channel when a webhook request is received"

SLACK_WEBHOOK_URL=https://hooks.slack.com/...      # Your Apps → Incoming Webhooks
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...   # channel → Edit → Integrations → Webhooks

WEBHOOK_URL=https://soar.example.internal/hook     # generic JSON webhook (Zapier/Make/SOAR)
WEBHOOK_TOKEN=...                                  # optional → Authorization: Bearer

NTFY_TOPIC=wazuh-triage                            # https://ntfy.sh/wazuh-triage (or a full URL)
NTFY_TOKEN=...                                     # optional, for a protected topic

SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_SECURITY=starttls                             # starttls | ssl | none
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=wazuh-triage@example.org
SMTP_TO=secops@example.org,oncall@example.org
```

- **Telegram chat id:** add the bot to the group (or send it a message), send `/start@<your_bot>`, then open
  `https://api.telegram.org/bot<token>/getUpdates` and take `"chat":{"id":...}` — group ids are negative
  (`-100…`). Already sending Wazuh alerts to Telegram through the Dashboard's Notifications plugin? The same
  bot token and chat id work here.
- **Teams:** the old Office 365 "Incoming Webhook" connectors are retired; use the Workflows template above.
  Messages arrive as Adaptive Cards with a link to the report.
- **Slack:** create an app → *Incoming Webhooks* → add to a channel → copy the Webhook URL. Messages arrive as
  block-kit sections with a link to the report.
- **Discord:** channel → *Edit* → *Integrations* → *Webhooks* → *New Webhook*. Plain-text messages.
- **Generic webhook:** any endpoint that accepts a JSON body (`{"title", "lines", "link", "text"}`); set
  `WEBHOOK_TOKEN` for a `Bearer` header.
- **ntfy:** push to `https://ntfy.sh/<topic>` (or self-host); the title becomes the notification title.
- Multi-environment setups put the same keys in a `notify:` block, globally or per environment —
  see [docs/notifications.md](docs/notifications.md).

Messages contain environment names, finding titles, host names and IPs — pick channels accordingly.

## Rule drafts — commands or one-click deploy

Every rule draft in the knowledge base has three buttons:

- **Commands** — a copy-paste block for the manager: backup, append to `etc/rules/wdt_rules.xml`,
  `wazuh-analysisd -t` (restores the backup if it fails), restart, verify, roll back. Works everywhere.
- **Approve and deploy** — opt-in per environment (`rule_deploy`). Writes the draft through the Wazuh API with a
  separate least-privilege user, validates, restarts the manager or cluster, checks the rule IDs are loaded,
  runs the draft's two-way logtest and **rolls back automatically** on any failure. Drafts that silence or lower
  alerts need the rule IDs typed as a second confirmation.
- **Remove from Wazuh** — undoes a deployed draft the same way.
- **Check live / Make permanent** — see whether the rule fired on real events since it was applied, and get the
  package that moves it into your own rules file / repository (configure `promote:`).

Setup and the exact API permissions: [docs/rule-deployment.md](docs/rule-deployment.md).

## Knowledge base import / export

Bring the notes you already keep (known noise, decisions, lessons) as a YAML list — the same format as
[`config/seed/example.yaml`](config/seed/example.yaml):

```sh
python -m app.kb import noise.yaml -e prod --dry-run     # preview
python -m app.kb import noise.yaml -e prod --update      # add new, update changed (matched by key or kind+title)
kubectl exec -i deploy/wazuh-daily-triage -- python -m app.kb import - -e prod --update < noise.yaml
python -m app.kb export -e prod --kind baseline > baseline.yaml
```

Or use **Import / export** on the knowledge base page. Re-running never creates duplicates.

## Compatibility

- Wazuh **4.x** (developed against 4.14) — all-in-one, distributed, Docker and Kubernetes deployments.
- Wazuh Indexer / OpenSearch 2.x with the standard `wazuh-alerts-*` template. Index patterns are configurable.
- Wazuh server API is optional; without it agent/daemon health, rule info and logtest are disabled.
- Basic auth, private CA (`ca_file`) and mutual TLS (`client_cert`/`client_key`) are supported.

## Security model

- **Read-only towards Wazuh by default.** No active response, no config writes, no agent commands. The only
  index writes go to its own `daily-triage-*` indices. The opt-in rule deployment uses a separate API user that
  can only upload custom rules files and restart the manager; the application writes one dedicated file.
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
          │ submit_report ──► daily-triage-runs ──► notify (mail/Telegram/Teams/Slack/Discord/ntfy/webhook) │
          │ Web UI / chat ◄──► daily-triage-knowledge / -chat                    │
          │ Approve & deploy (opt-in, separate API user) ──► etc/rules/wdt_rules │
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

See [ROADMAP.md](ROADMAP.md) — the priority list includes a Helm chart, signed releases with SBOM, Jira and other
ticketing, a read-only viewer role, PDF export, decoder drafts and more languages.

## Acknowledgements

- [Wazuh — Threat hunting with agentic AI](https://wazuh.com/blog/threat-hunting-with-agentic-ai/) (least-privilege roles, correlation window)
- [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server), [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh)

## License

Copyright © 2026 Rüstem Duru. Licensed under the **GNU Affero General Public License v3.0** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE). If you run a modified version for users over a network, you must
offer them its source code (set `SOURCE_URL` to your fork).

Wazuh is a trademark of Wazuh, Inc. This project is independent and not affiliated with Wazuh, Inc.
