# Wazuh Daily Triage — Wiki

**English** · [Türkçe](Home-TR) · [Español](Home-ES) · [Français](Home-FR)

**An on-call companion for Wazuh.** It watches your alerts around the clock and tells you within minutes when
something urgent happens — without asking an AI. Once or twice a day an AI round reviews everything the watch
saw, explains it and suggests what to tune. You decide; nothing changes in Wazuh without your approval.

> **Personal data does not reach the AI.** E-mail addresses, phone numbers, national ID numbers (TCKN …), IBANs,
> card numbers, passwords, tokens and keys are replaced by pseudonyms such as `<email:3f9a…>` **before** anything
> is sent to the model — on by default since 0.10.1 (KVKK / GDPR). Secrets cannot be unmasked at all. IP
> addresses are kept for the analysis unless you set `ips: public` or `ips: all`. Your reports keep the real
> values, inside your installation. → [Privacy](Privacy)

> **Talk to your Wazuh from any MCP-capable agent.** The built-in MCP server gives every agent or assistant that
> speaks the Model Context Protocol — Claude Desktop, Claude Code, Cursor, VS Code and others — the same
> read-only investigation tools the AI uses — alert search, timelines, IP profiles, agents,
> rule info, logtest, reports, the knowledge base — with the same query limits, masking and a per-client rate
> limit. Ask "what happened on webserver last night?" and get answers from live data. → [MCP server](MCP)

![Watch board](images/dashboard.png)

**Current release:** 0.10 · **Licence:** AGPL-3.0-only · **Python:** 3.11–3.15 · **Wazuh:** 4.x

## Two loops

| | The watch | The AI round |
|---|---|---|
| When | every few minutes | once or twice a day, at the times you set |
| How | local rules — **no model is called** | your model, with read-only tools |
| You get | an immediate "rule-based alert" on Teams, Telegram, Slack, e-mail … | a report: findings with evidence, questions, a verdict on every watch event, rule drafts and tuning suggestions |

Urgent means: an alert at a critical level, a watched rule or group, a successful login after failed attempts,
Active Response, a sudden increase in volume, agents that stop reporting. Quiet hours hold everything but critical
events. The watch is switched on in **Settings → Watch**. → [Watch](Watch)

## What else it does

- Collects alerts, vulnerabilities, agent health and rule information from the Wazuh Indexer and API.
- Keeps a knowledge base (known noise, decisions, open items) that is given to the model on every round, and
  learns from your decisions.
- Never writes to Wazuh: the only writes go to its own `daily-triage-*` indices, plus the optional rule
  deployment you explicitly approve.
- Finds personal data stored in clear text in your logs and turns it into a recommendation.
- Encrypted backups of its own data (download or S3), and a warning when an index retention policy would delete it.
- A settings page, a read-only viewer role, SSO behind Keycloak/Authentik, a monthly audit report.

## Pick your path

| I want to… | Read |
|---|---|
| Ask my Wazuh questions from any MCP-capable agent | [MCP server](MCP) |
| Be sure no personal data goes to the AI provider (KVKK / GDPR) | [Privacy](Privacy) |
| Install with Docker Compose (or try the demo) | [Installation](Installation) |
| Learn every `.env` variable and the YAML file | [Configuration](Configuration) |
| Put Keycloak or Authentik in front (SSO proxy) | [SSO proxy authentication](SSO-Proxy-Auth) |
| Give a colleague read-only access | [Viewer mode](Viewer-Mode) |
| Get urgent alerts within minutes, without the AI | [Watch](Watch) |
| Back up the knowledge base, protect it from index retention rules | [Backup](Backup) |
| Rule deploy, promotion, incident records, extra sources, audit report, eval | [Features](Features) |
| Understand the security model | [docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md), [docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md) |
| Deploy to Kubernetes | [deploy/kubernetes/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/kubernetes/README.md), [Helm chart](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/helm/wazuh-daily-triage/README.md) |

## Five-minute demo (no Wazuh needed)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git
cd wazuh-daily-triage
cp .env.demo .env
docker compose up -d --build
```

Open <http://127.0.0.1:8080> and sign in with `demo-password-change-me` (the `APP_PASSWORD` in `.env.demo`). The demo uses synthetic data
(a Jenkins brute force, SSH attempts, a disconnected agent, a vulnerability burst) and the `mock` provider,
which writes a placeholder report without calling a model. It starts with a finished report, watch events with
AI verdicts and waiting suggestions, so every page has something to show.

## How it flows

```mermaid
flowchart LR
  W[Watch: every few minutes, no AI] -->|urgent| N[Notification]
  W -->|events| A
  S[AI round: once or twice a day] --> C[Collector]
  C --> F[Deterministic flags]
  F --> M[Masking: personal data to pseudonyms]
  M --> A[AI with read-only tools]
  A --> R[Report + findings + questions]
  R --> D[Your decisions]
  D --> K[Knowledge base]
  K -. next run .-> A
```

## Where the documentation lives

- This wiki: installation, configuration, watch, backup, features, privacy, SSO, viewer mode, MCP.
- Repository docs: [architecture](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/architecture.md), [permissions](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md),
  [rule deployment](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/rule-deployment.md), [notifications](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/notifications.md),
  [providers](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/providers.md), [sources](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/sources.md), [compatibility](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/compatibility.md),
  [security exceptions](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md).
- Four-language READMEs: [English](https://github.com/dururustem68/wazuh-daily-triage/blob/main/README.md), [Türkçe](https://github.com/dururustem68/wazuh-daily-triage/blob/main/README.tr.md),
  [Deutsch](https://github.com/dururustem68/wazuh-daily-triage/blob/main/README.de.md), [Español](https://github.com/dururustem68/wazuh-daily-triage/blob/main/README.es.md).

> The language links at the bottom of each page switch between the English and Turkish wiki versions; the home
> page is also in [Español](Home-ES) and [Français](Home-FR).

---

[English](Home) · [Türkçe](Home-TR) · [Español](Home-ES) · [Français](Home-FR)
