# Roadmap

Where the project is going, roughly ordered by impact. This is a living document — ideas and PRs welcome
(see [CONTRIBUTING.md](CONTRIBUTING.md)). Status legend: ✅ shipped · 🚧 in progress · ⬜ planned.

## Reach & distribution

| Status | Item | Why |
|---|---|---|
| 🚧 | **Helm chart** + a one-line install | most Wazuh users deploy with `wazuh-kubernetes`/Helm; a chart is the single biggest adoption lever. |
| ✅ | Docker Compose + Kubernetes (kustomize) | single container, read-only FS, non-root, no PVC. |
| ⬜ | Signed container images (cosign) + SBOM + SLSA provenance | a requirement in enterprise evaluations. |
| ✅ | Multi-language UI (en, tr, es, de) | more languages = more users; the catalogue is tiny (`app/i18n.py`). |
| ⬜ | Interactive demo (one-click temporary deploy) | let people try it without a Wazuh of their own. |

## Integrations

| Status | Item | Why |
|---|---|---|
| ✅ | e-mail, Telegram, Microsoft Teams, Slack, Discord, generic webhook, ntfy | cover every team's channel. |
| ✅ | MCP server (`/mcp`) | Claude Desktop / any MCP client can investigate with live data. |
| ✅ | LLM providers: Anthropic, OpenAI, Azure OpenAI, Gemini, DeepSeek, Ollama/vLLM/LM Studio/LiteLLM | bring your own key, or run fully offline. |
| ⬜ | Ticketing: **Jira**, ServiceNow, GitLab/GitHub issues (Zammad ✅) | the incident-record draft already has a clean provider hook. |
| ⬜ | PagerDuty / Opsgenie | for on-call escalation of `real_incident` findings. |

## Product

| Status | Item | Why |
|---|---|---|
| ✅ | Deterministic collection → LLM triage → structured report → recommendation inbox → knowledge base. | the core loop. |
| ✅ | Rule drafts with validation, rollback and two-way logtest (opt-in deployment). | the differentiator. |
| ✅ | Live verification of deployed/promoted rules on real events. | "logtest passed" is not proof; real events are. |
| ✅ | Monthly audit report (ISMS evidence) + agent coverage + vulnerability SLA + mail saturation + anomalies. | regulatory story. |
| ⬜ | **PDF export** of the report and monthly audit (logo, signature block). | regulated customers want a printable artefact. |
| ⬜ | **Decoder drafts** next to rule drafts (validate + logtest + rollback). | onboarding new log sources. |
| ⬜ | **Read-only viewer role** (vs. approver/deployer) and per-environment ACLs. | team deployments need role separation. |
| ⬜ | Embedded SVG time-series charts in reports. | readability + "wow" factor without a JS build step. |
| ⬜ | False-positive feedback loop polish: auto-baseline suggestions after N days unchanged. | turns decisions into automation. |

## Trust & security

| Status | Item | Why |
|---|---|---|
| ✅ | Read-only by default; separate least-privilege deploy user; prompt-injection-aware agent; strict CSP. | see [SECURITY.md](SECURITY.md). |
| ✅ | defusedxml (no DTD/entities), bounded regexes, signed session cookie, login throttling. | |
| 🚧 | **CodeQL + dependency audit in CI**, SBOM, signed releases. | signals enterprise readiness. |
| ⬜ | Published eval results (`python -m app.eval`) per model in the README. | nobody else shows their numbers this openly. |

## Earlier releases

- v0.5.0 — mail saturation, coverage, vuln SLA, live verification, promotion package, monthly audit report.
- v0.6.0 — MCP server, Prometheus/Loki/Kubernetes tools, anomalies, incident drafts, evaluation.
- v0.6.1 — CodeQL fixes, defusedxml, bounded regexes, safe language cookie.
- v0.7.0 (next) — Slack/Discord/webhook/ntfy notifications, Spanish & German UI, CodeQL + dependency audit + SBOM.
