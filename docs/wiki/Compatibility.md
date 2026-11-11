# Compatibility matrix

**For:** anyone deciding whether the tool fits their environment. Three words are used with fixed meanings:

- **Tested**: exercised by the project, either in continuous integration or in the environment it is developed
  against.
- **Expected**: the code path exists and nothing known prevents it, but the project has not run it.
- **Not supported**: known not to work, or deliberately not offered.

The automated tests run against a built-in demo engine (a small OpenSearch query engine with synthetic data),
not against a live Wazuh cluster. "Tested" for a Wazuh version therefore means: used in development against
that version.

## Wazuh

| Component | Status | Notes |
|---|---|---|
| Wazuh manager 4.14 | **Tested** | the version the project is developed against |
| Other Wazuh 4.x from 4.6 | Expected | 4.6 is the practical floor: the RBAC actions of the optional deploy user and the logtest API |
| Wazuh 4.x before 4.6 | Expected for read-only use | deployment helpers may lack endpoints |
| Other major versions | no statement | not tried |
| Wazuh Indexer (OpenSearch 2.x) with the standard `wazuh-alerts-*` template | **Tested** | queries use `bool.filter`, `terms`, `date_histogram`, `query_string`; no plugin needed |
| Custom alert index names | Expected | `alerts_index` takes a pattern or a concrete index |
| `wazuh-states-vulnerabilities-*` | optional | absent index: the vulnerability tools return an empty result |
| All-in-one, distributed cluster, wazuh-docker, wazuh-kubernetes | Expected | for a cluster, point `api.url` at the master |

## What each feature needs

| Feature | Indexer | Wazuh API | Extra |
|---|---|---|---|
| Alert analysis, daily report, noise map, anomalies | required | – | – |
| Vulnerability summary and SLA | required, vulnerability index | – | – |
| Agent and daemon health, coverage | – | read-only user | – |
| Rule definitions, ID collision check, logtest | – | read-only user | – |
| The watch | required | for the "agents lost" trigger | a notification channel |
| Rule deployment | – | separate deploy user | manager restart permitted |
| Storage safety policy check | ISM read permission (optional) | – | – |
| Prometheus, Loki, Kubernetes tools | – | – | those sources; cluster read role |
| Incident tickets | – | – | Zammad or Jira |
| MCP | as for the tools used | as for the tools used | `MCP_TOKEN` |

Without the Wazuh API the alert analysis is unaffected; the report's agent, daemon and rule sections are empty.

## Runtime

| Item | Status |
|---|---|
| Python 3.11, 3.12, 3.13, 3.15 | **Tested** (CI matrix); the image is built on 3.15 |
| Python 3.14 | Expected (inside the supported range, not in the matrix) |
| Python 3.10 and older | Not supported |
| Linux container (the published image) | **Tested** |
| Windows and macOS | Expected for development; not a deployment target |
| Helm chart | linted, rendered and installed in CI |
| Kustomize base and components | Expected; examples must be adapted |
| More than one replica with the scheduler on | Not supported: every check would run twice |
| Current Chrome, Firefox, Edge, Safari | Expected; the UI uses no inline scripts |

## Models

| Interface | Setting | Requirement |
|---|---|---|
| Anthropic Messages API | `LLM_PROVIDER=anthropic` | tool use |
| OpenAI-compatible Chat Completions (OpenAI, Azure OpenAI, Gemini, DeepSeek, Ollama, vLLM, LM Studio, LiteLLM) | `LLM_PROVIDER=openai` + `LLM_BASE_URL` | function calling |
| No model | `LLM_PROVIDER=mock` | demo and tests only |

The test suite uses the mock provider. How well a particular model does on **your** alerts is not something the
project can test for you; measure it with `python -m app.eval`
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)). Model names and
parameter quirks: [docs/providers.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/providers.md).

## Integrations

| Integration | Notes |
|---|---|
| E-mail (SMTP, STARTTLS or SSL), Telegram, Microsoft Teams (Workflows webhook), Slack, Discord, ntfy, generic JSON webhook | any combination |
| Zammad, Jira | incident tickets, optional |
| Prometheus, Loki, Kubernetes API | read-only sources, optional |
| S3-compatible storage | backup target, optional |
| SSO: oauth2-proxy with Keycloak, Authentik forward auth | through a proxy that sets a user header |
| MCP clients | Streamable HTTP on `POST /mcp`, or stdio; protocol versions `2025-06-18`, `2025-03-26`, `2024-11-05` |
| UI languages | English, Turkish, Spanish, German |

## Known limits

- **Logtest cannot replay manager-internal events** (rootcheck, FIM, SCA, vulnerability). Drafts for those
  groups are deployed with logtest *not run* and must be confirmed on a real event.
- **`rules:update` cannot be limited to one file** in the Wazuh API. The deploy user is therefore trusted with
  custom rule files in general.
- **The window depends on the stored runs.** Deleting run documents makes the next run fall back to the default
  window.
- **One process schedules.** Run one replica.
- **Masking is pseudonymisation, not DLP.** Names in free text and non-e-mail usernames are not detected.
- **Custom masking patterns** are limited to a safe subset unless `google-re2` is installed.
- **"What would it do?"** does not evaluate CDB lists, time windows and frequency rules.
- **The "sudden increase" watch trigger** compares with the 24-hour average and does not know the time of day.
- **Two roles only.** Administrator and read-only viewer, from the password or from SSO groups; no finer roles.
- **The ATT&CK view depends on the rules' `<mitre>` blocks.** Alerts of rules without one are not in the matrix,
  and a tactic without alerts is a hint, not a measured coverage gap.
- **Watch events are not available over MCP.**
- **The audit trail** is rotated at 20 MB with three generations, and lives on the application's volume.

The repository copy of this matrix:
[docs/compatibility.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/compatibility.md).

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Compatibility) · [Türkçe](Compatibility-TR)
