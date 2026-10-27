# Compatibility

Tested against the versions below. "Works" means the code path exists and is covered by the test suite, not
that every patch release of a third-party product was tried.

## Wazuh

| Component | Supported | Notes |
|---|---|---|
| Wazuh manager | **4.x**, developed and tested against **4.14** | 4.6+ is the practical floor (RBAC actions used by the optional deploy user, `logtest` API). Older 4.x works read-only but the deploy/ticket helpers may lack endpoints. |
| Wazuh indexer | OpenSearch **2.x** with the standard `wazuh-alerts-*` template | Queries use `bool.filter`, `terms`, `date_histogram` and `query_string`; no OpenSearch plugins are required. |
| Alerts index | `wazuh-alerts-*` (configurable) | `alerts_index` accepts a pattern or a concrete index. |
| Vulnerabilities | `wazuh-states-vulnerabilities-*` | Optional; the vulnerability tools answer an empty result when the index is absent. |
| Wazuh API | **optional** | Without it: no agent/daemon health, no rule definitions, no logtest, no deploy. Alert analysis is unaffected. |
| Deployment shape | all-in-one, distributed cluster, `wazuh-docker`, `wazuh-kubernetes` | For clusters point `api.url` at the master; rules are written there and synchronised. |

## Runtime

| Item | Supported |
|---|---|
| Python | **3.11 – 3.13** (CI matrix: 3.11, 3.12, 3.13) |
| Operating system | Linux containers (the image), Windows and macOS for development |
| Container | non-root user, read-only root filesystem, all capabilities dropped; one writable volume for state |
| Browser | current Chrome, Firefox, Edge, Safari (no inline scripts, so a strict CSP is enforced) |

Dependencies are pinned with lower bounds in `requirements.txt` and audited in CI (`pip-audit`); see
[security-exceptions.md](security-exceptions.md) for the exception process.

## AI providers

| Provider | Setting | Requirement |
|---|---|---|
| Anthropic Messages API | `LLM_PROVIDER=anthropic` | tool use support |
| OpenAI-compatible Chat Completions | `LLM_PROVIDER=openai` + `LLM_BASE_URL` | function calling support |
| Local / self-hosted (Ollama, vLLM, LM Studio…) | `LLM_PROVIDER=openai` | an OpenAI-compatible endpoint with function calling |
| No model | `LLM_PROVIDER=mock` | demo and tests only: deterministic canned reports |

Model names are not hard-coded; see [providers.md](providers.md) for the `.env`/YAML keys.

## Integrations

| Integration | Notes |
|---|---|
| E-mail (SMTP/STARTTLS/SSL) | any SMTP server; `SMTP_VERIFY_TLS` can be disabled deliberately |
| Telegram, Teams, Slack, Discord, ntfy, generic webhook | one or more channels at once |
| Jira / ServiceNow | incident tickets, optional |
| Prometheus, Loki, Kubernetes API | read-only sources, optional; configured per environment |
| MCP clients (Claude Desktop, …) | Streamable HTTP on `POST /mcp`, bearer token, optional `MCP_ENVS` allow-list |

## Known limits

- **Logtest cannot replay manager-internal events** (rootcheck, FIM, SCA, vulnerability). A rule draft for those
  groups is marked `not_run`, deployed, and must be confirmed on the next real event — see
  [rule-deployment.md](rule-deployment.md).
- **`rules:update` cannot be scoped to one file** in the Wazuh API; the deploy user is therefore trusted with
  custom rule files in general. Keep it a separate, secret-only account.
- **The report window depends on the stored runs.** Deleting run documents makes the next run fall back to the
  default window instead of the exact gap.
- **One process per installation** for scheduling: two replicas with the scheduler enabled would run twice.
  Run one replica, or set `WDT_SCHEDULER=false` on the extra ones.
- **Audit trail rotation**: the file is rotated at 20 MB, keeping three generations, unless a log shipper moves
  it. Retention and shipping are described in [permissions.md](permissions.md).
