# Architecture

One Python process serves the web UI/API, the scheduler, the MCP endpoint and the triage pipeline. Nothing is
sent to Wazuh except reads; the only writes are to its own `daily-triage-*` indices, the audit file on disk
and — when explicitly enabled — one custom rules file on the manager.

```
                    ┌──────────────────────────── one process ────────────────────────────┐
 scheduler ─────────►  Runtime.enqueue_run()  ──►  _run_guarded()                        │
 web "Run check" ───►        │                        │                                  │
                            ▼                        ▼                                  │
                    window = since last done run   Collector (indexer + API, read-only)   │
                            │                        │                                  │
                            │                        ▼                                  │
                            │                 deterministic summary + health flags        │
                            │                        │                                  │
                            │                        ▼                                  │
                            └──────────────►  Agent loop ⇄ LLM provider                 │
                                                    │  tools (query_guard limits)      │
                                                    ▼                                  │
                                              submit_report ──► report, findings,       │
                                                                knowledge proposals,    │
                                                                notifications           │
                                                                                       │
 web UI / MCP  ◄──── daily-triage-runs / -knowledge (indexer storage)                   │
 rule deploy (opt-in) ◄──── rules.py ──► etc/rules/wdt_rules.xml on the master          │
                                                                                       │
 /metrics, /healthz, /readyz   ◄──── observability.py (in-memory counters)                │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | Responsibility |
|---|---|
| `app/main.py` | Application factory: lifespan, middleware/route wiring, `/healthz`, `/readyz`, `/metrics` |
| `app/web/auth.py` | Login/logout, language cookie, the authentication + authorization middleware, security headers |
| `app/web/pages.py` | Server-rendered pages (dashboard, environment, report, inbox, knowledge, audit) |
| `app/web/api.py` | JSON API used by `app/static/app.js` (runs, findings, knowledge, deploy, exports) |
| `app/web/common.py` | Session primitives, per-request helpers (`env`, `safe`, `visible`) and the template context |
| `app/web/ui.py` | Jinja environment, template filters and UI vocabularies |
| `app/services.py` | `EnvRuntime` (clients, store, repo, locks) and the optional source clients |
| `app/reporting.py` | Report normalisation (`normalize_report`, deterministic fallback, compaction) |
| `app/runtime.py` | `Runtime` composition: environment construction, LLM cache, compatibility re-exports |
| `app/runs.py` | Run lifecycle: start/guard, window, collection, agent call, save, stale-run recovery |
| `app/review.py` | Recommendation inbox plus run, rule-deploy and liveness notifications |
| `app/ruledeploy.py` | Rule draft analysis, deploy/rollback, live verification, promotion |
| `app/incident_ops.py` | Monthly audit report and incident records (draft + ticket) |
| `app/diagnostics.py` | Connection test behind the UI button and `python -m app.check` |
| `app/knowledgeio.py` | Seed import and knowledge-base import/export |
| `app/scheduler.py` | Scheduler loop, retention tick and shutdown |
| `app/collector.py` | Deterministic collection: volume, levels, rules, agents, vulns, watch list, health flags, empty hours |
| `app/agent/runner.py` | LLM loop: system prompt, tool calls, retries, token accounting, `submit_report` |
| `app/agent/tools.py` | The READ-ONLY tool set shared by the AI and MCP; every filter goes through `query_guard` |
| `app/agent/prompts.py` | System prompts, including the triage method and the injection warning |
| `app/query_guard.py` | Field allow-list, time-range cap, bucket/terms/size caps, histogram interval floor |
| `app/store.py` | Storage abstraction (`IndexStore` for OpenSearch, `MemoryStore` for tests/demo) and `Repo` |
| `app/rules.py` | Rule XML validation, logtest classification, write/validate/restart/verify/rollback |
| `app/promote.py` | Promote a rule draft into a local rules file managed by GitOps/ConfigMap |
| `app/notify.py` | E-mail, Telegram, Teams, Slack, Discord, ntfy, generic webhook |
| `app/sources.py` | Optional Prometheus, Loki and Kubernetes read-only sources |
| `app/incident.py` | Incident draft and ticket (Jira/ServiceNow) helpers |
| `app/audit.py` | Monthly ISMS report built from the index — *not* the operational audit trail |
| `app/authz.py` | Role → permission matrix and per-role environment allow-lists |
| `app/auditlog.py` | Append-only, hash-chained operational audit trail (`logs/audit.jsonl`) |
| `app/observability.py` | Request id context, log format, in-memory Prometheus exposition |
| `app/security.py` | Startup validation of the security-relevant configuration |
| `app/config.py` | Pydantic models for YAML/`.env` configuration |
| `app/mcp.py` | MCP server over Streamable HTTP (`POST /mcp`), bearer token, environment allow-list |
| `app/demo.py` | Deterministic fake indexer/API/LLM so the demo and tests need no Wazuh |

## Run lifecycle

`POST /api/e/{env}/run` (or the scheduler) creates a run document with `status: running` and starts one
asyncio task per environment; a second request while a run is active returns `409` (`err.busy`).

1. **Window** (`runtime._window`): start at the last **successful** run's `window.to` so consecutive runs cover
   the gap exactly once — a run six hours after the previous one analyses six hours. `window_min_hours` is the
   fallback when there is no previous report and the lower bound for a manual `hours` request; `window_max_hours`
   caps every window (a week-long gap after holidays is cut to the maximum). A failed run does not move the
   window; the next run starts from the last *successful* one.
2. **Collect** (`collector`): all indexer and API reads for that window, in parallel, with a request timeout;
   the collector uses fixed, reviewed queries, so it is not subject to the model-facing query caps.
3. **Analyse** (`agent.runner`): the model assesses every group above the high-level threshold, infrastructure
   flags first, and calls `submit_report`.
4. **Persist**: run document (findings, questions, metrics, agent trace) and knowledge proposals.
5. **Notify**: summary to the configured channels; critical flags are sent as such.
6. **Liveness** (`runtime`): a separate, LLM-free check every few minutes notifies when Wazuh breaks and when it
   recovers.

Failures are recorded on the run document (`status: error`, `error`, `stage`) and counted in `/metrics`; the
previous successful run is never overwritten, so a failed run does not shift the window.

### What fails softly, what fails hard

| Failure | Behaviour |
|---|---|
| Indexer unreachable during collection | Each section catches its own error; the report continues with an empty section, an `indexer_down`/`collector_errors` flag and the error text — a visible blind spot, never a silent "all clear" |
| Wazuh API unreachable | Agent, daemon, cluster and rule sections are empty (and flagged); alert analysis is unaffected |
| Optional source (Prometheus, Loki, Kubernetes) error | That tool returns an error string to the model; the run continues |
| Tool query above the guard limits | The model receives a hint and can retry with a narrower window; nothing reaches the cluster |
| LLM unavailable after retries | Run is saved as `done` with `ai_error`, a deterministic report built from the health flags (`flags_only_report`) and `agent.stopped = llm_error`; questions stay open for the next run |
| Model never submits a valid report | Same deterministic fallback (`run.ai_no_report`), with the reason in `ai_error` |
| Unhandled error in the pipeline | Run is saved as `error` with stage and exception, counted in metrics; the next run starts from the last *successful* window |
| Rule deployment failure | Rolled back and verified; `rollback_state` is `done`/`failed`/`not_needed`; a failed rollback logs `CRITICAL` |
| Store write failure mid-run | The run is lost (error logged, metrics increment); no partial document is treated as a report |

## Security layers

| Layer | Where | Effect |
|---|---|---|
| Startup validation | `security.check()` in the lifespan | With `ENVIRONMENT=production`, example passwords, a missing `APP_SECRET`, `COOKIE_SECURE=false` or disabled TLS verification stop the process |
| Authentication | `web/auth.auth_mw` | Signed `HttpOnly`/`SameSite=Strict` cookie; `AUTH_DISABLED` delegates to a proxy header; login throttling |
| Authorization | `authz` + `web/auth.required_perm`/`web/common.env` | Role → permission matrix and per-role environment allow-lists; checked server-side on every route |
| Audit trail | `auditlog` | Every state-changing request, denial, login and rule deployment appended with actor, role, env, result; SHA-256 hash chain detects tampering |
| Query guard | `query_guard` in `ToolBox` | Caps time range, buckets, terms and document count; allow-lists field names — a prompt-injected instruction cannot become an expensive query |
| Egress | tool set | No shell, no HTTP client, no active response; the model can only read and propose |
| Deploy gate | `rules.apply` | Fail closed: validation, restart, logtest and rollback are all verified before a rule stays deployed |
| Headers | `web/auth.finish` | CSP without inline scripts, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` |
| Observability | `/metrics` | Admin session or `METRICS_TOKEN`; request ids in logs and audit lines |

Details: [permissions.md](permissions.md), [rule-deployment.md](rule-deployment.md),
[security-exceptions.md](security-exceptions.md).

## Health and probes

| Endpoint | Meaning | Use for |
|---|---|---|
| `/healthz` | Process and event loop answer; no dependency is touched | `livenessProbe` (a Wazuh outage must not restart the pod) |
| `/readyz` | Lifespan finished, config loaded, runtime built, at least one environment; no network calls | `readinessProbe` |
| `/metrics` | Prometheus exposition (admin session or `METRICS_TOKEN`) | Scraping |

Readiness deliberately ignores Wazuh and the indexer: if it failed on an SIEM outage, Kubernetes would remove
the only UI that explains the outage. Dependency health is covered by the liveness check (notifications), the
connection test on the environment page and the degraded-storage banner that `web.common.safe()` renders when a
read fails.

## Storage

| Index | Contents |
|---|---|
| `daily-triage-runs` | One document per run: window, collection, findings, questions, metrics, agent trace |
| `daily-triage-knowledge` | Baseline noise, decisions, rule drafts, glossary entries |

The prefix is configurable (`storage_prefix`). `MemoryStore` provides the same interface for tests and the
demo, which is why the suite runs without a cluster.

**Retention.** `run_retention_days` (default `0` = keep forever) deletes run documents older than the given
number of days, once a day, through `_delete_by_query` filtered by `env`. The knowledge base is never pruned:
decisions, baselines and lessons are durable evidence. Audit-trail rotation is documented in
[permissions.md](permissions.md#5-audit-trail).

## Extension points

- **New tool**: add a handler and a spec in `app/agent/tools.py` (register it in `_handlers`); add its fields to
  `query_guard.BASE_FIELDS` or `query_limits.extra_fields` if it needs new ones. MCP exposes it automatically.
- **New source**: implement a client in `app/sources.py`, add it to `EnvRuntime.sources`, then expose it through
  a tool.
- **New notification channel**: `app/notify.py` (`NotifyCfg` + a sender); see
  [notifications.md](notifications.md).
- **New language**: add a dictionary to `app/i18n.py` and the code to `LANGUAGES` in `app/config.py`.
