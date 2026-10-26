# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Notification channels **Slack**, **Discord**, **generic JSON webhook** and **ntfy** (push), alongside
  e-mail, Telegram and Teams — configurable per channel via `notify:` or `SLACK_WEBHOOK_URL`,
  `DISCORD_WEBHOOK_URL`, `WEBHOOK_URL`/`WEBHOOK_TOKEN`, `NTFY_TOPIC`/`NTFY_TOKEN`.
- **Spanish** and **German** UI (`es`, `de`), selectable from the language menu; the report language follows.
- **Helm chart** in `deploy/helm/wazuh-daily-triage` (hardened deployment, optional read-only RBAC, ingress and
  network policy), linted and rendered in CI.
- **Jira ticketing** next to Zammad for incident record drafts (`incident.jira`, basic auth + ADF description).
- **PDF export** of the monthly audit report (`/api/e/{env}/audit.pdf`, reportlab, pure Python) with a bundled
  Unicode font so Turkish/Spanish/German render correctly.

### Changed
- CI now runs **CodeQL** and a **dependency audit** (`pip-audit`); releases attach an **SPDX SBOM** artifact.
- Added `ROADMAP.md`.

## [0.6.1] — 2026-10-27

### Security
- Rule XML is parsed with `defusedxml` (no DTDs / entity expansion — CodeQL "XML internal entity expansion").
- Rule-draft extraction uses plain string operations instead of backtracking regular expressions
  (CodeQL "polynomial regular expression"); input is capped at 200 KB.
- The language cookie is written from the server's own list of codes, never from request data.
- Dependency added: `defusedxml`.

## [0.6.0] — 2026-10-26

### Added
- **MCP server** on `POST /mcp` (Streamable HTTP, JSON): every read-only tool for every environment, plus
  `list_environments`, `inbox`, `audit_report`; `propose_knowledge` creates proposals only. Off unless
  `MCP_TOKEN` is set (bearer token). `tools/mcp_bridge.py`: stdio bridge for Claude Desktop (stdlib only).
- **Prometheus, Loki and Kubernetes tools** (`sources:`): PromQL instant/range, LogQL, Kubernetes pods / nodes /
  events / workloads / jobs / services / ingresses / PVCs and pod logs — read-only, never secrets/configmaps,
  optional namespace allow-list; shown in the connection test. `components/rbac-readonly` for in-cluster access.
- **Anomalies** (no AI): rule × agent spikes against the previous 14 days (z-score) and rules new on an agent;
  in the report and given to the AI first.
- **Incident record drafts** from any finding (report and inbox): the AI fills an incident template with
  evidence it queries itself; editable, downloadable, saved on the finding; optional internal **Zammad** ticket
  (`incident.zammad`). Custom template via `incident.template_file`.
- **Evaluation**: `python -m app.eval cases.yaml [--model …] [--repeat N] [--out …]` replays past windows and
  scores recall, noise reported as incidents, steps, tokens and time; nothing is stored.

## [0.5.0] — 2026-10-26

### Added
- **Live verification** of rule drafts: after every run (and with **Check live**) a deployed, approved or
  promoted draft is checked against real events since it was applied — "confirmed live N×" or "not seen for
  N days". The state is shown on the card and given to the AI.
- **Make permanent** (promotion package): rule block with provenance, a script for `host` or `kubernetes`
  (backup → append → `wazuh-analysisd -t` on the running manager → `kubectl apply -k` / restart → loaded?),
  and a draft § for an alert catalogue; refuses while the draft is still in `rule_deploy.file`. **Mark as
  promoted** records who/when/where. Configure with `promote:`.
- **Mail channel saturation** (`mail: {alert_level, max_per_hour}`): saturated hours, the flooding rule, and the
  other rules that may never have been mailed; `mail_saturated` flag.
- **Agent coverage**: agents by status, version (drift from the manager) and node; `inventory` /
  `inventory_file` → expected-but-missing and unexpected agents.
- **Vulnerability SLA** (`vuln_sla`, default Critical 15 / High 30 / Medium 90 days) from
  `vulnerability.detected_at`: overdue counts, agents, packages, oldest.
- **Monthly audit report** (`/e/{env}/audit`, Markdown export): alert volume per day, top high-level rules, runs,
  findings and decisions, rule changes, decisions/baselines changed, SIEM outages (liveness history), coverage,
  vulnerability SLA, open items. Printable (print CSS).
- Liveness keeps an outage history (problem start/end) for the audit report.
- **Copy details** on every knowledge entry: the entry, deploy result / errors and rule XML as plain text.
- **Edit** on a rule draft also edits its rule XML (e.g. move the ID into the allowed range).

### Fixed
- Rule deployment no longer rolls back drafts whose logtest sample cannot be replayed: children of
  manager-internal events (rootcheck, FIM/syscheck, SCA, vulnerability detection, agent status) skip logtest
  ("confirm on the next real event"), and a `match` sample that no rule matches at all is reported as
  inconclusive (`?`) instead of failed. A sample caught by another rule still fails and rolls back.
- Rule-draft tests accept the original `location`; the agent is told not to add logtest samples for internal events.
- **Edit** on a knowledge entry failed with "invalid status" (title/body changes were never saved).
- Draft analysis checks existing rules even when the ID is outside the allowed range, so an ID collision is
  reported together with the range error.

## [0.4.4] — 2026-10-26

### Added
- **"Discuss in chat"** on every knowledge base entry: opens a chat with the entry, its rule XML and — when the last
  deployment failed — the failed steps, so the draft can be corrected (`POST /api/e/{env}/k/{id}/chat`).

### Fixed
- Rule deployment: when Wazuh refuses the upload, nothing has been written — the run now stops with
  "nothing was changed" instead of attempting a rollback that fails the same way and reports
  "rollback FAILED — check the manager now". A permission error names the missing RBAC grant.

### Docs
- `rules:delete` on `rule:file:<file>` is needed for every deploy (overwrite), not only for the first rollback.

## [0.4.3] — 2026-10-26

### Added
- **Liveness check** every `liveness.interval_minutes` (default 10, no AI): indexer unreachable or red, API
  unreachable, required daemon down, SIEM silent, indexer disk ≥ 90 %, cluster not running. Notifies when a
  problem starts, reminds every `repeat_hours` and says when it recovered; status pill and problems on the watch
  board; `POST /api/e/{env}/liveness` runs it on demand. The daily run no longer repeats these health flags.

## [0.4.2] — 2026-10-26

### Changed
- **Watch board** is now a work list per environment: recommendations waiting for a decision (with detail and
  server checks), questions waiting for an answer (answer inline), rule changes (proposed / deployed / failed),
  requests and open items, other knowledge proposals — collected across recent runs, not per report.

### Added
- **Kubernetes components** (`deploy/kubernetes/components/`): `networkpolicy`, `ingress-nginx` (TLS via
  cert-manager, IP allow-list and oauth2-proxy options) and `ingress-traefik-authentik` (Traefik IngressRoute +
  Authentik forward auth). The example overlay now covers notifications, two runs a day and rule deployment;
  CI builds the overlay with every component. `base/networkpolicy.yaml` moved to the component.

## [0.4.1] — 2026-10-26

### Fixed
- **"The model did not submit a report" / empty findings:** a report cut off by the output limit (invalid JSON) or
  missing its summary used to be accepted as an empty report. `submit_report` now rejects it with instructions,
  the model resubmits a compact version; after the tool budget up to two extra calls force `submit_report`
  (`tool_choice`, skipped automatically where unsupported). If there is still no valid report, the run keeps
  the deterministic findings and says why.
- A failed login of the rule-deployment user is shown as a failed deployment ("nothing was changed").
- Rule deployment refuses drafts whose parent rule sits in a custom file that loads later (alphabetical
  `etc/rules` order) and suggests a file name.

### Added
- **Watch board:** per environment, the recommendations waiting for a decision (across recent runs, urgent
  first) and pending knowledge proposals — each links straight to the item. Critical health flags on top.
- Run summary notifications list the most important waiting items, not only this run's counts.
- Knowledge base: the environment context file is shown under "Context".

## [0.4.0] — 2026-10-26

### Changed
- **New interface:** sidebar navigation per environment, page headers, KPI row and section links on reports,
  severity-coloured findings (the colour bar was never shown before), detailed data tables collapsed by default,
  two-column recommendation inbox with progress and large decision buttons, cleaner knowledge base and chat.

### Added
- **Run summary notification** (`on_run_summary` / `NOTIFY_ON_RUN_SUMMARY`, off by default): one short message
  after every run — health, alert counts, findings by label, recommendations waiting. Critical items are still
  sent on their own and the summary is appended to them.
- **Rule deployment notification** (`on_rule_deploy`, on by default): deployed / failed (rolled back) / removed,
  with rule ids and who did it.
- **Knowledge base import / export** in the seed YAML format — "Import / export" on the knowledge page (paste or
  pick a file, preview first) and `python -m app.kb import|export` (stdin works, e.g. through `kubectl exec -i`).
  Re-importing is idempotent: entries match by `key` (or kind + title); `--update` refreshes changed ones.

### Fixed
- docs/rule-deployment.md: `rules:update` must be granted on `*:*:*` (Wazuh rejects a per-file resource with
  "Permission denied: Resource type: *:*").

## [0.3.0] — 2026-10-26

### Added
- **Rule drafts you can ship.** Every rule draft shows copy-paste commands for the manager (backup, append,
  `wazuh-analysisd -t` with automatic restore, restart, verify, roll back).
- **Approve and deploy** (opt-in per environment, `rule_deploy`): writes the draft to one dedicated rules file
  through the Wazuh API with a separate least-privilege user, validates the configuration, restarts the manager
  or cluster, verifies the rule IDs are loaded, runs the draft's two-way logtest events and rolls back on any
  failure. Drafts that silence or lower alerts (level 0, `overwrite`, `no_log`…, lower than the parent) need the
  rule IDs typed as a second confirmation. "Remove from Wazuh" undoes a deployed draft. Who/when/steps are kept
  on the knowledge entry (SSO user header when behind a proxy).
- `propose_knowledge` takes `xml` and `tests` for rule drafts; the demo proposes and deploys one.

### Changed
- The AI sees which drafts are deployed (to measure them), removed, or rejected (not to propose them again).

## [0.2.0] — 2026-10-26

### Added
- **Recommendation inbox:** unreviewed findings of recent runs, one at a time, de-duplicated across runs;
  one decision (acknowledged / false positive / known noise / closed) applies to every occurrence.
- **Manual checks:** findings can carry exact read-only commands to run on hosts the tool cannot reach.
- **"Investigate in chat":** opens a chat pre-filled with the finding and its commands; paste the output and the
  assistant interprets it and gives the next step.
- **Several runs per day:** `schedule.times: ["07:50", "19:50"]` (or `SCHEDULE_TIME=07:50,19:50`).
- **Notifications for critical situations** via e-mail (SMTP), Telegram and Microsoft Teams (Workflows
  webhook); critical health flags, real incidents, critical findings, optionally failed runs; the same item is
  not repeated within `repeat_hours`; "Test notifications" button.

### Changed
- The triage prompt no longer repeats findings the user closed, marked false positive or known noise.

### Fixed
- An empty environment variable (e.g. `SMTP_PORT=`) now falls back to its default instead of failing startup.

## [0.1.2] — 2026-10-26

### Fixed
- LLM calls are retried with backoff on overload / rate-limit / gateway errors (429, 5xx, 529), honouring
  `Retry-After` (`max_retries`, `LLM_MAX_RETRIES`, default 4).
- If the AI provider is still unavailable, the run is saved with the deterministic health flags and data
  instead of failing; open requests are kept for the next run.

## [0.1.1] — 2026-10-26

### Added
- Kubernetes manifests: hardened Kustomize base (single-replica Deployment, Service, optional NetworkPolicy)
  and an example overlay (`deploy/kubernetes`).

## [0.1.0] — 2026-10-25

### Added
- Scheduled and on-demand daily triage per Wazuh environment with deterministic health flags.
- AI diagnosis with read-only tools; Anthropic and OpenAI-compatible providers, per-environment override.
- Reports, knowledge base and chat stored in the environment's own Wazuh Indexer (`daily-triage-*`).
- Questions to the user, finding feedback, AI knowledge proposals with approval.
- Rule draft validation (XML, OS_Regex pitfalls, ID collisions) and logtest.
- Web UI in English and Turkish; connection test in the UI and `python -m app.check`.
- Single-environment configuration from environment variables; mutual TLS; redaction option.
- Demo mode with synthetic data.
- Provider guide for Claude, OpenAI, Gemini, DeepSeek, Azure and local models; `LLM_TEMPERATURE`,
  `LLM_TOKEN_PARAM`, `LLM_REASONING_EFFORT`, `LLM_EXTRA_BODY` variables.
