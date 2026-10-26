# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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
