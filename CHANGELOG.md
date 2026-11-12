# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.11.1] — 2026-11-12

### Fixed
- **Rule deployment behind an SSO proxy returned HTTP 502** although the deployment went on: a deployment
  (manager restart, verification, logtest) takes about a minute, oauth2-proxy waits 30 s. Long operations now run
  as **background jobs** (`app/jobs.py`): rule deploy / remove, connection test, incident draft and *What would it
  do?* answer `202 {"job", "poll"}` and the page polls `GET /api/e/<env>/jobs/<id>`. The checks that can refuse a
  deployment still answer immediately (403 / 400 / 404 / 409). `?wait=true` keeps the synchronous answer for API
  clients. Double clicks reuse the running job.
- **Frequency and correlation rules always failed the logtest step** and were rolled back: one logtest event can
  only reach the parent rule. Samples of rules with `frequency`, `if_matched_sid` or `if_matched_group` are now
  replayed `frequency + 2` times (at least twice, at most 64) in one logtest session (token); the step shows the
  event the rule fired on. The manual commands say how many times to paste the sample.

### Added
- Live deployment progress: each step appears as it happens; elapsed time is shown.
- The deployment record is stored as *running* before anything is written; a restart in the middle marks it
  **interrupted** at start-up (critical log line) instead of leaving it stuck. A job that is cancelled at shutdown
  is audited as `interrupted`.
- Graceful shutdown waits for running jobs (`JOB_DRAIN_SECONDS`, default 400); `terminationGracePeriodSeconds: 420`
  in the base manifest and the chart (`terminationGracePeriodSeconds` value).
- The browser explains a gateway error page (502 / 503 / 504 without JSON) as a proxy time-out — the operation may
  still be running — instead of `HTTP 502`; job polling rides out short network or proxy interruptions.

### Changed
- `POST …/deploy`, `…/undeploy`, `…/check`, `…/f/<id>/incident` and `GET …/whatif` return `202` with a job.
  Chart 0.3.1.

## [0.11.0] — 2026-11-11

### Added
- **Dashboard.** The start page is a dashboard: per-environment tiles, key figures (alerts, high level, critical,
  agents, waiting recommendations, open questions) with trend lines and the change against the previous period,
  alert volume over time, severity bands, top rules / agents / source addresses and the ATT&CK tactic strip, for
  24 h, 7 or 30 days. Deterministic, cached for a minute. The work queue (inbox, questions, rule changes, open
  items) stays below.
- **MITRE ATT&CK page** (`/e/<env>/attack`): tactic × technique matrix with heat colours, change against the
  previous period, techniques seen for the first time in 30 days, techniques that disappeared, tactics without
  alerts. Cells link to attack.mitre.org.
- **ATT&CK on findings.** Findings get `mitre` (technique ids) from the rules' `<mitre>` blocks and from the model
  (new optional `mitre` field in `submit_report`, validated), plus `mitre_tactics`; shown as tags in the report and
  the inbox.
- **SSO roles from groups.** Behind an SSO proxy the group header (`X-authentik-groups`, `X-Forwarded-Groups`,
  `X-Auth-Request-Groups`, `Remote-Groups`; `GROUP_HEADER`) decides the role: `SSO_ADMIN_GROUPS` → administrator,
  `SSO_VIEWER_GROUPS` → read-only viewer, anyone else → `SSO_DEFAULT_ROLE` (`viewer`; `deny` when viewer groups are
  listed). The permission matrix and `ADMIN_ENVS` / `VIEWER_ENVS` now apply in SSO mode too; the audit trail
  records the role.
- Server-rendered SVG charts (`app/charts.py`): no JavaScript library, no change to the Content-Security-Policy.
- **MCP over stdio**: `python -m app.mcp_stdio` serves the same tools as `POST /mcp` in one process, one JSON-RPC
  message per line. With `WDT_DEMO=true` it needs nothing else (synthetic data, sample AI round), so any stdio MCP
  client can try the tools with `docker run -i --rm -e WDT_DEMO=true <image> python -m app.mcp_stdio`, and MCP
  directories can start the server to list its tools. Logs go to stderr.
- `glama.json` (maintainer entry for the Glama MCP directory).

### Changed
- **New interface:** sidebar navigation with the environments and the user's name and role, a cleaner layout,
  light and dark themes. The report's hourly bars are an area chart.
- **SSO users are no longer administrators by default.** Set `SSO_ADMIN_GROUPS` before upgrading, or
  `SSO_DEFAULT_ROLE=admin` for the previous behaviour. Startup warns when no administrator group is set.
- The demo alerts carry ATT&CK mappings.
- Helm chart 0.3.0.

### Documentation
- **Wiki restructured around tasks.** Twelve new pages (English and Turkish): *Getting started* (from the demo to
  a checked first report), *User guide*, *Rule lifecycle*, *Kubernetes*, *Security model* (with a data-flow
  table), *Security checklist*, *Troubleshooting*, *Upgrade*, *Compatibility* (tested / expected / not
  supported), *Development*, *Scenarios* and *FAQ and glossary*. The home page (English, Turkish, Spanish, French)
  says what the tool is and is not and has a documentation map; the sidebar is grouped by task.
- **README shortened** in all four languages: what it is, quick start, security in short, and links to the wiki
  instead of repeating it.
- Wiki for 0.11: the dashboard and the ATT&CK page in the *User guide* and *Features*, SSO roles in *SSO proxy
  authentication*, *Viewer mode* and *Configuration*, upgrade notes, new screenshots.
- Corrections: `docs/compatibility.md` and `docs/architecture.md` listed ServiceNow (the ticket integrations are
  Zammad and Jira) and Python 3.11–3.13 (CI covers 3.11–3.15); the Kustomize example pinned `v0.7.0`; the
  *Features* page said startup refuses a shared deploy account (it warns; it refuses an empty or example
  password).

## [0.10.1] — 2026-11-10

### Changed
- **Personal-data masking is on by default** (`privacy.mode: mask`, also for `PRIVACY_MODE` in single-environment
  mode). Until now an installation without a `privacy:` block sent personal data to the AI provider unmasked.
  Reports keep the real values; set `privacy.mode: off` explicitly to switch masking off. When `PRIVACY_SALT` and
  `APP_SECRET` are both empty, startup warns that pseudonyms change on every restart.


### Fixed
- **Demo with Docker Compose did not start** when `WDT_DEMO=true` was added to a copy of `.env.example`
  above its `WDT_DEMO=false` line (the last definition wins) — the container exited with
  "no config file and WAZUH_INDEXER_URL is not set". The demo now has its own `.env.demo`
  (`cp .env.demo .env`), `.env.example` no longer sets `WDT_DEMO`, and the startup error says what to do.
- **Audit trail with Docker Compose**: `./logs` was created by Docker as root, so the app user could not
  write the audit file. `docker-compose.yml` now uses the named volume `audit` (move an existing
  `./logs/audit.jsonl` into it if you want to keep it).

### Added
- **Demo sample data**: the demo starts with a finished report, the watch switched on with judged events
  (successful login after failed attempts, Active Response, lost agent, watched groups), tuning suggestions and
  a masking profile with a custom detector. `WDT_DEMO_SEED=false` starts it empty.

### Documentation
- Wiki home page: the project as an on-call companion (the watch first, the AI round second), with what
  leaves the installation (pseudonyms only) and the MCP server up front; the home page also in Spanish and French.
- Wiki updated for 0.10: new pages *Watch* and *Backup* (English and Turkish), and the watch, settings page,
  masking profile, per-environment pseudonyms, MCP rate limit and proxy checks on the existing pages.

## [0.10.0] — 2026-11-10

### Added
- **The watch** — rule-based alerts between AI rounds, without calling the model. Every few minutes local
  rules look for: alerts at a critical level, watched rules and groups, Active Response, a successful login
  after failed attempts from the same source, a sudden increase in volume and agents that stopped reporting.
  Events are sorted out (mute list, known noise from the knowledge base, repeat window), announced at once
  as "rule-based alert — not reviewed by AI" and kept in `<prefix>-events`. Off by default
  ([wiki: Watch](https://github.com/dururustem68/wazuh-daily-triage/wiki/Watch)).
- **AI round**: the scheduled run receives all watch events in one call and returns a verdict per event
  (`event_verdicts`) plus tuning suggestions. A suggestion changes nothing until an administrator accepts it.
  The round times (one or two a day) can be set in the UI.
- **Settings page** (`/e/<env>/settings`, admin only): watch triggers and thresholds, notification channels
  (chosen among the configured ones — no address or key is entered in the UI), quiet hours, AI-round times,
  masking profile, backup. Stored in `<prefix>-settings`; every change is audited.
- **Masking profile**: the standard profile is fixed; a site adds its own detectors (`x_…`), exceptions and
  can switch off non-secret detectors (confirmation + audit). Preview, YAML import/export, and each run
  records the profile version. Custom patterns are compiled with RE2 when `google-re2` is installed,
  otherwise only a conservative subset is accepted and timed against repetitive input.
- **Backup** ([wiki: Backup](https://github.com/dururustem68/wazuh-daily-triage/wiki/Backup)): encrypted export (scrypt + AES-256-GCM) as a download and
  optionally to S3; import with a preview and "add what is missing" / "overwrite"; automatic backups only
  with S3 and `BACKUP_PASSPHRASE`; reminder after 30 days. Imported rule drafts need approval again.
- **Storage safety**: a missing storage index is no longer recreated silently — the loss is recorded, raises
  a critical flag, a banner and a notification until acknowledged. The settings page reports a risky
  `storage_prefix` and any ISM policy that would delete the application's indices, with the date.

### Security
- **Pseudonyms are per environment**: a token created for one environment no longer resolves in another
  (MCP clients, shared installations).
- **Client address**: login throttling and audit use the real client behind `TRUSTED_PROXIES` instead of the
  proxy's address. **`/mcp` is rate limited** (`MCP_RATE_PER_MINUTE`, default 120) and locks an address out
  after repeated wrong tokens.
- **SSO mode verifies the proxy**: a request without a user header is refused (`SSO_REQUIRE_USER`, default
  on); `TRUSTED_PROXIES` restricts the peers and `PROXY_SECRET` requires a shared header. Production startup
  warns when neither is set. The Helm chart's NetworkPolicy is **on by default**.

### Upgrading
- New dependency: `cryptography` (already in the image).
- **SSO (`AUTH_DISABLED=true`)**: make sure your proxy forwards one of the `USER_HEADER` headers; otherwise
  every page answers 401 after the upgrade (`SSO_REQUIRE_USER=false` restores the old behaviour).
- **Helm**: `networkPolicy.enabled` is now `true`. Set `networkPolicy.ingressNamespace` to your ingress
  controller's namespace or the UI becomes unreachable.
- Two indices are created on first start: `<prefix>-events`, `<prefix>-settings`. The indexer user needs the
  same rights on them as on the existing `<prefix>-*` indices; reading ISM policies is optional.
- Nothing changes in behaviour until the watch is switched on in the settings page.

## [0.9.2] — 2026-11-10

Security hardening after a code review; no new features. **Read "Upgrading" before you roll it out.**

### Security
- **Pseudonym key**: personal-data pseudonyms were an HMAC with the built-in key `wdt-privacy` whenever
  `APP_SECRET` was unset (typical behind an SSO proxy), so a token could be checked against a guessed value.
  There is no built-in key any more: `PRIVACY_SALT`, else `APP_SECRET`, else a random key per process (with a
  startup warning). Tokens are 64 bit instead of 32 (`<email:3f9a1c2b7d4e9a10>`), which also removes
  collisions inside the token registry.
- **Cross-origin writes**: every state-changing request must come from the application's own origin
  (`Sec-Fetch-Site`, else `Origin`/`Referer` against `Host`/`X-Forwarded-Host`/`WDT_TRUSTED_ORIGINS`).
  Previously a page on a sibling sub-domain could trigger body-less POSTs (undeploy, promoted, liveness,
  check, notify-test) in SSO mode. Clients without browser headers (curl, scripts) and `/mcp` are unaffected.
- **Permissions fail closed**: a state-changing route without a permission mapping now needs `admin` instead
  of `read`; a test enumerates every route so a new one cannot be forgotten.
- **Error texts**: the model and MCP clients get an error category and a reference (`{"error", "kind",
  "ref"}`) instead of the exception text (endpoint URLs, index names, raw indexer/API responses). The full
  text and traceback are in the log under the same reference.
- **Lucene `query` argument**: fields named inside the free-text query pass the same allow-list as the
  structured filters (including `_exists_:`), field patterns and leading wildcards are refused, regular
  expressions and wildcards are bounded. `query.extra_fields` accepts sub-trees (`data.win.*`).
- **Indexer queries** carry a server-side `timeout` just below the client timeout; a partial (`timed_out`)
  answer is an error instead of a silent undercount.
- **SMTP**: in production `email.security: none` with a username is refused (password in clear text),
  without one it warns (`WDT_ALLOW_INSECURE_SMTP=1`); `verify_tls: false` is refused unless
  `WDT_ALLOW_INSECURE_TLS=1`. An unknown `security` value no longer silently means "no encryption".
- **Audit trail fails closed**: with `AUDIT_STRICT` (default on in production) state-changing requests and
  MCP `propose_knowledge` answer 503 while the audit file cannot be written. Outside strict mode every lost
  record is logged and counted (`wdt_audit_write_failures_total`) instead of one warning per process.
- **Credentials in logs**: `httpx` logged every request line at INFO, including the Telegram bot token and
  whole webhook URLs. Its loggers are now at WARNING, a filter on the log handler scrubs tokens in URLs and
  `Authorization` values, and notification errors (log, run record, "test notification" result) are scrubbed.

### Upgrading
- Set `PRIVACY_SALT` (or `APP_SECRET`) if masking is on and neither is set, otherwise pseudonyms change at
  every restart. Rotate the Telegram bot token / webhook URLs if your pod logs were shipped anywhere.
- Production with `email.verify_tls: false`, or `email.security: none` plus a username, **refuses to start**.
- Behind a proxy that rewrites `Host` without sending `X-Forwarded-Host`, old browsers without
  `Sec-Fetch-Site` need `WDT_TRUSTED_ORIGINS=https://your.public.host`.
- If the model used fields outside the allow-list in `query`, add them to `query.extra_fields`.

## [0.9.1] — 2026-11-06

### Fixed
- **`<srcip>`/`<dstip>` in rule drafts**: Wazuh accepts only an IP address or CIDR block there (optionally `!`),
  but drafts such as `<srcip type="pcre2">^192\.168\.68\.(52|53)$</srcip>` passed `validate_rule_xml` and only
  failed at `wazuh-analysisd -t`. The rule parser (approve/deploy, "What would it do?") now rejects them with a
  hint (`192.168.68.52/31`, or one element per address), `validate_rule_xml` warns, and the AI prompt explains it.
- **"What would it do?" with several `<srcip>`/`<dstip>`**: they are now combined with OR, as Wazuh does
  (previously AND, so such drafts looked like they matched nothing).
- **Inbox hid waiting rule drafts**: an `expected`/`measurement` finding that carries a rule draft now appears in
  the inbox and in the waiting-decision reminder; without a draft they stay out as before.
- **Inbox hid new findings after an unrelated decision**: a decision on one finding settled every later finding
  that shared a single rule id (e.g. 2501). Decisions now settle a finding only when the rule sets mostly
  coincide (Jaccard ≥ 0.5); grouping across runs stays as fuzzy as before.

### Added
- **`health_accept`** (`HEALTH_ACCEPT`): warning flags you already know about (e.g. `vuln_overdue`) are shown as
  "accepted" and no longer turn every run's health into "warn", so a real warning stands out again. Critical
  flags (SIEM silent, daemons down, red indexer, disk ≥ 90 %) are never downgraded.
- **`ignore_agents`** (`IGNORE_AGENTS`, fnmatch patterns): retired or personal machines left out of the
  "agents not active" flag; they stay in the collected data.

### Changed
- CI also tests on Python 3.15, the version of the Docker base image.

## [0.9.0] — 2026-11-02

### Added
- **"What would it do?" for rule drafts** — replays a child-rule draft (`if_sid`) against the last 14 days of real
  alerts before anything is deployed: estimated alerts per day it takes over, the new level, how many of them
  were at or above the high level (before → after), top agents / source IPs / log locations, matching examples
  and parent alerts it would *not* match. `<match>`/`<regex>` (OS_Match, OS_Regex, PCRE2), `<field>`, `<srcip>`,
  `<user>`, `<url>`, `<location>`, `<decoded_as>` … are evaluated on a random sample (exact when the parents had
  ≤ 2 000 alerts); CDB lists, time windows and frequency are listed as not evaluated. Button on every rule draft,
  `GET /api/e/{env}/k/{id}/whatif`, and the read-only tool **`simulate_rule`** — the AI is told to run it before
  proposing a draft and to put the numbers in the proposal (also available over MCP).
- **Noise map** (`/e/{env}/noise`, no AI): the busiest rules of the last 1/7/14/30 days with alerts per day,
  share of all alerts and of the high-level band, change against the previous period and the dominant agent /
  location; a 28-day daily chart of all vs high-level alerts; level-reduction candidates (high level and ≥ 5 %
  of the high band or ≥ 100 a day). Per rule: **Ask AI for a draft** (queues a request the next run answers with
  a measured child rule) or **Skeleton draft** (an editable child rule in the knowledge base, next free id).
- **Reminder for waiting decisions**: on weekdays after `notify.pending_time` (09:30) one message per environment
  lists the recommendations that have waited longer than `notify.pending_days` (7) — label, severity, age and how
  often they were seen. Teams cards get buttons that open the inbox and the three oldest items directly
  (`/e/{env}/inbox?key=…`); Slack gets the same links. Once a day, also across restarts and replicas.
  `NOTIFY_ON_PENDING`, `NOTIFY_PENDING_DAYS`, `NOTIFY_PENDING_TIME`. The inbox marks items older than 7 days.

### Security
- CodeQL `py/polynomial-redos` (3 alerts) in the knowledge TXT import: the `[kind] title`, `rules:` and `key:`
  lines are now parsed with plain string operations instead of regular expressions, so a crafted upload cannot
  make the parser backtrack. A regression test feeds 200 000-character hostile lines.

## [0.8.0] — 2026-10-28

### Added
- **Personal data protection (GDPR / KVKK)** — `privacy:` per environment, [docs/privacy.md](docs/privacy.md).
  - `mode: mask` pseudonymises personal data at the **LLM boundary**: system prompt, collected summary and tool
    results. E-mail, phone, Turkish/Belgian/French national IDs, IBAN, card numbers (validated by check digits)
    and, optionally, IP addresses (`ips: public|all`) become stable pseudonyms such as `<email:3f9a1c2b>`; secrets
    (passwords, tokens, JWTs, private keys, AWS keys) are removed irreversibly. Tool arguments and the model's
    answer are mapped back, so tools keep working and reports show real values to the reviewer. MCP output is
    masked the same way. `redact: true` still works and means `mode: mask`.
  - `detect: true` (default) scans a sample of every window's alerts (`detect_sample`, default 1000, spread over
    the busiest log locations) for personal data stored in clear text — including rules that copy it into
    `rule.description`. A `personal_data` flag and a report section name the source (rule × agent × location,
    masked example), and the model recommends masking at the source.
- `list_reports` / `get_report` (UI tools and MCP) include `status`, `error`/`ai_error`, model and steps, so a
  failed run can be diagnosed remotely.

- **Simple knowledge import**: download a template (TXT, Excel CSV or YAML) from the knowledge page, fill it in
  with Notepad or Excel and upload it. TXT is one `[kind] title` block per entry with an optional `rules:` line;
  kind names are accepted in the UI languages (`karar`, `gürültü`, `ders` …). `GET /api/kb/template?fmt=`.
- **About page** (`/about`): version, documentation links and, per environment, which features are on (schedule,
  model, rule deployment, privacy, extra sources, liveness, notifications, tickets, MCP), plus MCP setup for
  Claude Desktop. No secrets are shown.
- When rule deployment is off, the **Deploy** button is shown disabled with a link to the setup guide instead of
  being hidden.

### Changed
- **Navigation moved to a top toolbar**: dashboard and environments in the first row, the current environment's
  pages (inbox, reports, knowledge, audit) in the second; About, language and logout on the right. More room for
  wide tables; scrolls horizontally on phones.
- The recommendation inbox merges the same finding across runs even when the model rewords the title, changes the
  label between `real_incident`/`investigate`/`detection_gap` or adds a rule id (rule or agent overlap, or title
  similarity when there are no rule ids).
- With a YAML config, `APP_LANGUAGE` and `TZ` now apply when the file has no `app:` block (previously only in
  variable-only mode, so a deployment setting `APP_LANGUAGE=tr` still got English reports).

### Fixed
- A `seed_file` that is not a list of `{kind, title, body}` entries (e.g. a free-form YAML document) crashed the
  first run or was silently ignored; it is now skipped with a warning naming the file, and invalid entries are
  skipped individually.
- Redaction turned run ids into `env-<card?>abc123` (the 14-digit timestamp looked like a card number), which made
  `get_report` fail with an indexer 400. Card numbers now need a valid Luhn check **and** an issuer prefix, and
  digits glued to an identifier (`-`, `_`, `/`, `:`) are never masked.

### Fixed
- `.github/workflows/ci.yml` was invalid YAML — an unquoted colon in the `mypy` step name — so GitHub created the
  run under the file path with **no jobs**. The name is quoted now and `tests/test_ci.py` parses every workflow in
  `pytest`, before the push.
- The CodeQL workflow re-added in 0.7.0 collided with GitHub's default setup ("CodeQL analyses from advanced
  configurations cannot be processed when the default setup is enabled"). Removed again, so default setup keeps
  scanning python, actions and javascript-typescript.
- The container image refused to start with `WDT_DEMO=true` alone: the image sets `WDT_CONFIG` globally, so demo
  mode looked for `/app/config/environments.yaml` and failed with "no config file and WAZUH_INDEXER_URL is not
  set". `config_path()` now falls back to `config/demo.yaml` and logs the fallback once.
- `test_inbox_dedupe_and_act` could fail depending on the wall clock: demo alerts are generated once relative to
  "now" while the run window ends at the start of every run, so an hourly alert sitting exactly on the window
  start dropped out of the second run. The test now freezes the clock.

## [0.7.0] — 2026-10-27

### Added
- **Copy buttons** on every finding and question: one click copies title, classification, evidence, recommendation,
  agents, rules and the read-only commands as plain text (tickets, mail, terminal). The copied text now starts with
  the environment and report time, the button confirms through an `aria-live` region, and payloads are capped at
  12 000 characters so a large rule draft cannot bloat the page.
- **Run retention** (`run_retention_days`, default `0` = keep forever): old run documents are pruned once a day;
  the knowledge base (decisions, baselines, lessons) is never deleted.
- **README** in English, Turkish, German and Spanish, with a language switcher in each file.
- **`/readyz`** readiness endpoint next to `/healthz` (liveness). Readiness covers startup and configuration only —
  deliberately no Indexer call, so a Wazuh outage never removes the UI that explains it. Kubernetes and Helm probes
  use `/readyz` for readiness and `/healthz` for liveness.
- **Storage failures are visible**: a failed read on a page now logs the request id and renders a warning banner with
  the failing message instead of silently showing an empty list.
- **Coverage gate** at 80 % (`fail_under`) and a gradual, non-blocking `mypy` run in CI for the web layer and small
  modules.

### Changed
- **Web layer split** out of `main.py` into `app/web/` (`auth`, `pages`, `api`, `common`, `ui`); `EnvRuntime` lives in
  `app/services.py` and report normalisation in `app/reporting.py`. `main.py` now only builds the app, the lifespan and
  the liveness/readiness/metrics endpoints; existing imports keep working through re-exports.
- **Runtime split** into focused mixins: `runs`, `review`, `ruledeploy`, `incident_ops`, `diagnostics`,
  `knowledgeio` and `scheduler`; `runtime.py` keeps only the composition and the shared caches (~90 lines). Existing
  imports (`normalize_report`, `_compact`, `demo_enabled`, `build_sources`) are re-exported.
- **`ToolBox` mode** is typed as `Literal["triage", "tools", "mcp"]` and a failing tool call is logged with its
  traceback (the model still gets a short error and the run continues).

### Fixed
- **Timezone data is a declared dependency** (`tzdata`): `python:3.12-slim` has no system zoneinfo, so a clean
  install could fail at startup. The configured timezone is now validated when the config is loaded.
- **i18n parity is enforced** for all four catalogues at import time, not only English/Turkish.

### Removed
- **Chat feature** (page, API endpoints, store index and prompts). Findings and questions are now handled in the
  report, the recommendation inbox and the incident record instead.

## [0.6.4] — 2026-10-27

### Fixed
- The audit page now has a single **PDF** button (server-rendered); the second browser-print button produced a
  different layout and was removed.

## [0.6.3] — 2026-10-27

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
- **Read-only viewer role** — an optional `VIEWER_PASSWORD` signs in to view everything but change nothing; the
  session cookie now carries the role and mutating requests are rejected for viewers.

### Changed
- CI runs a **dependency audit** (`pip-audit`, non-blocking) and releases attach an **SPDX SBOM** artifact;
  CodeQL comes from GitHub's **default setup** (the custom workflow was removed — advanced configurations cannot
  upload SARIF while default setup is enabled).
- The Helm chart is published to a GitHub Pages Helm repository (`helm repo add wazuh-daily-triage …`) by a
  self-contained `helm package` + `helm repo index` workflow.
- Added `ROADMAP.md`.

### Fixed
- `pypa/gh-action-pip-audit` was pinned to a non-existent tag (`v1.1.1`), which failed every `test` matrix job.
- The chart-release workflow failed at the `chart-releaser` step; replaced with an explicit publish script.
- The monthly audit PDF was redesigned (title band, KPI cards, zebra tables, page footer).

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
