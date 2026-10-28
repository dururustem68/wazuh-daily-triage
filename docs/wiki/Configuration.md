# Configuration

Two layers, one rule: **secrets and switches in the environment, structure in YAML**.

| Layer | File | Contains |
|---|---|---|
| Environment | `.env` (Docker), Kubernetes Secret/ConfigMap, shell exports | passwords, API keys, UI/auth switches, notification channels |
| Structure | `config/environments.yaml` | which Wazuh environments exist, schedules, thresholds, per-environment options |

`${VAR}` and `${VAR:-default}` placeholders in the YAML are expanded from the environment at startup; an empty
variable also falls back to the default (`${PROD_INDEXER_PASSWORD}` with no value becomes an empty string,
`${TZ:-UTC}` becomes `UTC`).

## Which configuration is used?

```
WDT_CONFIG set?          → that file
config/environments.yaml → YAML mode: every environment comes from the YAML
otherwise                → single-environment mode from WAZUH_* variables
```

- Docker sets `WDT_CONFIG=/app/config/environments.yaml` and mounts `./config` at `/app/config`.
- In **YAML mode** the `WAZUH_*` single-environment variables are ignored (they can still be used *inside* the
  YAML as `${WAZUH_...}` if you want).
- In **single-environment mode** the `WAZUH_*`, `SCHEDULE_*`, `HIGH_LEVEL`, `WINDOW_MIN_HOURS`, `REDACT`,
  `INVENTORY`, `LIVENESS_*` and `RULE_DEPLOY_*` variables build one environment (id `default`).
- `.env`, `config/environments.yaml`, `config/certs/`, `config/context/*` and `config/seed/*` are git-ignored.

## Environment variables

### Web UI, authentication, process

| Variable | Default | Meaning |
|---|---|---|
| `ENVIRONMENT` | *(empty)* | `production` (or `prod`, `live`) enables the fatal startup checks; anything else is a lab. |
| `APP_PASSWORD` | *(empty)* | Admin password. Required in production unless `AUTH_DISABLED=true`. |
| `VIEWER_PASSWORD` | *(empty)* | Optional read-only password; must differ from `APP_PASSWORD`. See [Viewer mode](Viewer-Mode). |
| `APP_SECRET` | *(random)* | Session signing key (`openssl rand -hex 32`). Empty means every restart invalidates sessions. |
| `AUTH_DISABLED` | `false` | Trust an SSO proxy instead of the app login (`true`/`1`/`yes`). See [SSO](SSO-Proxy-Auth). |
| `USER_HEADER` | `X-authentik-username,X-Forwarded-User,Remote-User,X-Auth-Request-User` | Comma-separated header names; the first non-empty one becomes the audit actor. |
| `COOKIE_SECURE` | `false` | Mark the session cookie `Secure`; must be `true` in production. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` (Docker) | Uvicorn's trusted proxy addresses; never `*`. |
| `APP_LANGUAGE` | `en` | UI and report language: `en`, `tr`, `es`, `de`. |
| `TZ` | `UTC` | IANA timezone for the schedule and timestamps; validated at startup. |
| `SOURCE_URL` | project repository | Footer link (AGPL-3.0 §13 — point it at your fork if you modify the code). |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `WDT_SCHEDULER` | `true` | `false` disables the in-process scheduler (manual runs and the UI still work). |
| `WDT_DEMO` | `false` | Demo mode: synthetic data, `config/demo.yaml`, never in production. |
| `WDT_CONFIG` | `config/environments.yaml` | Path to the YAML configuration. |

### Authorization, audit, tokens

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_ENVS` | *(empty = all)* | Environment ids the admin role may see (comma separated). |
| `VIEWER_ENVS` | *(empty = all)* | Environment ids the viewer role may see. |
| `MCP_ENVS` | *(empty = all)* | Environment ids MCP clients may query. |
| `AUDIT_LOG` | `true` | Append-only JSONL audit trail; `false` is for tests only. |
| `AUDIT_LOG_FILE` | `logs/audit.jsonl` | Audit file path. |
| `METRICS_TOKEN` | *(empty)* | Bearer token for `/metrics`; when empty an admin session is required. |
| `MCP_TOKEN` | *(empty)* | Enables `POST /mcp`; without it the endpoint answers `404`. See [MCP](MCP). |

### Model (LLM)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `openai` (any OpenAI-compatible endpoint) or `mock`. |
| `LLM_MODEL` | *(empty)* | Model id from the provider. |
| `LLM_API_KEY` | *(empty)* | Not needed for a local model without auth. |
| `LLM_BASE_URL` | *(empty)* | OpenAI-compatible base URL: OpenAI, Gemini, DeepSeek, Azure, Ollama, vLLM, LM Studio… |
| `LLM_MAX_TOKENS` | `4096` | Output budget; too low truncates the report. |
| `LLM_TEMPERATURE` | `0.2` | `none`/`default`/`off` leaves it to the provider (reasoning models). |
| `LLM_TOKEN_PARAM` | `max_tokens` | `max_completion_tokens` for newer OpenAI models. |
| `LLM_REASONING_EFFORT` | *(empty)* | Provider-specific effort field. |
| `LLM_EXTRA_BODY` | *(empty)* | JSON object passed to the provider verbatim. |
| `LLM_MAX_RETRIES` | `4` | Retries on 429/5xx/overload with backoff. |
| `LLM_MAX_TOOL_STEPS` | `14` | Tool-call budget per run (cost ceiling). |

### Notifications

| Variable | Default | Meaning |
|---|---|---|
| `NOTIFY_ENABLED` | `true` | Master switch. |
| `NOTIFY_UI_URL` | *(empty)* | Link inside messages, e.g. `https://triage.example.internal`. |
| `NOTIFY_REPEAT_HOURS` | `24` | Do not repeat the same critical item within this window. |
| `NOTIFY_ON_RUN_SUMMARY` | `false` | Send a short summary after every run (default: critical only). |
| `NOTIFY_ON_RUN_ERROR` | `false` | Send a message when a run fails. |
| `NOTIFY_ON_RULE_DEPLOY` | `true` | Notify about deploy/rollback. |
| `NOTIFY_ON_LIVENESS` | `true` | Notify about liveness problems and recoveries. |
| `LIVENESS_ENABLED` | `true` | Quick check without AI. |
| `LIVENESS_INTERVAL_MINUTES` | `10` | 2–120 minutes. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO`, `SMTP_VERIFY_TLS` | `587`, `starttls`, `true` | E-mail channel (`starttls`, `ssl`, `none`). |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | *(empty)* | Telegram. |
| `TEAMS_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL` | *(empty)* | Webhooks. |
| `WEBHOOK_URL`, `WEBHOOK_TOKEN` | *(empty)* | Generic JSON webhook; the token becomes `Authorization: Bearer`. |
| `NTFY_TOPIC`, `NTFY_TOKEN` | *(empty)* | ntfy push. |

A channel is on when its fields are set. See [docs/notifications.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/notifications.md).

### Single environment (`WAZUH_*`)

| Variable | Default | Meaning |
|---|---|---|
| `WAZUH_ENV_ID` | `default` | Lowercase id used in URLs (`a-z0-9`, `-`, `_`). |
| `WAZUH_ENV_NAME` | `Wazuh` | Display name. |
| `WAZUH_INDEXER_URL` | *(required)* | `https://host:9200`. |
| `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | *(empty)* | Read-only indexer account. |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | *(empty)* | Optional Wazuh API. |
| `WAZUH_VERIFY_TLS` | `true` | Prefer `WAZUH_CA_FILE` over disabling verification. |
| `WAZUH_CA_FILE` | *(empty)* | Private CA path inside the container (`/app/config/certs/root-ca.pem`). |
| `WAZUH_ALERTS_INDEX` | `wazuh-alerts-4.x-*` | Alert index pattern. |
| `SCHEDULE_ENABLED` | `true` | Scheduled runs. |
| `SCHEDULE_TIME` | `07:30` | One time or a comma-separated list (`07:30,19:30`). |
| `SCHEDULE_DAYS` | `mon,tue,wed,thu,fri` | Days of the week. |
| `HIGH_LEVEL` | `7` | Level considered “high”. |
| `WINDOW_MIN_HOURS` | `24` | Fallback window when no previous report exists. |
| `REDACT` | `false` | Same as `PRIVACY_MODE=mask` (kept for compatibility). |
| `PRIVACY_MODE` | `off` | `mask`: pseudonymise personal data before it reaches the model — see [Privacy](Privacy). |
| `PRIVACY_IPS` | `keep` | `public` / `all`: pseudonymise IP addresses too. |
| `PRIVACY_DETECT` | `true` | Flag personal data stored in clear text in the alerts. |
| `INVENTORY` | *(empty)* | Expected agent names; missing/unexpected agents become flags. |
| `RULE_DEPLOY_ENABLED` | `false` | Opt-in rule deployment (needs a separate API user). |
| `WAZUH_DEPLOY_USER`, `WAZUH_DEPLOY_PASSWORD` | *(empty)* | That separate user. |
| `RULE_DEPLOY_FILE` | `wdt_rules.xml` | One file in `etc/rules` on the manager. |
| `RULE_DEPLOY_ID_MIN`, `RULE_DEPLOY_ID_MAX` | `100000`, `119999` | Allowed rule id range. |
| `RULE_DEPLOY_REQUIRE_TESTS` | `false` | Fail closed unless logtest samples match. |
| `RULE_DEPLOY_ALLOW_INCONCLUSIVE` | `false` | Also deploy samples logtest cannot reproduce. |
| `MAIL_MAX_PER_HOUR`, `MAIL_ALERT_LEVEL` | *(unset)*, `7` | Mail channel analysis (your `ossec.conf` limits). |

`WDT_ALLOW_INSECURE_TLS=1` and `WDT_ALLOW_INSECURE_COOKIE=1` are deliberate lab overrides for the production
startup checks; see [docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md).

## The YAML file

`config/environments.example.yaml` is the complete, commented reference. The skeleton:

```yaml
app:
  timezone: ${TZ:-UTC}
  language: ${APP_LANGUAGE:-en}     # en | tr | es | de
  title: Wazuh Daily Triage

llm:                                 # omit the block to use LLM_* variables
  provider: anthropic
  model: ${LLM_MODEL}
  api_key: ${LLM_API_KEY}
  max_tokens: 8000
  max_tool_steps: 16

notify:                              # omit to use NOTIFY_*/SMTP_*/... variables
  ui_url: ${NOTIFY_UI_URL:-}
  on_run_summary: false

environments:
  - id: prod                         # lowercase; used in URLs
    name: Production Wazuh
    description: 1 master, 2 workers, 3 indexers
    indexer:
      url: https://wazuh-indexer.example.internal:9200
      username: ${PROD_INDEXER_USER}
      password: ${PROD_INDEXER_PASSWORD}
      ca_file: /app/config/certs/root-ca.pem
      # client_cert / client_key for mutual TLS
    api:                              # optional
      url: https://wazuh-manager.example.internal:55000
      username: ${PROD_API_USER}
      password: ${PROD_API_PASSWORD}
      ca_file: /app/config/certs/root-ca.pem
    alerts_index: wazuh-alerts-4.x-*
    vuln_index: wazuh-states-vulnerabilities-*
    storage_prefix: daily-triage      # results in daily-triage-runs / -knowledge
    run_retention_days: 0             # >0 prunes old runs; knowledge is never pruned
    schedule:
      enabled: true
      times: ["07:30", "19:30"]
      days: [mon, tue, wed, thu, fri]
    window_min_hours: 12
    window_max_hours: 96
    high_level: 7
    max_silence_minutes: 60
    liveness: {enabled: true, interval_minutes: 10}
    privacy: {mode: off, ips: keep, detect: true}   # GDPR / KVKK — see Privacy
    context_file: context/prod.md
    seed_file: seed/prod.yaml
    inventory: [web01, db01]          # or inventory_file
    watch_rules: []
    watch_groups: [authentication_failed, web_scan, sshd]
    rule_deploy:
      enabled: false
      username: ${PROD_DEPLOY_USER:-}
      password: ${PROD_DEPLOY_PASSWORD:-}
      file: wdt_rules.xml
      id_min: 100000
      id_max: 119999
```

Per-environment options that only exist in YAML (no `.env` equivalent in single-environment mode):
`run_retention_days`, `window_max_hours`, `context_file`, `seed_file`, `vuln_sla`, `promote`, `sources`,
`incident`, `anomaly`, `query`, `mail`, per-environment `llm` and `notify` overrides. See the example file for
each block.

### Query limits (AI and MCP)

```yaml
    query:
      max_range_hours: 336     # widest window one tool call may use (14 days)
      max_buckets: 200         # date_histogram buckets per query
      max_terms_size: 50       # terms aggregation bucket count
      max_size: 25             # documents returned
      min_interval: 1m         # smallest histogram interval
      max_concurrent: 8        # parallel queries per environment
      request_timeout: 30      # seconds; falls back to indexer.timeout
      extra_fields: [data.custom_field]   # adds to the built-in field allow-list
```

The model never sends raw queries: tools build them and `app/query_guard.py` validates the field names, the
window and the bucket counts first. The collector itself uses fixed, reviewed queries and is not limited by
these values, so a tight cap cannot break a scheduled run.

## Add an environment

1. Add a block under `environments:` with a unique lowercase `id` (max 41 characters, `a-z0-9`, `-`, `_`).
2. Put its credentials in `.env` (or the Kubernetes Secret) and reference them as `${VARS}`.
3. Optional: `config/context/<id>.md` for free-text environment context and `config/seed/<id>.yaml` for initial
   knowledge. Both are given to the model.
4. If roles must be limited, set `ADMIN_ENVS`, `VIEWER_ENVS` and/or `MCP_ENVS`.
5. Restart the process.

```sh
# after editing .env / environments.yaml
docker compose up -d
docker compose exec triage python -m app.check
```

Configuration is read at startup; editing `.env` while the container runs changes nothing. Changing
`APP_SECRET` invalidates all sessions. Changing a password does **not** invalidate sessions already issued —
rotate `APP_SECRET` for that.

## Validate before you restart

```sh
docker compose exec triage python -m app.check          # indexer, alerts, vulnerabilities, storage, API, extra sources, model (--no-llm skips it)
docker compose exec triage python -c "from app.config import load_settings; s=load_settings(); print([e.id for e in s.environments])"
# notifications are tested separately: environment page → "Test notification" (POST /api/e/<env>/notify-test)
```

`app/security.py` validates the security-relevant settings at startup. In production it refuses to start on
example passwords, a missing session key, insecure cookies, disabled TLS verification or incomplete rule
deployment credentials or a weak `rule_deploy` password; warnings cover `AUTH_DISABLED=true`, a shared
read-only/deploy account and `AUDIT_LOG=false`. Production mode is `ENVIRONMENT=production` (alias `WDT_ENV`).

Next: [Features](Features) · [Privacy](Privacy) · [SSO proxy authentication](SSO-Proxy-Auth) · [Viewer mode](Viewer-Mode) · [MCP server](MCP)

---

[English](Configuration) · [Türkçe](Configuration-TR)
