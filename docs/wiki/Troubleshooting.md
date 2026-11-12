# Troubleshooting

**For:** operators. Search this page for the message you see. Each entry gives the check, the likely cause and
the fix. The commands are for Docker Compose; on Kubernetes replace `docker compose exec triage` with
`kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage --` and `docker compose logs triage` with
`kubectl -n wazuh-daily-triage logs deploy/wazuh-daily-triage`.

## First three checks

```sh
docker compose ps                                  # running and healthy?
docker compose logs --tail 100 triage              # the startup lines name what is wrong
docker compose exec triage python -m app.check     # Indexer, API, sources, model
```

`python -m app.check <env>` tests one environment, `--no-llm` skips the model. **Test connections** on the
environment's **Reports** page runs the same test. Every log line and every audit record carries a request ID (the `X-Request-ID`
response header); searching the log for it gives the whole request.

## The container does not start

| Message or symptom | Cause | Fix |
|---|---|---|
| `refusing to start in production` | a production safety check failed; the message names the variable | set a real `APP_PASSWORD`, `APP_SECRET`, `COOKIE_SECURE=true`, or fix TLS verification |
| `no configuration: … does not exist and WAZUH_INDEXER_URL is not set` | neither a YAML file nor the single-environment variables | demo: `cp .env.demo .env`. Real: set `WAZUH_INDEXER_URL` or create `config/environments.yaml` |
| The demo exits although `WDT_DEMO=true` is in `.env` | the variable appears twice; the last line wins | use `.env.demo` unchanged |
| `ERR_EMPTY_RESPONSE` on 127.0.0.1:8080 | the container is restarting | read `docker compose logs triage` |
| A value contains `#` and following text | a comment on a value line in `.env` | put comments on their own line |
| `ZoneInfoNotFoundError` | `TZ` is not an IANA name | for example `TZ=Europe/Istanbul` |

## Sign-in and the web UI

| Message or symptom | Cause | Fix |
|---|---|---|
| Sign-in returns to the login page | `COOKIE_SECURE=true` over plain HTTP, or the proxy drops cookies | use HTTPS; `COOKIE_SECURE=false` only for a local test |
| *Too many attempts, wait 5 minutes* for everyone | all users share one address because forwarded headers are ignored | set `FORWARDED_ALLOW_IPS` to the address the container sees the proxy from |
| `401` "did not come through the authenticating proxy" | SSO mode without a user header | forward `X-Forwarded-User` or `X-authentik-username`; check `TRUSTED_PROXIES` and `PROXY_SECRET` |
| `403` "cross-origin request refused" on a button | the browser's `Origin` is not the host the application sees | `WDT_TRUSTED_ORIGINS=https://your.public.host` |
| `403` on an action, page says read-only | signed in with the viewer password, or (SSO) not in a group of `SSO_ADMIN_GROUPS` | sign in as administrator; check the group name the proxy forwards |
| `403` "no role in this application" | SSO: the user is in no listed group and `SSO_DEFAULT_ROLE` is `deny` | add the user to a group in `SSO_ADMIN_GROUPS` / `SSO_VIEWER_GROUPS` |
| SSO: everyone is read-only after upgrading to 0.11 | no `SSO_ADMIN_GROUPS`, or the proxy forwards no group header | set the groups; forward `X-authentik-groups` / `X-Auth-Request-Groups` ([SSO proxy authentication](SSO-Proxy-Auth)) |
| *You do not have access to this environment* | the role's environment list excludes it | `ADMIN_ENVS` / `VIEWER_ENVS` |
| `503` "audit trail is not writable" | production mode refuses changes without an audit trail | make the log directory writable (the `audit` volume) |
| `502` from the proxy, container healthy | the proxy points at the wrong host or port | port 8080; `docker compose ps` |
| `502`/`504` only on a long action (deploy, connection test, incident draft), before 0.11.1 | the proxy's upstream time-out (oauth2-proxy: 30 s); the action itself went on | upgrade to 0.11.1 (background jobs); check the audit trail for the outcome; see [SSO proxy authentication](SSO-Proxy-Auth#long-operations-and-proxy-time-outs-0111) |
| *The proxy in front of the application gave up waiting* | same, on 0.11.1 for a request that is not a job | raise the proxy time-out; reload to see the result |
| Banner "Some stored data could not be loaded" | a read from the Indexer failed | check the Indexer; the banner shows a request ID |

## Indexer: connection, TLS, authentication

Test outside the application first, with the same account and CA:

```sh
curl -sS --cacert config/certs/root-ca.pem -u 'daily-triage:PASSWORD' \
  "https://<indexer>:9200/wazuh-alerts-*/_count"
```

| Result | Cause | Fix |
|---|---|---|
| certificate verify failed | wrong or missing CA; or the certificate does not contain the host name you use | mount the CA under `config/certs/` and set `ca_file` to its path **inside the container** (`/app/config/certs/…`); use a name that is in the certificate |
| `401` | wrong password, or the user was removed | on wazuh-docker and wazuh-kubernetes, `securityadmin` can overwrite users created through the REST API; define the user in the YAML files |
| `403` on `wazuh-alerts-*` | missing read permission or role mapping | re-apply the role and mapping from the permissions document |
| `403` on `daily-triage-events` or `-settings` after an upgrade to 0.10 | the role lists the old index names | give the role `<prefix>-*` |
| Timeout | routing, firewall or NetworkPolicy | test from inside the container's network |
| Storage safety shows *could not be checked* | the user may not read ISM policies | optional: grant ISM read; otherwise check the policies yourself |

Do not set `verify_tls: false` to get past a certificate error in production; the application refuses to start
with it.

## Wazuh API: connection and permissions

| Symptom | Cause | Fix |
|---|---|---|
| Agent, daemon and rule sections of the report are empty | the API is not configured, not reachable or not permitted | set `api:` / `WAZUH_API_*`; create the read-only user from the permissions document |
| The user cannot be created | Wazuh password policy: 8–64 characters with upper case, lower case, digit and symbol | choose a compliant password |
| `4009` when creating a policy | an identical policy exists under another name | reuse that policy's ID |
| Logtest unavailable | `logtest:run` missing from the role | add it |
| Cluster: status looks wrong | `api.url` points at a worker | point it at the master |

Without the API, alert analysis still works.

## The report is empty, late or incomplete

| Symptom | Cause | Fix |
|---|---|---|
| No report at the scheduled time | container was not running, schedule disabled, wrong timezone | keep it running; `schedule.enabled`; `TZ` |
| The button answers "busy" (`409`) | a run for this environment is active | wait; a run that died is recovered at the next start |
| The window is shorter or longer than expected | it starts at the last **successful** run; `window_max_hours` caps it | choose a fixed window on the environment's **Reports** page for a one-off |
| "Collection errors (blind spots)" lists entries | single queries failed | fix the cause shown; that section of the report is empty, not clean |
| Zero alerts although Wazuh has alerts | wrong `alerts_index`, or the account cannot read it | check the pattern and the `_count` test above |
| Flags only, no findings; the summary mentions an AI error | the model was unreachable or never submitted a report; a deterministic report was stored instead | see the next section; questions stay open for the next run |
| A run with status *error* | an unhandled error; the run shows stage and message | the next run starts from the last successful window; report it with the request ID |

## Model problems

| Symptom | Cause | Fix |
|---|---|---|
| "AI tool calls (0)" and a thin report | the model does not support tool (function) calling, or ignores it | choose a model with tool calling; small local models often skip tools |
| *The model did not submit a report* | the model stopped without calling the report tool, or ran out of steps | raise `max_tool_steps`; try a stronger model |
| A note "output limit reached" | the answer was cut at the token limit | raise `max_tokens` |
| `400` from an OpenAI reasoning model | parameter names differ | `LLM_TOKEN_PARAM=max_completion_tokens`, `LLM_TEMPERATURE=none` |
| `401` / `404` from the provider | wrong key, base URL or model ID | check `LLM_*` against [docs/providers.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/providers.md) |
| Cost is higher than expected | many tool steps per run, or many runs | lower `max_tool_steps`; one or two AI rounds a day; the watch and the liveness check never call the model |

Compare models with numbers instead of impressions: `python -m app.eval`
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)).

## Notifications

| Symptom | Cause | Fix |
|---|---|---|
| Nothing arrives | no channel has all its fields set | press **Test notifications** on the environment's **Reports** page; it reports per channel |
| The run summary is missing | off by default | `notify.on_run_summary: true` |
| The same critical item is not repeated | by design, within `repeat_hours` (24) | – |
| Teams: nothing | the old Office 365 connectors are retired | use the Workflows webhook |
| Telegram: nothing | wrong chat ID (group IDs are negative), or the bot is not in the group | get the ID from `getUpdates` |
| E-mail refused | `security: none` with a user name is not allowed | use `starttls` or `ssl` |
| The watch announces nothing | watch off, no channel ticked, quiet hours, or the event is muted or known noise | the **Watch** page shows the status of each event |

## Rule deployment

| Symptom | Cause | Fix |
|---|---|---|
| The button is greyed out | `rule_deploy` is not enabled | [Rule lifecycle](Rule-Lifecycle) |
| Startup refuses to start with rule deployment on | the deploy user name or password is empty, or the password is an example value | set real credentials for the separate deploy user |
| Startup warning about the deploy user | it is the same account as the read-only user | create the separate user |
| `Permission denied: Resource type: rule:file` | the `rules:delete` policy names another file than `rule_deploy.file` | make the names equal |
| `Permission denied: Resource type: *:*` | `rules:update` was scoped to a file; Wazuh only accepts `*:*:*` | fix the policy |
| Rolled back, *inconclusive* | a sample matched no rule at all | fix the sample so that it reaches the parent rule; `allow_inconclusive` only as a documented exception |
| Parent rule unknown | load order of files in `etc/rules` | use a file name that sorts later, such as `zz_wdt_rules.xml`, in both the setting and the policy |
| Rollback **failed** (critical in the log) | the manager did not accept the restored file or did not restart | a person must check the manager: `wazuh-analysisd -t` on the manager, then the file |
| The restart times out | a slow cluster | raise `restart_timeout` |
| Frequency rule rolled back, `match → <parent id> ✗` | before 0.11.1 a single logtest event can only reach the parent | 0.11.1 replays the sample `frequency + 2` times in one session |
| Record says *Interrupted — check the manager* | the pod restarted during a deployment | check the rule file on the manager (`grep -n wdt:begin`), then deploy again or remove |

## Kubernetes

| Symptom | Cause | Fix |
|---|---|---|
| Pod restarts in a loop | a startup check failed | `kubectl logs --previous` shows the message |
| Ready, but connection checks time out | NetworkPolicy egress | allow the Indexer, API, and any extra source; see [Kubernetes](Kubernetes) |
| Ingress answers `502`/`503` | the policy's `ingressNamespace` is not your controller's namespace | set `networkPolicy.ingressNamespace` |
| Every page is `401` after upgrading to 0.10 in SSO mode | the proxy forwards no user header | forward one of the `USER_HEADER` headers |
| Every check runs twice | more than one replica | one replica, or `WDT_SCHEDULER=false` on the others |
| The audit trail is empty after a restart | `emptyDir` | ship it or mount a volume |

Readiness and liveness never depend on Wazuh. A pod that is ready while Wazuh is down is intended.

## MCP

| Symptom | Cause | Fix |
|---|---|---|
| `404` on `/mcp` | `MCP_TOKEN` is not set; the endpoint is off | set it and restart |
| `401` | wrong token; repeated failures lock the address out for a while | check the token file; wait |
| `429` "rate limit exceeded" | more than 120 requests a minute from one address | wait a minute, or `MCP_RATE_PER_MINUTE` |
| `405` on `GET /mcp` | normal: there is no server-initiated stream | – |
| The client shows the SSO login page | `/mcp` is routed through the SSO proxy | route `/mcp` around the login; it has its own token |
| An environment is missing | `MCP_ENVS` | add it |
| The host name does not resolve from the client | the UI is only reachable inside your network or VPN | connect the VPN, or use the stdio bridge on a machine that can reach it |

## Storage and backup

| Symptom | Cause | Fix |
|---|---|---|
| Red banner "The index … was missing" | a retention policy or a person deleted application data | **Settings → Backup → Import**, or acknowledge the loss. See [Backup](Backup) |
| The archive cannot be opened | wrong passphrase, or the file was changed | there is no recovery without the passphrase |
| No automatic backup | it needs S3, `BACKUP_PASSPHRASE` and the switch in Settings | configure all three |

## When you report a problem

Open an issue with the version (About page), how it is deployed, the request ID, and the relevant log lines.
Remove host names, IP addresses and tokens first. Security problems go privately through
[GitHub security advisories](https://github.com/dururustem68/wazuh-daily-triage/security/advisories/new).

*Applies to 0.11.1 · reviewed 2026-11-12*

---

[English](Troubleshooting) · [Türkçe](Troubleshooting-TR)
