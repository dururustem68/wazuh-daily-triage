# Least-privilege accounts and network access

Wazuh Daily Triage is **read-only towards Wazuh** by default. The only write permission it needs is to its own
`daily-triage-*` indices. Do not give it admin credentials — create the two accounts below.

The optional "Approve and deploy" for rule drafts uses a **third, separate** API user that may only upload custom
rules files and restart the manager — see [rule-deployment.md](rule-deployment.md).

Sections 1–2 are about the Wazuh accounts; sections 4–6 cover the application's own controls (UI roles,
environment scoping, audit trail, metrics).

## 1. Wazuh Indexer (OpenSearch) — user `daily-triage`

| Permission | Scope | Why |
|---|---|---|
| `cluster_composite_ops_ro`, `cluster_monitor` | cluster | search, `_cluster/health`, `_cat/allocation` |
| `read` | `wazuh-alerts-*`, `wazuh-states-vulnerabilities-*` | alert and vulnerability queries |
| `indices_all` | `daily-triage-*` | reports and knowledge base (including index creation) |

With the Security REST API (once, as an admin):

```sh
IX=https://wazuh-indexer:9200
AUTH='admin:ADMIN_PASSWORD'

curl -sk -u "$AUTH" -X PUT "$IX/_plugins/_security/api/roles/daily_triage" -H 'Content-Type: application/json' -d '{
  "cluster_permissions": ["cluster_composite_ops_ro", "cluster_monitor"],
  "index_permissions": [
    {"index_patterns": ["wazuh-alerts-*", "wazuh-states-vulnerabilities-*"], "allowed_actions": ["read"]},
    {"index_patterns": ["daily-triage-*"], "allowed_actions": ["indices_all"]}
  ]}'

curl -sk -u "$AUTH" -X PUT "$IX/_plugins/_security/api/internalusers/daily-triage" -H 'Content-Type: application/json' \
  -d '{"password": "A_STRONG_PASSWORD", "description": "Wazuh Daily Triage (read-only + daily-triage-*)"}'

curl -sk -u "$AUTH" -X PUT "$IX/_plugins/_security/api/rolesmapping/daily_triage" -H 'Content-Type: application/json' \
  -d '{"users": ["daily-triage"]}'

# verify
curl -sk -u 'daily-triage:A_STRONG_PASSWORD' "$IX/wazuh-alerts-*/_count"
```

If you changed `storage_prefix`, use that prefix instead of `daily-triage-*`.

> **Kubernetes / Docker deployments (wazuh-kubernetes, wazuh-docker):** the security configuration may be
> reloaded from `internal_users.yml`, `roles.yml` and `roles_mapping.yml` with `securityadmin`, which can
> overwrite users created through the REST API. Add the same definitions to those files (generate the bcrypt
> hash with `plugins/opensearch-security/tools/hash.sh`) and apply them with `securityadmin`.

## 2. Wazuh server API — user `daily-triage` (optional)

| Action | Resource | Used for |
|---|---|---|
| `agent:read` | `agent:id:*` | agent status, inactive agents |
| `manager:read` | `*:*:*` | daemon status, `ossec.log` errors |
| `cluster:status` | `*:*:*` | whether the cluster is enabled |
| `cluster:read` | `node:id:*` | cluster health check |
| `rules:read` | `rule:file:*` | rule definitions, ID collision check |
| `logtest:run` | `*:*:*` | which rule a log line matches |

```sh
API=https://wazuh-manager:55000
TOKEN=$(curl -sk -u 'wazuh-wui:PASSWORD' -X POST "$API/security/user/authenticate?raw=true")
H="Authorization: Bearer $TOKEN"
J='Content-Type: application/json'

pol() { curl -sk -H "$H" -H "$J" -X POST "$API/security/policies" -d "$1" | jq -r '.data.affected_items[0].id'; }
P1=$(pol '{"name":"daily_triage_agents","policy":{"actions":["agent:read"],"resources":["agent:id:*"],"effect":"allow"}}')
P2=$(pol '{"name":"daily_triage_global","policy":{"actions":["manager:read","cluster:status","logtest:run"],"resources":["*:*:*"],"effect":"allow"}}')
P3=$(pol '{"name":"daily_triage_cluster","policy":{"actions":["cluster:read"],"resources":["node:id:*"],"effect":"allow"}}')
P4=$(pol '{"name":"daily_triage_rules","policy":{"actions":["rules:read"],"resources":["rule:file:*"],"effect":"allow"}}')

ROLE=$(curl -sk -H "$H" -H "$J" -X POST "$API/security/roles" -d '{"name":"daily_triage"}' | jq -r '.data.affected_items[0].id')
curl -sk -H "$H" -X POST "$API/security/roles/$ROLE/policies?policy_ids=$P1,$P2,$P3,$P4"

USR=$(curl -sk -H "$H" -H "$J" -X POST "$API/security/users" \
  -d '{"username":"daily-triage","password":"Str0ng.Passw0rd!"}' | jq -r '.data.affected_items[0].id')
curl -sk -H "$H" -X POST "$API/security/users/$USR/roles?role_ids=$ROLE"
```

Wazuh API passwords need 8–64 characters with upper and lower case letters, a digit and a symbol.
Without the API, alert analysis still works; agent/daemon health, rule info and logtest are disabled.

## 3. Network access

The container talks to the indexer (9200) and the API (55000) **directly over HTTPS**.

- **All-in-one / VM installs:** reach the host over your LAN or VPN.
- **Kubernetes:** these services are usually cluster-internal. Either deploy this container in the same cluster
  (`https://indexer.wazuh.svc:9200`, `https://wazuh.wazuh.svc:55000`) or expose them through an
  internal-only LoadBalancer/NodePort/Ingress reachable from your VPN — never to the internet.
- **Self-signed certificates:** copy the root CA into `config/certs/` and set `ca_file`. Use
  `verify_tls: false` only for a first test.

Run `python -m app.check` (or the "Test connections" button) to verify each step.

With `ENVIRONMENT=production` (or `WDT_ENV=production`) the application refuses to start when TLS verification is
disabled for any endpoint, unless `WDT_ALLOW_INSECURE_TLS=1` is set deliberately. See
[security-exceptions.md](security-exceptions.md).

## 4. Web UI roles and environment scoping

Two roles exist. There is no user database: the admin password is `APP_PASSWORD`, the optional read-only role
uses `VIEWER_PASSWORD`. Behind an SSO proxy (`AUTH_DISABLED=true`) every request is an admin, identified by the
proxy's user header.

| Permission | Admin | Viewer | Covers |
|---|---|---|---|
| `read` | ✓ | ✓ | dashboards, reports, inbox, knowledge base, audit views |
| `run` | ✓ | – | start a triage run, liveness check, connection test, notification test |
| `decide` | ✓ | – | finding decisions, questions, inbox actions |
| `knowledge` | ✓ | – | create/update/delete knowledge entries, import/export |
| `deploy` | ✓ | – | rule deploy, undeploy, promote |
| `admin` | ✓ | – | environment-level operations, `/metrics` without a token |

The matrix lives in `app/authz.py`. Permissions are enforced in the HTTP middleware for every route
(`app/main.py::_required_perm`), not by hiding buttons.

When several environments share one installation (production + staging + customer instances), each role can be
limited to a list of environment ids:

```sh
# .env — comma separated; empty means "all configured environments"
ADMIN_ENVS=prod,staging
VIEWER_ENVS=staging
MCP_ENVS=staging            # environments MCP clients may query
```

A denied environment answers `403` (API) or the `auth.no_env` page, and the denial is audited. Environment
scoping is additionally checked inside `_env()` and in the MCP tool dispatcher, so a crafted URL or tool call
cannot reach an environment outside the list. The model/AI is only given the environments the session can see.

### Query limits (AI and MCP)

The model never sends raw queries: tools build them, and `app/query_guard.py` checks them first. Per environment:

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

An unknown field, a window above the cap, too many buckets or an unparseable timestamp raises a
`QueryError` that is returned to the model as a hint — the query is never sent to the cluster. The collector
itself is not limited by these values (it uses fixed, reviewed queries), so a tight cap cannot break a run.

## 5. Audit trail

`logs/audit.jsonl` (override with `AUDIT_LOG_FILE`) is an **append-only JSON Lines** file, separate from the
monthly ISMS report (`app/audit.py`, stored in the index). Each line carries:

| Field | Example |
|---|---|
| `ts` | `2026-10-27T07:31:05+00:00` |
| `action` | `login`, `login.failed`, `rule.deploy`, `rule.undeploy`, `http.post`, `denied`, `mcp.propose_knowledge` |
| `actor`, `role` | proxy user or `ui`/`viewer`, and the role |
| `env`, `target` | environment id and the object touched (rule id, path) |
| `result` | `ok`, `deployed`, `failed (rollback: done)`, `denied:deploy` |
| `request_id`, `method`, `path` | correlation with the application log line (`X-Request-ID`) |
| `prev`, `hash` | SHA-256 chain over the previous hash and the record |

Every state-changing HTTP request, every denial (including env scope), every login attempt, every rule
deployment and MCP knowledge proposal is recorded. **No secrets, tokens, passwords or raw log lines** are
written — only identifiers and the outcome.

Integrity check:

```sh
python -c "from app import auditlog; print(auditlog.verify('logs/audit.jsonl'))"
# {'ok': True, 'lines': 4213, 'broken': None, ...}
```

A broken chain means a line was modified, inserted or removed; compare with your log shipper's copy.

**Rotation and retention.** The file rotates at 20 MB and keeps three generations (`.1` … `.3`), so the
default footprint stays under ~80 MB. Each generation is a complete hash chain of its own (the first line of a
new file has no `prev`), so verify every file you ship. For compliance, ship the files to central storage
(Vector, Fluent Bit, Filebeat, a sidecar) and keep them according to your retention policy — the application
does not delete history beyond rotation. The shipped manifests mount a writable directory at `/app/logs`
(`docker-compose` bind-mounts `./logs`, Kubernetes an `emptyDir`), so records vanish with the pod there:
ship them or replace the volume with a PVC. Set `AUDIT_LOG=false` only for tests: production startup then
warns that there is no trail. If the path is not writable the application keeps running and logs a single
warning; a mounted read-only volume is fine as long as the log directory itself is writable or shipped
elsewhere.

## 6. Metrics endpoint

`GET /metrics` exposes an in-memory Prometheus text exposition: build info, uptime, HTTP requests and
durations, runs by trigger/status, findings, LLM tokens, rule deploys and rollbacks, query errors.

- Without `METRICS_TOKEN`, an **admin session** is required (the viewer gets `403`).
- With `METRICS_TOKEN`, a `Authorization: Bearer <token>` header is required instead, so a scraper does not need
  a session: `METRICS_TOKEN=...` and a `ServiceMonitor`/scrape config.

Counters are per process and reset on restart; they are for health questions, not for long-term reporting.

## 7. Startup checks

`app/security.py` validates the security-relevant configuration when the process starts. In production it
**refuses to start** on: `WDT_DEMO=true`, a missing/example `APP_PASSWORD`, a missing `APP_SECRET`,
`VIEWER_PASSWORD` equal to the admin password, `COOKIE_SECURE=false`, TLS verification disabled for an
endpoint, or `rule_deploy.enabled` without credentials. Warnings (not fatal): `AUTH_DISABLED=true`, the
read-only client and the deploy user sharing one account, and `AUDIT_LOG=false`. Every message names the
variable and the fix; all deliberate overrides are listed in
[security-exceptions.md](security-exceptions.md).
