# Least-privilege accounts and network access

Wazuh Daily Triage **never changes anything in Wazuh**. The only write permission it needs is to its own
`daily-triage-*` indices. Do not give it admin credentials — create the two accounts below.

## 1. Wazuh Indexer (OpenSearch) — user `daily-triage`

| Permission | Scope | Why |
|---|---|---|
| `cluster_composite_ops_ro`, `cluster_monitor` | cluster | search, `_cluster/health`, `_cat/allocation` |
| `read` | `wazuh-alerts-*`, `wazuh-states-vulnerabilities-*` | alert and vulnerability queries |
| `indices_all` | `daily-triage-*` | reports, knowledge base, chat (including index creation) |

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
