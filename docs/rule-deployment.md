# Deploying approved rule drafts (optional)

The AI writes **rule drafts** (`kind: rule_draft` in the knowledge base). For every draft the UI offers:

| Button | What happens | Needs |
|---|---|---|
| **Commands** | A copy-paste shell block for the manager: back up the file, append the rule, `wazuh-analysisd -t` (restores the backup and stops if it fails), restart, verify, how to roll back. | nothing — always available |
| **Approve (do not deploy)** | Marks the draft accepted; the AI treats it as a decision from now on. | nothing |
| **Approve and deploy** | The application writes the rule to the manager itself, validates, restarts and verifies — rolling back automatically on any failure. | `rule_deploy.enabled: true` + a separate API user |
| **Remove from Wazuh** | Removes that draft's block from the file, validates, restarts. | same |

Deployment is **off by default**. With it off the application stays fully read-only towards Wazuh.

## What "Approve and deploy" does

1. **Checks the draft** — XML syntax, only `<group>`/`<rule>` elements, rule IDs inside `id_min`–`id_max`,
   no collision with a rule in another file, parent rules (`if_sid`, `if_matched_sid`) exist.
2. **Flags silencing** — `level="0"`, `overwrite="yes"`, `no_log`/`no_full_log`/`no_email_alert`/`no_ar`
   options, or a child rule with a *lower* level than its parent. These need a second confirmation: the user
   types the rule ID(s). A prompt-injected model therefore cannot blind the SIEM with one careless click.
3. **Writes one dedicated file** — `etc/rules/<file>` (default `wdt_rules.xml`) through
   `PUT /rules/files/{file}`. Each draft is a block between `<!-- wdt:begin <id> -->` and
   `<!-- wdt:end <id> -->`, so re-deploying an edited draft replaces its block and removal is exact.
   Your own rule files are never touched.
4. **Validates** — `GET /manager/configuration/validation` (or `/cluster/...`). If it fails, the previous
   file is restored and **no restart happens**.
5. **Restarts** — `PUT /manager/restart`, or `PUT /cluster/restart` when a cluster is running (rules are
   written on the master and synchronised to the workers). Event processing pauses for roughly 20–60 s.
6. **Verifies** — waits until `wazuh-analysisd` runs and the new rule IDs are loaded from the file.
7. **Logtest** — if the draft carries test events (the AI adds at least one that must match and one that must
   not), each is run through `PUT /logtest`. Any wrong result rolls the change back.
8. **Records** who did it (the SSO user from `X-authentik-username`, `X-Forwarded-User`, `Remote-User` or
   `X-Auth-Request-User` when `AUTH_DISABLED=true` behind a proxy — configurable with `USER_HEADER`),
   when, every step, and keeps the last 10 attempts on the knowledge entry.

The AI is told which drafts are deployed (to measure their effect), which were removed and which the user
rejected (so it does not propose them again).

## Configuration

`config/environments.yaml`, per environment:

```yaml
    rule_deploy:
      enabled: true
      username: ${PROD_DEPLOY_USER}
      password: ${PROD_DEPLOY_PASSWORD}
      file: wdt_rules.xml        # etc/rules/<file>; must be a plain *.xml name
      id_min: 100000             # drafts outside this range are refused
      id_max: 119999
      restart_timeout: 180       # seconds to wait for the manager to come back
```

Single environment without YAML: `RULE_DEPLOY_ENABLED=true`, `WAZUH_DEPLOY_USER`, `WAZUH_DEPLOY_PASSWORD`,
optionally `RULE_DEPLOY_FILE`, `RULE_DEPLOY_ID_MIN`, `RULE_DEPLOY_ID_MAX`.

The API URL and TLS settings are taken from the environment's `api:` block; only the credentials differ.
Keep the read-only `daily-triage` user for everything else.

## Wazuh API user `daily-triage-deploy`

| Action | Resource | Used for |
|---|---|---|
| `rules:read` | `rule:file:*` | read the file, check IDs and parent rules |
| `rules:update` | `*:*:*` | upload the rules file (Wazuh only accepts `*:*:*` for this action) |
| `rules:delete` | `rule:file:<file>` (same name as `rule_deploy.file`) | **required for every deploy**: the upload uses `overwrite=true`, which Wazuh checks as a delete of the existing file; also removes the file again if the very first deploy is rolled back. A wrong file name here gives `Permission denied: Resource type: rule:file` |
| `manager:read` | `*:*:*` | status, configuration validation |
| `manager:restart` | `*:*:*` | restart a standalone manager |
| `cluster:status` | `*:*:*` | is a cluster running |
| `cluster:read` | `node:id:*` | cluster configuration validation |
| `cluster:restart` | `node:id:*` | restart a cluster |
| `logtest:run` | `*:*:*` | two-way test of the new rule |

```sh
API=https://wazuh-manager:55000
TOKEN=$(curl -sk -u 'wazuh-wui:PASSWORD' -X POST "$API/security/user/authenticate?raw=true")
H="Authorization: Bearer $TOKEN"; J='Content-Type: application/json'
F=wdt_rules.xml   # same as rule_deploy.file

pol() { curl -sk -H "$H" -H "$J" -X POST "$API/security/policies" -d "$1" | jq -r '.data.affected_items[0].id'; }
D1=$(pol '{"name":"wdt_deploy_rules_read","policy":{"actions":["rules:read"],"resources":["rule:file:*"],"effect":"allow"}}')
D2=$(pol "{\"name\":\"wdt_deploy_rules_delete\",\"policy\":{\"actions\":[\"rules:delete\"],\"resources\":[\"rule:file:$F\"],\"effect\":\"allow\"}}")
D3=$(pol '{"name":"wdt_deploy_manager","policy":{"actions":["rules:update","manager:read","manager:restart","cluster:status","logtest:run"],"resources":["*:*:*"],"effect":"allow"}}')
D4=$(pol '{"name":"wdt_deploy_cluster","policy":{"actions":["cluster:read","cluster:restart"],"resources":["node:id:*"],"effect":"allow"}}')

ROLE=$(curl -sk -H "$H" -H "$J" -X POST "$API/security/roles" -d '{"name":"wdt_rule_deploy"}' | jq -r '.data.affected_items[0].id')
curl -sk -H "$H" -X POST "$API/security/roles/$ROLE/policies?policy_ids=$D1,$D2,$D3,$D4"
USR=$(curl -sk -H "$H" -H "$J" -X POST "$API/security/users" \
  -d '{"username":"daily-triage-deploy","password":"An0ther.Str0ng!"}' | jq -r '.data.affected_items[0].id')
curl -sk -H "$H" -X POST "$API/security/users/$USR/roles?role_ids=$ROLE"
```

If an identical policy already exists under another name, Wazuh answers `4009`; reuse that policy's ID.

> **Limit of Wazuh RBAC:** `rules:update` cannot be scoped to one file — the API rejects `rule:file:<name>` with
> `Permission denied: Resource type: *:*`. So this user *could* overwrite any custom rules file through the API.
> The application itself only ever writes `rule_deploy.file`; keep the credentials in a secret and do not reuse
> the user elsewhere. Ruleset files shipped by Wazuh (`ruleset/rules`) are not writable through this endpoint.

## Load order

Wazuh loads `ruleset/rules` first, then `etc/rules` **alphabetically**. A draft whose `if_sid` points at a rule in
another custom file must be in a file that sorts *after* it — otherwise the parent is unknown when the draft loads.
The check refuses such drafts and suggests a name; if you keep level-lowering rules in files like
`zz_local_rules.xml`, use `file: zz_wdt_rules.xml` (and the same name in the deploy user's `rules:delete` policy).

## Deployment types

| Wazuh | Notes |
|---|---|
| All-in-one / OVA / single manager | Works as is (`/manager/restart`). |
| Multi-node cluster | Point `api.url` at the **master**. Rules are synchronised to workers; `/cluster/restart` is used. |
| wazuh-docker / wazuh-kubernetes | Same as above. `etc/rules` must be on a persistent volume (it is in the official manifests), otherwise a pod restart loses the file. If you manage rules through GitOps/ConfigMaps, keep deployment off and use **Commands** or copy the approved XML into your repo. |

## Safety notes

- Approving is a human decision about AI-written XML. Read the draft; the checks above catch syntax,
  ID and silencing problems, not wrong logic.
- A restart briefly pauses analysis. Deploying during an incident is your call.
- Everything the application wrote is in one file — `grep wdt:begin /var/ossec/etc/rules/wdt_rules.xml`
  lists it, and deleting the file plus a restart removes it all.
