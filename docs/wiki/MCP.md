# MCP server

`POST /mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io) (Streamable HTTP, JSON
responses). It exposes the **same read-only investigation tools the built-in AI uses**, so Claude Desktop or any
other MCP client can query your Wazuh data, reports and knowledge base with the same limits.

The endpoint is **off by default**. Without `MCP_TOKEN` it answers `404`.

## What it exposes

| Group | Tools | Needs |
|---|---|---|
| Discovery | `list_environments` | always — call this first |
| Alerts | `search_alerts`, `aggregate_alerts`, `rule_timeline`, `ip_profile`, `correlate_around`, `vulnerabilities` | Indexer |
| Wazuh API | `agent_info`, `rule_info`, `logtest` | Wazuh API configured |
| Other sources | `prom_query`, `prom_range`, `loki_query`, `loki_labels`, `k8s_get`, `k8s_logs` | that source configured; `k8s_logs` also needs `sources.kubernetes.pod_logs: true` (default) |
| This application | `list_reports`, `get_report`, `inbox`, `knowledge`, `audit_report` | always |
| Rule drafts | `validate_rule_xml`, `propose_knowledge` | always |

- **Read-only.** There is no tool that changes Wazuh, deploys a rule or edits the knowledge base.
- `propose_knowledge` adds a **proposal** only; it has no effect until a human approves it in the UI.
- `submit_report` (the model's own output channel) is deliberately not exposed.
- `privacy.mode: mask` (or the older `redact: true`) applies to MCP results as well: personal data comes back as
  pseudonyms, which resolve again when you pass them as tool arguments. See [Privacy](Privacy).
- Every tool carries `readOnlyHint` except `propose_knowledge`.

## Enable it

1. Generate a long random token:

   ```sh
   openssl rand -hex 32
   ```

2. Store it as `MCP_TOKEN` in the process environment:

   | Deployment | Where |
   |---|---|
   | Docker Compose | `.env` (next to `APP_PASSWORD`) |
   | Helm | `secret.MCP_TOKEN` in your values file |
   | Kustomize | the generated Secret (`secret.env`) |
   | Local Python | exported shell variable |

3. Restart the pod/container. `MCP_TOKEN` is read per request, but the process environment is fixed at start.

4. Test:

   ```sh
   curl -s https://triage.example.com/mcp \
     -H "Authorization: Bearer $MCP_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
   ```

`GET /mcp` returns `405` (there is no server-initiated stream) and `DELETE /mcp` returns `204` (session
teardown). Clients fall back to plain request/response.

## Connect a client

### Claude Desktop (stdio bridge)

Claude Desktop starts local MCP servers over stdio; the repository ships a standard-library bridge,
[`tools/mcp_bridge.py`](https://github.com/dururustem68/wazuh-daily-triage/blob/main/tools/mcp_bridge.py), that forwards stdio to `/mcp`.

```sh
printf '%s' "$MCP_TOKEN" > ~/.wdt-mcp-token
chmod 600 ~/.wdt-mcp-token
```

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh-prod": {
      "command": "python3",
      "args": [
        "/path/to/wazuh-daily-triage/tools/mcp_bridge.py",
        "https://triage.example.com/mcp",
        "--token-file", "/home/you/.wdt-mcp-token"
      ]
    }
  }
}
```

- Private CA: add `--ca-file /path/to/ca.pem`.
- Lab only: `--insecure` disables TLS verification.
- Windows + WSL: `"command": "wsl.exe"` and `/mnt/c/...` paths.
- The token can also come from `WDT_MCP_TOKEN` instead of a file.

### Any Streamable HTTP client

Use the URL with `Authorization: Bearer <token>` and `Content-Type: application/json`.

```sh
# 1. handshake
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"curl","version":"1"}}}'

# 2. see the environments this token may use
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"list_environments","arguments":{}}}'

# 3. run a query
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"search_alerts",
                 "arguments":{"env":"prod","from":"now-24h","min_level":7}}}'
```

Tool results arrive as a `content` array with one `text` item containing JSON; `isError` is `true` for tool
errors. Supported protocol versions: `2025-06-18`, `2025-03-26`, `2024-11-05`.

## Environment scoping and limits

### `MCP_ENVS`

```sh
MCP_ENVS=prod,staging        # empty = every configured environment
```

- `list_environments` only lists the allowed ids.
- Every tool takes an `env` argument; its schema is an `enum` of the allowed ids.
- With exactly one allowed environment the argument is optional; with several it is required.
- An unknown or disallowed id returns an error **and the tool call is not executed**.

### Query limits

MCP clients go through `app/query_guard.py`, exactly like the model:

```yaml
    query:
      max_range_hours: 336     # 14 days per call
      max_buckets: 200
      max_terms_size: 50
      max_size: 25
      min_interval: 1m
      max_concurrent: 8
```

An unknown field, a window above the cap or an unparseable timestamp is rejected before the query reaches the
Indexer. A client cannot turn MCP into an expensive query engine.

## Behind a proxy

The application treats `/mcp` as **public** because it checks its own bearer token; an SSO proxy in front must
let the path through, otherwise the `Authorization` header never reaches the app (or the user is redirected to
an HTML login page).

| Proxy | Setting |
|---|---|
| oauth2-proxy | `--skip-auth-route=POST=^/mcp$` |
| Traefik + Authentik | a second `IngressRoute` rule for `Path('/mcp')` **without** the Authentik middleware (the shipped component does this) |
| ingress-nginx | a dedicated `Ingress` for `/mcp` without the `auth-url` annotations (annotations are per Ingress) |

**Keep the host internal.** The bearer token is the only protection on this path; do not publish `/mcp` to the
internet. Rotate the token by changing `MCP_TOKEN` and restarting.

## Security model

- **Read-only tools**, enforced in the dispatcher: the MCP mode has no `submit_report`, no deploy and no
  knowledge edit. `propose_knowledge` creates a proposal that waits for a human.
- **Per-environment allow-list** (`MCP_ENVS`) is checked in the tool dispatcher, not only in the schema.
- **Query guard** caps fields, windows, buckets and document counts.
- **Masking** (`privacy.mode: mask`) is applied to the JSON returned to the client.
- **Audit.** `mcp.propose_knowledge` is written to `logs/audit.jsonl`; every tool call is logged at INFO with
  its name and outcome (`mcp search_alerts ok`). Arguments and alert contents are not written to the audit log.
- **Prompt injection.** Alert content is attacker-controlled; the server instructions tell the client to treat
  it as data. Even a fooled model can at most add a proposal that you must approve.
- **No shell, no outbound requests.** Tools only query the configured Indexer/API/sources.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `404 {"error":"MCP is disabled (set MCP_TOKEN)"}` | `MCP_TOKEN` is empty. That is the intended disabled state. |
| `401 {"error":"unauthorized"}` | Header missing, not `Bearer`, or the token differs. Check `Authorization` after the proxy. |
| `405` on `GET` | Use `POST`; there is no server-initiated stream. |
| HTML login page instead of JSON | The SSO proxy intercepted `/mcp`; add the skip route. |
| `{ "error": "unknown, missing or not permitted env; one of [...]" }` | The `env` argument is missing or outside `MCP_ENVS`. Call `list_environments`. |
| `{ "error": "tool X is not available for Y" }` | The tool needs the Wazuh API or an extra source that this environment does not configure, or it is excluded (`submit_report`). |
| Empty results | Check the window (`from`/`to`), `min_level` and the agent/rule filters. |
| Timeout in Claude Desktop | The bridge waits up to 180 s; narrow the window or check Indexer latency. |

Next: [Configuration](Configuration) · [Viewer mode](Viewer-Mode) · [SSO proxy authentication](SSO-Proxy-Auth)

---

[English](MCP) · [Türkçe](MCP-TR)
