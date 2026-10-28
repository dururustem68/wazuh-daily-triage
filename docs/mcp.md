# MCP server — use the investigation tools from Claude Desktop (or any MCP client)

`POST /mcp` speaks the [Model Context Protocol](https://modelcontextprotocol.io) (Streamable HTTP, JSON responses).
It exposes the same **read-only** tools the built-in AI uses, for every environment:

| Tool | What it does |
|---|---|
| `list_environments` | environments and which extra sources they have — call first |
| `search_alerts`, `aggregate_alerts`, `rule_timeline`, `ip_profile`, `correlate_around` | the alerts index |
| `vulnerabilities`, `agent_info`, `rule_info`, `logtest` | vulnerability state, Wazuh API |
| `prom_query`, `prom_range`, `loki_query`, `loki_labels`, `k8s_get`, `k8s_logs` | [other sources](sources.md), when configured |
| `list_reports`, `get_report`, `inbox`, `knowledge`, `audit_report` | this application's runs, waiting recommendations, knowledge base, monthly report |
| `validate_rule_xml`, `propose_knowledge` | check a rule draft; add a **proposal** (no effect until approved in the UI) |

Nothing else can be written. `privacy.mode: mask` applies to MCP results as well: personal data comes back as
pseudonyms (`<email:3f9a1c2b>`), which the server resolves again when they are passed as tool arguments.

## Enable

1. Generate a long random token and put it into the application's secret as `MCP_TOKEN`
   (e.g. `openssl rand -hex 32`). Without it `/mcp` answers 404.
2. Let `/mcp` past your SSO proxy — the endpoint checks the bearer token itself:
   - **oauth2-proxy:** `OAUTH2_PROXY_SKIP_AUTH_ROUTES=POST=^/mcp$`
   - **Traefik + Authentik (forward auth):** a second router for `PathPrefix(`/mcp`)` without the Authentik
     middleware (see `components/ingress-traefik-authentik`).
   - Keep the host internal (VPN) — the token is the only protection on this path.
3. Restart the pod.

## Claude Desktop

Claude Desktop starts local MCP servers over stdio. [`tools/mcp_bridge.py`](../tools/mcp_bridge.py) (standard
library only) forwards stdio to `/mcp`. Put the token in a file readable only by you, then in
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh-prod": {
      "command": "python3",
      "args": ["/path/to/wazuh-daily-triage/tools/mcp_bridge.py", "https://wazuh-triage.example.com/mcp",
               "--token-file", "/path/to/mcp.token"]
    }
  }
}
```

On Windows with WSL: `"command": "wsl.exe", "args": ["python3", "/mnt/c/…/mcp_bridge.py", "https://…/mcp", "--token-file", "/mnt/c/…/mcp.token"]`.
Use `--ca-file` for a private CA. Any client that supports Streamable HTTP with a custom header can connect
directly (`Authorization: Bearer <token>`).
