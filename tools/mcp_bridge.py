#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""stdio ↔ HTTP bridge for the wazuh-daily-triage MCP endpoint (standard library only).

MCP clients that start local servers over stdio (e.g. Claude Desktop) run this script; it forwards each
JSON-RPC message to https://<your-host>/mcp with the bearer token and prints the answer.

  WDT_MCP_TOKEN=... python3 mcp_bridge.py https://wazuh-triage.example.com/mcp
  python3 mcp_bridge.py https://... --token-file ~/.wdt-mcp-token [--ca-file ca.pem | --insecure]
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--token-file")
    ap.add_argument("--ca-file")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS (lab only)")
    a = ap.parse_args()
    tok = os.environ.get("WDT_MCP_TOKEN", "")
    if a.token_file:
        with open(os.path.expanduser(a.token_file), encoding="utf-8") as f:
            tok = f.read().strip()
    if not tok:
        sys.exit("no token: set WDT_MCP_TOKEN or --token-file")
    ctx = ssl.create_default_context(cafile=a.ca_file) if a.ca_file else ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    session = None
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "Authorization": f"Bearer {tok}"}
        if session:
            h["Mcp-Session-Id"] = session
        req = urllib.request.Request(a.url, data=line.encode(), headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=180, context=ctx) as r:
                session = r.headers.get("Mcp-Session-Id") or session
                body = r.read().decode()
        except urllib.error.HTTPError as e:
            body = ""
            if isinstance(msg, dict) and msg.get("id") is not None:
                body = json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                   "error": {"code": -32000, "message": f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"}})
        except Exception as e:  # noqa: BLE001
            body = ""
            if isinstance(msg, dict) and msg.get("id") is not None:
                body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": str(e)}})
        if body.strip():
            sys.stdout.write(body.strip().replace("\n", " ") + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
