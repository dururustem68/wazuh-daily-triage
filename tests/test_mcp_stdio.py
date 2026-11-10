# SPDX-License-Identifier: AGPL-3.0-only
"""MCP over stdio (python -m app.mcp_stdio)."""
import asyncio
import io
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _lines(*msgs) -> str:
    return "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in msgs)


def test_serve_answers_requests_only(monkeypatch):
    monkeypatch.setenv("WDT_DEMO", "true")
    from app import mcp_stdio  # imported here: other test modules set the environment first
    out = io.StringIO()

    async def go():
        rt = await mcp_stdio.build_runtime()
        try:
            await mcp_stdio.serve(rt, io.StringIO(_lines(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                "", "not json",
                [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, {"jsonrpc": "2.0", "id": 3, "method": "ping"}],
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                 "params": {"name": "list_environments", "arguments": {}}},
            )), out)
        finally:
            await rt.close()

    asyncio.run(go())
    res = [json.loads(x) for x in out.getvalue().splitlines()]
    assert len(res) == 4                                   # no answer to the notification or the blank line
    assert res[0]["result"]["serverInfo"]["name"] == "wazuh-daily-triage"
    assert res[1]["error"]["code"] == -32700
    names = {t["name"] for t in res[2][0]["result"]["tools"]}
    assert {"list_environments", "search_alerts", "get_report"} <= names and "submit_report" not in names
    assert res[2][1] == {"jsonrpc": "2.0", "id": 3, "result": {}}
    envs = json.loads(res[3]["result"]["content"][0]["text"])
    assert envs[0]["id"] == "demo"


def test_module_keeps_stdout_for_the_protocol():
    env = {**os.environ, "WDT_DEMO": "true", "WDT_DEMO_SEED": "false", "LOG_LEVEL": "INFO"}
    p = subprocess.run([sys.executable, "-m", "app.mcp_stdio"], cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=120, input=_lines({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
    assert p.returncode == 0, p.stderr
    assert [json.loads(x) for x in p.stdout.splitlines()] == [{"jsonrpc": "2.0", "id": 1, "result": {}}]
    assert "MCP over stdio" in p.stderr


def test_glama_json():
    d = json.loads((ROOT / "glama.json").read_text())
    assert d["maintainers"] == ["dururustem68"]
