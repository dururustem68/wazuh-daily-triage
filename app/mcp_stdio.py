# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The MCP tools over stdio, in one process — no web server, no token, no bridge.

    WDT_DEMO=true python -m app.mcp_stdio                       # synthetic data, nothing else needed
    docker run -i --rm -e WDT_DEMO=true <image> python -m app.mcp_stdio

Same tools and answers as ``POST /mcp`` (see :mod:`app.mcp`); only the transport differs: one JSON-RPC message
per line on stdin, one answer per line on stdout, logs on stderr. Meant for the demo, MCP directories that start
servers to list their tools, and local use next to a configuration you already have. For a shared installation
use the HTTP endpoint with ``MCP_TOKEN`` — it has rate limits, per-client audit and runs next to the web UI.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

from . import __version__, auditlog, security
from .config import config_path, load_settings
from .mcp import _err, _handle
from .observability import install_logging
from .runtime import Runtime, demo_enabled

log = logging.getLogger("wdt.mcp")


async def build_runtime() -> Runtime:
    demo = demo_enabled()
    settings = load_settings(config_path(demo))
    if demo and settings.llm.provider != "mock" and not settings.llm.api_key and not settings.llm.base_url:
        settings.llm = settings.llm.model_copy(update={"provider": "mock"})
    for w in security.check(settings, demo=demo):           # refuses to start on fatal problems
        log.warning("security: %s", w)
    auditlog.configure()
    rt = Runtime(settings, demo=demo)
    await rt.load_all_settings()
    if demo:
        from . import demo_seed
        if demo_seed.enabled():
            try:
                await demo_seed.seed_demo(rt)
            except Exception:  # noqa: BLE001 - the tools work without the sample round
                log.exception("demo: could not create the sample data")
    return rt


async def serve(rt, stdin=None, stdout=None) -> None:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, stdin.readline)
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            res = _err(None, -32700, "parse error")
        else:
            if isinstance(msg, list):
                res = [r for r in [await _handle(rt, m) for m in msg if isinstance(m, dict)] if r] or None
            elif isinstance(msg, dict):
                res = await _handle(rt, msg)
            else:
                res = _err(None, -32600, "invalid request")
        if res:
            stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
            stdout.flush()


async def main() -> None:
    install_logging(os.environ.get("LOG_LEVEL", "WARNING"))  # stderr; stdout carries the protocol only
    rt = await build_runtime()
    log.warning("wazuh-daily-triage %s MCP over stdio — %d environment(s)%s", __version__,
                len(rt.envs), " (DEMO)" if rt.demo else "")
    try:
        await serve(rt)
    finally:
        await rt.close()


if __name__ == "__main__":
    asyncio.run(main())
