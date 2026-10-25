# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Connection test from the command line.

    docker compose run --rm triage python -m app.check            # all environments
    docker compose run --rm triage python -m app.check prod --no-llm
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import load_settings
from .runtime import Runtime, demo_enabled


async def _main(args) -> int:
    cfg = os.environ.get("WDT_CONFIG") or ("config/demo.yaml" if demo_enabled() else "config/environments.yaml")
    rt = Runtime(load_settings(cfg), demo=demo_enabled())
    failed = 0
    try:
        ids = args.env or list(rt.envs)
        for env_id in ids:
            print(f"\n== {env_id} ({rt.get(env_id).env.name})")
            for r in await rt.check(env_id, with_llm=not args.no_llm):
                mark = "OK  " if r["ok"] else "FAIL"
                failed += 0 if r["ok"] else 1
                print(f"  [{mark}] {r['key']:<8} {r['detail']}")
    finally:
        await rt.close()
    return 1 if failed else 0


def main():
    p = argparse.ArgumentParser(prog="python -m app.check", description="Test indexer, Wazuh API and LLM connectivity")
    p.add_argument("env", nargs="*", help="environment id(s); default: all")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM call")
    sys.exit(asyncio.run(_main(p.parse_args())))


if __name__ == "__main__":
    main()
