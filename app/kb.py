# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Knowledge base import / export from the command line (same YAML format as seed files).

    python -m app.kb import noise.yaml -e prod --dry-run      # preview
    python -m app.kb import noise.yaml -e prod --update       # add new, update changed (by key / kind+title)
    kubectl exec -i deploy/wazuh-daily-triage -- python -m app.kb import - -e prod < noise.yaml
    python -m app.kb export -e prod --kind baseline > baseline.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

import yaml

from .config import load_settings
from .runtime import Runtime, demo_enabled


def _read(path: str):
    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    return yaml.safe_load(text) or []


async def _main(a) -> int:
    cfg = os.environ.get("WDT_CONFIG") or ("config/demo.yaml" if demo_enabled() else "config/environments.yaml")
    rt = Runtime(load_settings(cfg), demo=demo_enabled())
    try:
        env = a.env or next(iter(rt.envs))
        if a.cmd == "import":
            res = await rt.kb_import(env, _read(a.file), update=a.update, dry_run=a.dry_run)
            print(json.dumps(res, ensure_ascii=False, indent=1))
            return 1 if res["errors"] else 0
        rows = await rt.kb_export(env, kinds=a.kind or None, status=a.status or None)
        yaml.safe_dump(rows, sys.stdout, allow_unicode=True, sort_keys=False, width=120)
        return 0
    finally:
        await rt.close()


def main():
    p = argparse.ArgumentParser(prog="python -m app.kb", description="Knowledge base import / export")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("import", help="import a YAML/JSON list (seed format); '-' reads stdin")
    i.add_argument("file")
    i.add_argument("-e", "--env", help="environment id (default: the first)")
    i.add_argument("--update", action="store_true", help="update entries that already exist")
    i.add_argument("--dry-run", action="store_true", help="only report what would change")
    x = sub.add_parser("export", help="print entries as YAML")
    x.add_argument("-e", "--env")
    x.add_argument("--kind", action="append", help="repeatable, e.g. --kind baseline")
    x.add_argument("--status", action="append", help="repeatable, e.g. --status active")
    sys.exit(asyncio.run(_main(p.parse_args())))


if __name__ == "__main__":
    main()
