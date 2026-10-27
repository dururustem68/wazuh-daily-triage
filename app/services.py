# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Per-environment service container: clients, store and the run/deploy locks."""
from __future__ import annotations

import asyncio
import logging

from .config import Environment
from .store import MemoryStore, Repo

log = logging.getLogger("wdt")


def build_sources(env: Environment) -> dict:
    """Prometheus / Loki / Kubernetes clients for one environment (only those configured)."""
    from .sources import Kubernetes, Loki, Prometheus, SourceError
    out: dict = {}
    sc = env.sources
    if sc.prometheus:
        out["prometheus"] = Prometheus(sc.prometheus)
    if sc.loki:
        out["loki"] = Loki(sc.loki)
    if sc.kubernetes.enabled:
        try:
            out["kubernetes"] = Kubernetes(sc.kubernetes)
        except (SourceError, OSError) as e:
            log.warning("%s: Kubernetes source disabled: %s", env.id, e)
    return out


class EnvRuntime:
    def __init__(self, env: Environment, ix, api, store):
        self.env = env
        self.ix = ix
        self.api = api
        self.store = store
        self.repo = Repo(store, env.id)
        self.lock = asyncio.Lock()
        self.deploy_lock = asyncio.Lock()
        self.current_run: str | None = None
        self.sources: dict = build_sources(env) if not isinstance(store, MemoryStore) else {}
