# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Runtime: settings, per-environment containers and the mixin composition.

The behaviour lives in focused mixins so each file stays reviewable:

- ``runs.py`` — start/guard a run, pick the window, collect, call the model, save
- ``review.py`` — recommendation inbox, run/rule/liveness notifications
- ``ruledeploy.py`` — rule analysis, deploy/rollback, live verification, promotion
- ``incident_ops.py`` — monthly audit report and incident records
- ``diagnostics.py`` — the connection test
- ``knowledgeio.py`` — seed import and knowledge import/export
- ``scheduler.py`` — scheduler loop, retention tick, shutdown

``Runtime`` itself only builds the environments and keeps the shared caches; existing imports
(``normalize_report``, ``_compact``, ``demo_enabled``, ``build_sources``) are re-exported here.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC
from typing import Any
from zoneinfo import ZoneInfo

from .config import Environment, LLMConfig, Settings
from .diagnostics import DiagnosticsMixin
from .incident_ops import IncidentMixin
from .knowledgeio import KnowledgeIOMixin
from .llm.base import make_llm
from .reporting import _compact, _fmt_local, _neg_ts, flags_only_report, normalize_report
from .reporting import demo_enabled as demo_enabled
from .review import ReviewMixin
from .ruledeploy import RuleDeployMixin
from .runs import RunMixin
from .scheduler import SchedulerMixin
from .services import EnvRuntime
from .services import build_sources as build_sources
from .store import IndexStore, MemoryStore
from .wazuh.api import WazuhAPI
from .wazuh.indexer import Indexer

log = logging.getLogger("wdt")

__all__ = ["Runtime", "EnvRuntime", "build_sources", "demo_enabled", "normalize_report", "_compact",
           "_fmt_local", "_neg_ts", "flags_only_report", "UTC"]


class Runtime(KnowledgeIOMixin, RunMixin, ReviewMixin, RuleDeployMixin, IncidentMixin, DiagnosticsMixin,
              SchedulerMixin):
    def __init__(self, settings: Settings, demo: bool = False):
        self.settings = settings
        self.demo = demo
        self.tz = ZoneInfo(settings.app.timezone)
        self.envs: dict[str, EnvRuntime] = {}
        self._llms: dict[int, object] = {}
        self._sched_task: asyncio.Task | None = None
        self._fired: set[str] = set()
        self._seeded: set[str] = set()
        self._pruned: set[str] = set()
        self._prune_last: dict[str, float] = {}
        self._tasks: set[asyncio.Task] = set()
        self._run_locks: dict[str, asyncio.Lock] = {}
        self.notify_transport = None       # tests inject an httpx.MockTransport here
        self.live_state: dict[str, dict] = {}
        self._live_last: dict[str, float] = {}
        self._live_busy: set[str] = set()
        for e in settings.environments:
            ix: Any
            api: Any
            store: Any
            if demo:
                from .demo import FakeAPI, FakeIndexer
                ix, api, store = FakeIndexer(), FakeAPI(), MemoryStore()
            else:
                ix = Indexer(e.indexer, limits=e.query)
                api = WazuhAPI(e.api) if e.api else None
                store = IndexStore(ix, e.storage_prefix)
            self.envs[e.id] = EnvRuntime(e, ix, api, store)

    # ------------------------------------------------------------ helpers
    def llm_cfg(self, env: Environment) -> LLMConfig:
        return self.settings.llm_for(env)

    def llm_for(self, env: Environment):
        cfg = self.llm_cfg(env)
        key = id(cfg)
        if key not in self._llms:
            self._llms[key] = make_llm(cfg)
        from .privacy import MaskingLLM, masker_for
        m = masker_for(env)
        return MaskingLLM(self._llms[key], m) if m else self._llms[key]

    def lang(self, env: Environment) -> str:
        return self.settings.lang_for(env)

    def get(self, env_id: str) -> EnvRuntime:
        if env_id not in self.envs:
            raise KeyError(env_id)
        return self.envs[env_id]
