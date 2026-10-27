# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Scheduler loop, daily retention tick and shutdown."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from .config import DAYS, Environment
from .i18n import t

log = logging.getLogger("wdt")


class SchedulerMixin:
    def start_scheduler(self):
        if self._sched_task is None:
            self._sched_task: asyncio.Task | None = asyncio.create_task(self._scheduler())

    async def _scheduler(self):
        log.info("scheduler started (%s)", self.settings.app.timezone)
        while True:
            try:
                now = datetime.now(self.tz)
                hm = now.strftime("%H:%M")
                day = DAYS[now.weekday()]
                for rt in self.envs.values():
                    s = rt.env.schedule
                    if not (s.enabled and day in s.days and hm in s.all_times):
                        continue
                    key = f"{rt.env.id}:{now:%Y-%m-%d}:{hm}"
                    if key not in self._fired:
                        self._fired.add(key)
                        if not rt.current_run:
                            log.info("scheduled run: %s (%s)", rt.env.id, hm)
                            await self.start_run(rt.env.id, trigger="schedule")
            except Exception:  # noqa: BLE001
                log.exception("scheduler error")
            try:
                await self._liveness_tick()
            except Exception:  # noqa: BLE001
                log.exception("liveness scheduler error")
            try:
                await self._retention_tick()
            except Exception:  # noqa: BLE001
                log.exception("retention scheduler error")
            await asyncio.sleep(20)

    def next_run(self, env: Environment, lang: str = "en") -> str | None:
        s = env.schedule
        if not s.enabled:
            return None
        now = datetime.now(self.tz)
        names = t(lang, "days").split(",")
        for i in range(8):
            for tm in s.all_times:
                hh, mm = map(int, tm.split(":"))
                d = (now + timedelta(days=i)).replace(hour=hh, minute=mm, second=0, microsecond=0)
                if d > now and DAYS[d.weekday()] in s.days:
                    return f"{d:%d.%m} {names[d.weekday()]} {d:%H:%M}"
        return None

    async def close(self):
        for rt in self.envs.values():
            await rt.ix.close()
            if rt.api:
                await rt.api.close()
            for src in rt.sources.values():
                await src.close()
