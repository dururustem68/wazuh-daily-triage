# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Background jobs for operations that can outlast a reverse proxy's timeout.

A rule deployment restarts the Wazuh manager or cluster and waits for it (often 30–120 s); an incident draft and
the connection test call the model. Behind oauth2-proxy (30 s upstream timeout by default), an ingress or Kong,
a request that long is cut off with ``502``/``504`` while the work goes on unseen. So these routes answer at once
with ``202 {"job": …}`` and the page polls ``GET /api/e/<env>/jobs/<id>`` — the same pattern as a triage run.

Jobs live in memory, per process (the application runs one replica). A job that changes Wazuh also records its
state where it survives a restart (the rule draft's ``deploy`` record), and ``Runtime.recover_stale`` marks an
interrupted one as such.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("wdt")

KEEP_SECONDS = 3600          # finished jobs stay readable this long
MAX_FINISHED = 200


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Job:
    id: str
    kind: str
    env: str
    key: str
    actor: str
    state: str = "running"           # running | done | error
    started_at: str = field(default_factory=_now)
    finished_at: str | None = None
    result: Any = None
    error: str | None = None
    status: int = 200                 # HTTP-like status of the outcome (400, 403, 404, 409 … on error)
    progress: list[dict] = field(default_factory=list)
    _done_mono: float = 0.0
    _task: asyncio.Task | None = None

    def public(self) -> dict:
        return {"job": self.id, "poll": f"/api/e/{self.env}/jobs/{self.id}", "kind": self.kind, "env": self.env, "state": self.state,
                "started_at": self.started_at, "finished_at": self.finished_at, "result": self.result,
                "error": self.error, "status": self.status, "progress": list(self.progress)}


class JobError(Exception):
    """An expected failure with a status code for the client (validation, permission, conflict)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class Jobs:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self.tasks: set[asyncio.Task] = set()

    def running(self, key: str) -> Job | None:
        return next((j for j in self.jobs.values() if j.key == key and j.state == "running"), None)

    def start(self, kind: str, env: str, key: str, actor: str,
              fn: Callable[[Job], Awaitable[Any]]) -> Job:
        """Run ``fn(job)`` in the background. A second start for the same ``key`` while one runs returns the
        running job instead of starting another (double clicks, two tabs)."""
        self._prune()
        same = self.running(key)
        if same:
            return same
        job = Job(id=f"{kind}-{secrets.token_hex(6)}", kind=kind, env=env, key=key, actor=actor)
        self.jobs[job.id] = job

        async def runner() -> None:
            try:
                job.result = await fn(job)
                job.state = "done"
            except JobError as e:
                job.state, job.error, job.status = "error", str(e)[:1000], e.status
            except asyncio.CancelledError:
                job.state, job.error, job.status = "error", "cancelled (the application is shutting down)", 503
                raise
            except Exception as e:  # noqa: BLE001 - a job must always end in a readable state
                log.exception("job %s (%s) failed", job.id, kind)
                job.state, job.error, job.status = "error", f"{type(e).__name__}: {e}"[:1000], 500
            finally:
                job.finished_at = _now()
                job._done_mono = time.monotonic()

        task = job._task = asyncio.create_task(runner(), name=job.id)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def wait(self, job: Job, timeout: float | None = None) -> Job:
        """For API clients that ask for the old synchronous answer (``?wait=true``)."""
        if job._task and not job._task.done():
            await asyncio.wait({job._task}, timeout=timeout)
        return job

    def get(self, job_id: str) -> Job | None:
        self._prune()
        return self.jobs.get(job_id)

    def _prune(self) -> None:
        now = time.monotonic()
        done = [j for j in self.jobs.values() if j.state != "running"]
        for j in done:
            if now - j._done_mono > KEEP_SECONDS:
                self.jobs.pop(j.id, None)
        done = sorted((j for j in self.jobs.values() if j.state != "running"), key=lambda j: j._done_mono)
        for j in done[:max(0, len(done) - MAX_FINISHED)]:
            self.jobs.pop(j.id, None)

    async def drain(self, timeout: float) -> None:
        """At shutdown: give running jobs time to finish (a deployment must not stop between write and
        rollback), then cancel what is left."""
        if not self.tasks:
            return
        log.info("waiting up to %ds for %d background job(s)", int(timeout), len(self.tasks))
        _, pending = await asyncio.wait(set(self.tasks), timeout=timeout)
        for t in pending:
            log.critical("job %s still running at shutdown — cancelled; check its target", t.get_name())
            t.cancel()
        for t in pending:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
