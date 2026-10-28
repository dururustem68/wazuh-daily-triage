# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Web application (FastAPI + Jinja2, no build step).

Routes live in ``app/web``: ``auth.py`` (login + middleware), ``pages.py`` and ``api.py``. This module only
creates the application, wires the lifespan and exposes the liveness/metrics endpoints.
"""
from __future__ import annotations

import hmac
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, auditlog, authz, security
from .config import config_path, load_settings
from .observability import install_logging, metrics
from .runtime import Runtime, demo_enabled
from .web import api as api_routes
from .web import auth as auth_routes
from .web import pages as page_routes
from .web.common import role
from .web.ui import APP_DIR, _md, set_timezone  # noqa: F401 - _md is re-exported for tests

install_logging(os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("wdt")


# ----------------------------------------------------------------------- application
@asynccontextmanager
async def lifespan(app: FastAPI):
    demo = demo_enabled()
    want = os.environ.get("WDT_CONFIG")
    cfg = config_path(demo)                                 # WDT_CONFIG, else the demo or normal YAML file
    if demo and want and cfg != want:
        log.warning("WDT_DEMO=true: %s not found, using %s", want, cfg)
    settings = load_settings(cfg)
    warnings = security.check(settings, demo=demo)          # refuses to start on fatal problems
    for w in warnings:
        log.warning("security: %s", w)
    apath = auditlog.configure()                            # AUDIT_LOG_FILE, else logs/audit.jsonl
    log.info("audit trail: %s", apath)
    log.info("authorization: %s", authz.describe())
    rt = Runtime(settings, demo=demo)
    set_timezone(rt.tz)
    app.state.rt = rt
    await rt.recover_stale()
    if os.environ.get("WDT_SCHEDULER", "true").lower() not in ("0", "false", "no"):
        rt.start_scheduler()
    log.info("wazuh-daily-triage %s started — %d environment(s)%s", __version__, len(settings.environments),
             " (DEMO)" if demo else "")
    yield
    await rt.close()


app = FastAPI(title="Wazuh Daily Triage", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

auth_routes.install(app)
app.include_router(page_routes.router)
app.include_router(api_routes.router)

from .mcp import router as mcp_router  # noqa: E402

app.include_router(mcp_router)


@app.get("/healthz")
async def healthz():
    """Liveness only: the process is up and the event loop answers. No dependency is touched, so a
    Wazuh/Indexer outage never restarts the container (and never hides the UI that explains it)."""
    return {"ok": True, "version": __version__}


@app.get("/readyz")
async def readyz(request: Request):
    """Readiness: startup finished (config loaded, runtime built) and the app can serve requests.

    Deliberately no network calls: a Wazuh or Indexer outage must not take the UI out of the Service —
    that UI is where the outage is explained. Dependency health is reported by the liveness check, the
    connection test and the degraded-storage banner instead.
    """
    rt = getattr(request.app.state, "rt", None)
    if rt is None or not rt.envs:
        return JSONResponse({"ready": False, "reason": "startup", "version": __version__}, status_code=503)
    return {"ready": True, "version": __version__, "environments": list(rt.envs),
            "scheduler": bool(rt._sched_task and not rt._sched_task.done())}


@app.get("/metrics")
async def prometheus_metrics(request: Request):
    """Prometheus text exposition. Requires the admin session unless METRICS_TOKEN is set."""
    tok = os.environ.get("METRICS_TOKEN", "")
    auth = request.headers.get("authorization", "")
    if tok:
        if not (auth.lower().startswith("bearer ") and hmac.compare_digest(auth[7:].strip(), tok)):
            raise HTTPException(401, "unauthorized")
    elif not authz.permitted(role(request), authz.ADMINISTER):
        raise HTTPException(403, "admin only")
    return Response(metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")
