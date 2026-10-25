# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Wazuh server REST API (55000) client — JWT auth, read-only endpoints plus logtest."""
from __future__ import annotations

import time
from typing import Any

import httpx

from ..config import Endpoint


class WazuhAPIError(RuntimeError):
    pass


class WazuhAPI:
    def __init__(self, ep: Endpoint, transport: httpx.AsyncBaseTransport | None = None):
        self.ep = ep
        self._client = httpx.AsyncClient(base_url=ep.url.rstrip("/"), verify=ep.verify,
                                         cert=ep.cert, timeout=ep.timeout, transport=transport)
        self._token: str | None = None
        self._token_ts = 0.0

    async def close(self):
        await self._client.aclose()

    async def _auth(self):
        # Wazuh tokens are valid for 900 s by default; refresh after 600 s.
        if self._token and time.time() - self._token_ts < 600:
            return
        try:
            r = await self._client.post("/security/user/authenticate",
                                        auth=(self.ep.username, self.ep.password))
        except httpx.HTTPError as e:
            raise WazuhAPIError(f"cannot reach Wazuh API ({self.ep.url}): {e}") from e
        if r.status_code != 200:
            raise WazuhAPIError(f"Wazuh API authentication failed {r.status_code}: {r.text[:300]}")
        self._token = r.json()["data"]["token"]
        self._token_ts = time.time()

    async def request(self, method: str, path: str, params: dict | None = None, json: Any = None) -> dict:
        await self._auth()
        for attempt in (1, 2):
            try:
                r = await self._client.request(method, path, params=params, json=json,
                                               headers={"Authorization": f"Bearer {self._token}"})
            except httpx.HTTPError as e:
                raise WazuhAPIError(f"Wazuh API error {path}: {e}") from e
            if r.status_code == 401 and attempt == 1:
                self._token = None
                await self._auth()
                continue
            break
        if r.status_code >= 400:
            raise WazuhAPIError(f"Wazuh API {r.status_code} {method} {path}: {r.text[:400]}")
        return r.json()

    async def get(self, path: str, **params) -> dict:
        return await self.request("GET", path, params={k: v for k, v in params.items() if v is not None})

    # --- high level helpers ------------------------------------------------
    async def info(self) -> dict:
        return (await self.get("/"))["data"]

    async def manager_status(self) -> dict:
        return (await self.get("/manager/status"))["data"]["affected_items"][0]

    async def cluster_health(self) -> dict | None:
        try:
            st = (await self.get("/cluster/status"))["data"]
        except WazuhAPIError:
            return None
        if st.get("enabled") != "yes" or st.get("running") != "yes":
            return {"enabled": st.get("enabled"), "running": st.get("running")}
        hc = (await self.get("/cluster/healthcheck"))["data"]["affected_items"]
        nodes = {}
        for n in hc:
            info = n.get("info", {})
            nodes[info.get("name")] = {
                "type": info.get("type"), "version": info.get("version"),
                "n_active_agents": info.get("n_active_agents"),
            }
        return {"enabled": "yes", "running": "yes", "nodes": nodes}

    async def agents_summary(self) -> dict:
        return (await self.get("/agents/summary/status"))["data"]

    async def agents(self, status: str | None = None, search: str | None = None, limit: int = 100) -> list[dict]:
        r = await self.get("/agents", status=status, search=search, limit=limit,
                           select="id,name,ip,status,version,lastKeepAlive,os.name,os.version,group,node_name")
        return r["data"]["affected_items"]

    async def manager_errors(self, limit: int = 30) -> list[dict]:
        r = await self.get("/manager/logs", level="error", limit=limit, sort="-timestamp")
        return r["data"]["affected_items"]

    async def rules(self, rule_ids: list[str]) -> list[dict]:
        r = await self.get("/rules", rule_ids=",".join(rule_ids), limit=len(rule_ids) or 1)
        return r["data"]["affected_items"]

    async def logtest(self, event: str, log_format: str = "syslog", location: str = "daily-triage") -> dict:
        r = await self.request("PUT", "/logtest", json={"event": event, "log_format": log_format,
                                                         "location": location})
        data = r.get("data", {})
        tok = data.get("token")
        if tok:  # close the session so the single-threaded logtest server is not held
            try:
                await self.request("DELETE", f"/logtest/sessions/{tok}")
            except WazuhAPIError:
                pass
        return data
