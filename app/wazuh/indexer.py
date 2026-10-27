# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Wazuh Indexer (OpenSearch) client — HTTPS with basic auth and/or client certificate."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from ..config import Endpoint


class IndexerError(RuntimeError):
    pass


class Indexer:
    def __init__(self, ep: Endpoint, transport: httpx.AsyncBaseTransport | None = None, limits=None):
        self.ep = ep
        self.limits = limits
        # a hard ceiling on parallel queries keeps one runaway agent loop from saturating the cluster
        self._sem = asyncio.Semaphore(int(getattr(limits, "max_concurrent", 8) or 8))
        self._timeout = float(getattr(limits, "request_timeout", None) or ep.timeout)
        self._client = httpx.AsyncClient(
            base_url=ep.url.rstrip("/"),
            auth=(ep.username, ep.password) if ep.username else None,
            verify=ep.verify,
            cert=ep.cert,
            timeout=httpx.Timeout(self._timeout, connect=min(10.0, self._timeout)),
            transport=transport,
            headers={"Content-Type": "application/json"},
        )

    async def close(self):
        await self._client.aclose()

    async def request(self, method: str, path: str, body: Any = None, params: dict | None = None,
                      ok_404: bool = False) -> Any:
        try:
            async with self._sem:
                r = await self._client.request(
                    method, path, params=params,
                    content=json.dumps(body) if body is not None else None,
                )
        except httpx.TimeoutException as e:
            raise IndexerError(f"indexer query timed out after {self._timeout:.0f}s ({self.ep.url})") from e
        except httpx.HTTPError as e:
            raise IndexerError(f"cannot reach indexer ({self.ep.url}): {e}") from e
        if r.status_code == 404 and ok_404:
            return None
        if r.status_code in (401, 403):
            raise IndexerError(f"indexer authorization error {r.status_code} {path}: {r.text[:300]}")
        if r.status_code == 429:
            raise IndexerError(f"indexer rejected the query (429, too many requests): {r.text[:300]}")
        if r.status_code >= 400:
            raise IndexerError(f"indexer {r.status_code} {method} {path}: {r.text[:500]}")
        return r.json() if r.content else None

    async def search(self, index: str, body: dict) -> dict:
        body.setdefault("track_total_hits", True)
        r = await self.request("POST", f"/{index}/_search", body,
                               params={"ignore_unavailable": "true", "allow_no_indices": "true"})
        # with no matching index OpenSearch omits "aggregations" entirely; return an empty skeleton
        if body.get("aggs") and "aggregations" not in r:
            r["aggregations"] = {n: _empty_agg(spec) for n, spec in body["aggs"].items()}
        return r

    async def count(self, index: str, query: dict) -> int:
        r = await self.request("POST", f"/{index}/_count", {"query": query},
                               params={"ignore_unavailable": "true", "allow_no_indices": "true"})
        return int(r.get("count", 0))

    async def cluster_health(self) -> dict:
        return await self.request("GET", "/_cluster/health")

    async def allocation(self) -> list:
        return await self.request("GET", "/_cat/allocation", params={"format": "json", "bytes": "b"})

    async def index_exists(self, index: str) -> bool:
        try:
            r = await self._client.head(f"/{index}")
        except httpx.HTTPError as e:
            raise IndexerError(str(e)) from e
        return r.status_code == 200

    async def create_index(self, index: str, body: dict):
        try:
            return await self.request("PUT", f"/{index}", body)
        except IndexerError as e:
            if "resource_already_exists" in str(e):
                return None
            raise

    async def put_doc(self, index: str, doc_id: str, doc: dict, refresh: bool = True):
        return await self.request("PUT", f"/{index}/_doc/{doc_id}", doc,
                                  params={"refresh": "true" if refresh else "false"})

    async def get_doc(self, index: str, doc_id: str) -> dict | None:
        r = await self.request("GET", f"/{index}/_doc/{doc_id}", ok_404=True)
        if not r or not r.get("found"):
            return None
        return r["_source"]

    async def delete_by_query(self, index: str, query: dict) -> int:
        r = await self.request("POST", f"/{index}/_delete_by_query", {"query": query},
                               params={"ignore_unavailable": "true", "allow_no_indices": "true",
                                       "refresh": "true"})
        return int((r or {}).get("deleted", 0))

    async def delete_doc(self, index: str, doc_id: str):
        return await self.request("DELETE", f"/{index}/_doc/{doc_id}", params={"refresh": "true"}, ok_404=True)


def _empty_agg(spec: dict) -> dict:
    sub = spec.get("aggs") or {}
    return {"buckets": [], "value": None, "doc_count": 0, "sum_other_doc_count": 0,
            "hits": {"total": {"value": 0}, "hits": []}, **{n: _empty_agg(s) for n, s in sub.items()}}
