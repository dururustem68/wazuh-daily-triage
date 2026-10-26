# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Read-only clients for data sources next to Wazuh: Prometheus, Loki, Kubernetes.

Everything here is GET-only. Kubernetes access is limited to an allow-list of kinds (no secrets, no configmaps)
and, optionally, namespaces. Results are compacted before they reach the model.
"""
from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from .collector import _parse
from .config import KubernetesSource, SourceEndpoint

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class SourceError(RuntimeError):
    pass


def _ts(v: str | None, default: float) -> float:
    """ISO-8601, 'now', 'now-2h' or epoch seconds → epoch seconds."""
    if not v or v == "now":
        return default
    if v.startswith("now-"):
        n, u = int(v[4:-1]), v[-1]
        return default - n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[u]
    try:
        return float(v)
    except ValueError:
        return _parse(v).timestamp()


def _client(ep: SourceEndpoint, transport=None) -> httpx.AsyncClient:
    h = {}
    if ep.bearer_token:
        h["Authorization"] = f"Bearer {ep.bearer_token}"
    if ep.org_id:
        h["X-Scope-OrgID"] = ep.org_id
    return httpx.AsyncClient(base_url=ep.url.rstrip("/"), headers=h, verify=ep.verify, timeout=ep.timeout,
                             auth=(ep.username, ep.password) if ep.username else None, transport=transport)


async def _get(c: httpx.AsyncClient, path: str, params: dict | None = None) -> Any:
    try:
        r = await c.get(path, params=params)
    except httpx.HTTPError as e:
        raise SourceError(f"cannot reach {c.base_url}: {e}") from e
    if r.status_code >= 400:
        raise SourceError(f"{r.status_code} {path}: {r.text[:300]}")
    return r.json()


# ------------------------------------------------------------------ Prometheus
class Prometheus:
    def __init__(self, ep: SourceEndpoint, transport=None):
        self.c = _client(ep, transport)

    async def close(self):
        await self.c.aclose()

    async def query(self, expr: str, at: str | None = None) -> dict:
        now = time.time()
        d = await _get(self.c, "/api/v1/query", {"query": expr, "time": _ts(at, now)})
        res = d.get("data", {}).get("result", [])
        return {"type": d.get("data", {}).get("resultType"), "series": [
            {"labels": x.get("metric", {}), "value": (x.get("value") or [None, None])[1]} for x in res[:60]],
            "total_series": len(res)}

    async def query_range(self, expr: str, start: str | None, end: str | None, step: str | None) -> dict:
        now = time.time()
        e = _ts(end, now)
        s = _ts(start, e - 6 * 3600)
        st = step or f"{max(60, int((e - s) / 60))}s"
        d = await _get(self.c, "/api/v1/query_range", {"query": expr, "start": s, "end": e, "step": st})
        res = d.get("data", {}).get("result", [])
        out = []
        for x in res[:20]:
            vals = [float(v[1]) for v in x.get("values", []) if v[1] not in ("NaN", "+Inf", "-Inf")]
            pts = x.get("values", [])
            out.append({"labels": x.get("metric", {}),
                        "min": min(vals) if vals else None, "max": max(vals) if vals else None,
                        "last": vals[-1] if vals else None,
                        # at most 60 points, evenly sampled
                        "points": [[datetime.fromtimestamp(float(p[0]), UTC).strftime("%m-%d %H:%M"), p[1]]
                                   for p in pts[:: max(1, -(-len(pts) // 60))]]})
        return {"step": st, "series": out, "total_series": len(res)}


# ------------------------------------------------------------------ Loki
class Loki:
    def __init__(self, ep: SourceEndpoint, transport=None):
        self.c = _client(ep, transport)

    async def close(self):
        await self.c.aclose()

    async def query(self, logql: str, start: str | None, end: str | None, limit: int = 100,
                    direction: str = "backward") -> dict:
        now = time.time()
        e = _ts(end, now)
        s = _ts(start, e - 3600)
        d = await _get(self.c, "/loki/api/v1/query_range", {
            "query": logql, "start": int(s * 1e9), "end": int(e * 1e9),
            "limit": max(1, min(int(limit or 100), 500)), "direction": direction})
        data = d.get("data", {})
        if data.get("resultType") == "matrix":  # metric query (count_over_time …)
            return {"type": "matrix", "series": [
                {"labels": x.get("metric", {}), "points": [[datetime.fromtimestamp(float(p[0]), UTC).strftime(
                    "%m-%d %H:%M"), p[1]] for p in x.get("values", [])[:120]]} for x in data.get("result", [])[:20]]}
        lines = []
        for st in data.get("result", []):
            lab = st.get("stream", {})
            short = {k: lab[k] for k in ("namespace", "pod", "container", "app", "job", "host", "node_name",
                                         "unit", "filename") if k in lab}
            for ts, line in st.get("values", []):
                lines.append({"t": datetime.fromtimestamp(int(ts) / 1e9, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              "labels": short, "line": line[:600]})
        lines.sort(key=lambda x: x["t"], reverse=direction == "backward")
        return {"type": "streams", "lines": lines[:limit], "count": len(lines)}

    async def labels(self, name: str | None = None) -> list[str]:
        d = await _get(self.c, f"/loki/api/v1/label/{name}/values" if name else "/loki/api/v1/labels")
        return (d.get("data") or [])[:300]


# ------------------------------------------------------------------ Kubernetes
KINDS = {
    "pods": ("/api/v1", True), "nodes": ("/api/v1", False), "events": ("/api/v1", True),
    "services": ("/api/v1", True), "namespaces": ("/api/v1", False),
    "persistentvolumeclaims": ("/api/v1", True),
    "deployments": ("/apis/apps/v1", True), "statefulsets": ("/apis/apps/v1", True),
    "daemonsets": ("/apis/apps/v1", True), "replicasets": ("/apis/apps/v1", True),
    "jobs": ("/apis/batch/v1", True), "cronjobs": ("/apis/batch/v1", True),
    "ingresses": ("/apis/networking.k8s.io/v1", True),
}


class Kubernetes:
    def __init__(self, cfg: KubernetesSource, transport=None):
        self.cfg = cfg
        if cfg.in_cluster:
            host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            if not host:
                raise SourceError("not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set)")
            base = f"https://{host}:{port}"
            with open(f"{SA_DIR}/token", encoding="utf-8") as f:
                token = f.read().strip()
            verify: Any = f"{SA_DIR}/ca.crt"
        else:
            base, token, verify = cfg.api_url, cfg.token, cfg.ca_file or cfg.verify_tls
        self.c = httpx.AsyncClient(base_url=base.rstrip("/"), headers={"Authorization": f"Bearer {token}"},
                                   verify=verify, timeout=30, transport=transport)

    async def close(self):
        await self.c.aclose()

    def _ns_ok(self, ns: str | None):
        if ns and self.cfg.namespaces and ns not in self.cfg.namespaces:
            raise SourceError(f"namespace {ns} is not in the allow-list {self.cfg.namespaces}")

    async def get(self, kind: str, namespace: str | None = None, name: str | None = None,
                  label_selector: str | None = None, field_selector: str | None = None, limit: int = 200) -> dict:
        kind = kind.lower()
        if kind not in KINDS:
            raise SourceError(f"kind {kind!r} is not allowed; allowed: {', '.join(KINDS)}")
        prefix, namespaced = KINDS[kind]
        self._ns_ok(namespace)
        if namespaced and namespace:
            path = f"{prefix}/namespaces/{namespace}/{kind}"
        else:
            path = f"{prefix}/{kind}"
        if name:
            if namespaced and not namespace:
                raise SourceError("namespace is required with name")
            path += f"/{name}"
        params = {"limit": min(int(limit or 200), 500)}
        if label_selector:
            params["labelSelector"] = label_selector
        if field_selector:
            params["fieldSelector"] = field_selector
        d = await _get(self.c, path, None if name else params)
        items = [d] if name else d.get("items", [])
        if self.cfg.namespaces and not namespace and namespaced:
            items = [i for i in items if i.get("metadata", {}).get("namespace") in self.cfg.namespaces]
        out = [_compact(kind, i) for i in items]
        if kind == "events":
            out.sort(key=lambda e: e.get("last") or "", reverse=True)
        return {"kind": kind, "count": len(out), "items": out[:150]}

    async def logs(self, namespace: str, pod: str, container: str | None = None, tail: int = 200,
                   previous: bool = False, since_seconds: int | None = None) -> dict:
        if not self.cfg.pod_logs:
            raise SourceError("pod logs are disabled (sources.kubernetes.pod_logs: false)")
        self._ns_ok(namespace)
        params: dict[str, Any] = {"tailLines": max(1, min(int(tail or 200), 1000)), "timestamps": "true"}
        if container:
            params["container"] = container
        if previous:
            params["previous"] = "true"
        if since_seconds:
            params["sinceSeconds"] = int(since_seconds)
        try:
            r = await self.c.get(f"/api/v1/namespaces/{namespace}/pods/{pod}/log", params=params)
        except httpx.HTTPError as e:
            raise SourceError(str(e)) from e
        if r.status_code >= 400:
            raise SourceError(f"{r.status_code}: {r.text[:300]}")
        lines = r.text.splitlines()
        return {"pod": pod, "lines": [x[:600] for x in lines[-1000:]], "count": len(lines)}


def _compact(kind: str, o: dict) -> dict:
    m, sp, st = o.get("metadata", {}), o.get("spec", {}), o.get("status", {})
    base = {"name": m.get("name"), **({"namespace": m["namespace"]} if m.get("namespace") else {}),
            "created": m.get("creationTimestamp")}
    if kind == "pods":
        cs = st.get("containerStatuses") or []
        last = []
        for c in cs:
            lt = (c.get("lastState") or {}).get("terminated")
            if lt:
                last.append({"container": c.get("name"), "reason": lt.get("reason"), "exit": lt.get("exitCode"),
                             "at": lt.get("finishedAt")})
        waiting = [{"container": c.get("name"), "reason": (c.get("state") or {}).get("waiting", {}).get("reason")}
                   for c in cs if (c.get("state") or {}).get("waiting")]
        return {**base, "phase": st.get("phase"), "node": sp.get("nodeName"),
                "ready": f"{sum(1 for c in cs if c.get('ready'))}/{len(cs)}",
                "restarts": sum(int(c.get("restartCount") or 0) for c in cs),
                "started": st.get("startTime"), "last_termination": last, "waiting": waiting,
                "images": sorted({c.get("image") for c in sp.get("containers", [])})}
    if kind == "nodes":
        conds = {c["type"]: c["status"] for c in st.get("conditions", [])}
        info = st.get("nodeInfo", {})
        return {**base, "ready": conds.get("Ready"), "pressure": [k for k, v in conds.items() if k != "Ready" and v == "True"],
                "kubelet": info.get("kubeletVersion"), "kernel": info.get("kernelVersion"), "os": info.get("osImage"),
                "unschedulable": sp.get("unschedulable", False),
                "taints": [t.get("key") for t in sp.get("taints", [])]}
    if kind == "events":
        io = o.get("involvedObject", {})
        return {"namespace": m.get("namespace"), "type": o.get("type"), "reason": o.get("reason"),
                "object": f"{io.get('kind')}/{io.get('name')}", "message": (o.get("message") or "")[:400],
                "count": o.get("count") or (o.get("series") or {}).get("count") or 1,
                "first": o.get("firstTimestamp") or o.get("eventTime"),
                "last": o.get("lastTimestamp") or (o.get("series") or {}).get("lastObservedTime") or o.get("eventTime")}
    if kind in ("deployments", "statefulsets", "daemonsets", "replicasets"):
        return {**base, "replicas": sp.get("replicas", st.get("desiredNumberScheduled")),
                "ready": st.get("readyReplicas", st.get("numberReady")),
                "updated": st.get("updatedReplicas", st.get("updatedNumberScheduled")),
                "available": st.get("availableReplicas", st.get("numberAvailable")),
                "revision": {"current": st.get("currentRevision"), "update": st.get("updateRevision")}
                if kind == "statefulsets" else None,
                "images": sorted({c.get("image") for c in sp.get("template", {}).get("spec", {}).get("containers", [])})}
    if kind in ("jobs", "cronjobs"):
        return {**base, "schedule": sp.get("schedule"), "suspend": sp.get("suspend"),
                "succeeded": st.get("succeeded"), "failed": st.get("failed"),
                "last_schedule": st.get("lastScheduleTime"), "last_success": st.get("lastSuccessfulTime"),
                "completion": st.get("completionTime")}
    if kind == "persistentvolumeclaims":
        return {**base, "phase": st.get("phase"), "capacity": (st.get("capacity") or {}).get("storage"),
                "storage_class": sp.get("storageClassName")}
    if kind == "ingresses":
        return {**base, "class": sp.get("ingressClassName"),
                "hosts": [r.get("host") for r in sp.get("rules", [])]}
    if kind == "services":
        return {**base, "type": sp.get("type"), "ports": [p.get("port") for p in sp.get("ports", [])]}
    return base
