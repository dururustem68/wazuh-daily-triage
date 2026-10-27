# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Connection test used by the UI button and `python -m app.check`."""
from __future__ import annotations

from .store import now_iso


class DiagnosticsMixin:
    async def check(self, env_id: str, with_llm: bool = True) -> list[dict]:
        """Checks every dependency of one environment; used by the UI button and `python -m app.check`."""
        rt = self.get(env_id)
        env = rt.env
        out: list[dict] = []

        async def step(key, coro):
            try:
                detail = await coro
                out.append({"key": key, "ok": True, "detail": detail})
            except Exception as e:  # noqa: BLE001
                out.append({"key": key, "ok": False, "detail": f"{type(e).__name__}: {e}"})

        async def indexer():
            h = await rt.ix.cluster_health()
            return f"{env.indexer.url} — cluster {h.get('cluster_name', '?')} status {h.get('status')}"

        async def alerts():
            n = await rt.ix.count(env.alerts_index, {"range": {"timestamp": {"gte": "now-24h"}}})
            if n == 0:
                raise RuntimeError(f"0 alerts in `{env.alerts_index}` — wrong index pattern or no read permission?")
            return f"{n:,} in `{env.alerts_index}`"

        async def vulns():
            n = await rt.ix.count(env.vuln_index, {"match_all": {}})
            return f"{n:,} documents in `{env.vuln_index}`" + (" (empty or not readable — optional)" if n == 0 else "")

        async def storage():
            await rt.store.ensure()
            probe = f"_probe_{env.id}"
            await rt.store.put("knowledge", probe, {"id": probe, "env": "__meta__", "kind": "probe",
                                                    "status": "closed", "title": "probe", "created_at": now_iso(),
                                                    "updated_at": now_iso()})
            await rt.store.delete("knowledge", probe)
            return f"`{env.storage_prefix}-*`"

        async def api():
            if not rt.api:
                return "not configured (optional: agent/manager health and logtest disabled)"
            info = await rt.api.info()
            return f"{env.api.url} — Wazuh {info.get('api_version')}"

        async def llm():
            cfg = self.llm_cfg(env)
            r = await self.llm_for(env).complete("Reply with the single word OK.",
                                                 [{"role": "user", "content": "ping"}], [])
            return f"{cfg.provider} {cfg.model or ''} → {r.text[:40]!r}"

        await step("indexer", indexer())
        await step("alerts", alerts())
        await step("vulns", vulns())
        await step("storage", storage())
        await step("api", api())
        src = rt.sources
        if src.get("prometheus"):
            async def prom():
                r = await src["prometheus"].query("count(up == 1)")
                return f"{src['prometheus'].c.base_url} — {r['series'][0]['value'] if r['series'] else 0} targets up"
            await step("prometheus", prom())
        if src.get("loki"):
            async def loki():
                return f"{src['loki'].c.base_url} — {len(await src['loki'].labels())} labels"
            await step("loki", loki())
        if env.sources.kubernetes.enabled:
            async def k8s():
                if not src.get("kubernetes"):
                    raise RuntimeError("Kubernetes source could not start (see the log)")
                r = await src["kubernetes"].get("nodes", limit=50)
                return f"{r['count']} nodes, " + f"{sum(1 for n in r['items'] if n.get('ready') == 'True')} ready"
            await step("kubernetes", k8s())
        if with_llm:
            await step("llm", llm())
        return out
