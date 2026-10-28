# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Daily data collection: deterministic queries → compact summary dict.

The LLM receives this summary, not raw alerts. Each section catches its own
errors; a failed section shows up in the report as a blind spot instead of
aborting the run.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Environment
from .i18n import t
from .wazuh.api import WazuhAPI
from .wazuh.indexer import Indexer

TS = "timestamp"


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rng(frm: datetime | str, to: datetime | str) -> dict:
    f = iso(frm) if isinstance(frm, datetime) else frm
    t = iso(to) if isinstance(to, datetime) else to
    return {"range": {TS: {"gte": f, "lt": t}}}


def _b(agg: dict) -> list[dict]:
    return agg.get("buckets", []) if agg else []


class Collector:
    def __init__(self, env: Environment, indexer: Indexer, api: WazuhAPI | None, lang: str = "en",
                 inventory: list[str] | None = None):
        self.env = env
        self.inventory = inventory or []
        self.lang = lang
        self.ix = indexer
        self.api = api
        self.errors: list[str] = []

    async def _safe(self, name: str, coro):
        try:
            return await coro
        except Exception as e:  # noqa: BLE001 — sections are independent
            self.errors.append(f"{name}: {e}")
            return None

    async def collect(self, frm: datetime, to: datetime) -> dict[str, Any]:
        hours = max(1, round((to - frm).total_seconds() / 3600))
        prev_frm = frm - (to - frm)
        tasks = {
            "health": self._health(to),
            "volume": self._volume(frm, to, hours),
            "top_rules": self._top_rules(frm, to, prev_frm),
            "high_level": self._high_level(frm, to),
            "agents": self._agents_alerts(frm, to, prev_frm),
            "new_rules": self._new_rules(frm, to),
            "groups": self._groups(frm, to),
            "srcips": self._srcips(frm, to),
            "watch": self._watch(frm, to),
            "vulnerabilities": self._vulns(to),
        }
        if self.env.mail:
            tasks["mail_pressure"] = self._mail_pressure(frm, to)
        if self.env.anomaly:
            tasks["anomalies"] = self._anomalies(frm, to)
        if self.api:
            tasks["coverage"] = self._coverage(to)
        pv = self.env.privacy
        if pv.detect and pv.detect_sample:
            tasks["personal_data"] = self._personal_data(frm, to, pv.detect_sample)
        res = await asyncio.gather(*(self._safe(k, v) for k, v in tasks.items()))
        out = dict(zip(tasks.keys(), res, strict=True))
        out["window"] = {"from": iso(frm), "to": iso(to), "hours": hours}
        out["env"] = {"id": self.env.id, "name": self.env.name, "high_level": self.env.high_level}
        out["flags"] = self._flags(out)
        out["errors"] = self.errors
        return out

    # ------------------------------------------------------------------ health
    async def _health(self, now: datetime) -> dict:
        h: dict[str, Any] = {}
        ch = await self._safe("indexer_health", self.ix.cluster_health())
        if ch:
            h["indexer"] = {k: ch.get(k) for k in ("status", "number_of_nodes", "active_shards",
                                                     "unassigned_shards", "active_shards_percent_as_number")}
        alloc = await self._safe("indexer_disk", self.ix.allocation())
        if alloc:
            h["indexer_disk"] = [
                {"node": a.get("node"), "percent": _int(a.get("disk.percent")),
                 "shards": _int(a.get("shards"))} for a in alloc if a.get("node")
            ]
        last = await self._safe("last_alert", self.ix.search(self.env.alerts_index, {
            "size": 1, "sort": [{TS: "desc"}], "_source": [TS, "manager.name", "agent.name"],
            "query": {"range": {TS: {"gte": "now-7d", "lte": "now+5m"}}},
        }))
        if last is not None:
            hits = last["hits"]["hits"]
            if hits:
                ts = hits[0]["_source"][TS]
                h["last_alert"] = ts
                h["silence_minutes"] = round((now - _parse(ts)).total_seconds() / 60)
            else:
                h["last_alert"] = None
                h["silence_minutes"] = None
        # which manager nodes produced alerts recently
        mgr = await self._safe("alert_managers", self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"range": {TS: {"gte": "now-2h"}}},
            "aggs": {"m": {"terms": {"field": "manager.name", "size": 10},
                           "aggs": {"last": {"max": {"field": TS}}}}},
        }))
        if mgr:
            h["managers_last_2h"] = [{"manager": b["key"], "count": b["doc_count"],
                                      "last": b["last"].get("value_as_string")}
                                     for b in _b(mgr["aggregations"]["m"])]
        if self.api:
            info = await self._safe("api_info", self.api.info())
            if info:
                h["api_version"] = info.get("api_version")
            cl = await self._safe("cluster", self.api.cluster_health())
            if cl:
                h["cluster"] = cl
            ms = await self._safe("manager_status", self.api.manager_status())
            if ms:
                h["daemons_not_running"] = sorted(k for k in self.env.required_daemons if ms.get(k, "running") != "running")
                h["daemons_stopped_optional"] = sorted(k for k, v in ms.items()
                                                       if v != "running" and k not in self.env.required_daemons)
            sm = await self._safe("agents_summary", self.api.agents_summary())
            if sm:
                h["agents_summary"] = sm.get("connection", sm)
            bad = await self._safe("agents_bad", self.api.agents(status="disconnected,never_connected,pending"))
            if bad is not None:
                h["agents_not_active"] = [
                    {"id": a.get("id"), "name": a.get("name"), "status": a.get("status"),
                     "lastKeepAlive": a.get("lastKeepAlive"), "version": a.get("version")}
                    for a in bad if a.get("id") != "000"
                ]
            errs = await self._safe("manager_errors", self.api.manager_errors(limit=40))
            if errs is not None:
                # group identical messages
                agg: dict[str, dict] = {}
                for e in errs:
                    key = (e.get("tag", ""), (e.get("description") or "")[:160])
                    d = agg.setdefault("|".join(key), {"tag": key[0], "msg": key[1], "count": 0,
                                                        "last": e.get("timestamp")})
                    d["count"] += 1
                h["manager_errors"] = list(agg.values())[:15]
        return h

    # ------------------------------------------------------------------ liveness (every few minutes)
    async def liveness(self, now: datetime, silence_minutes: int) -> dict[str, str]:
        """Critical problems only, as {code: message}. Cheap: a few small queries, no aggregations."""
        L, p = self.lang, {}
        try:
            ch = await self.ix.cluster_health()
            if ch.get("status") == "red":
                p["indexer_status"] = t(L, "flag.indexer_status", s="red")
        except Exception as e:  # noqa: BLE001
            p["indexer_down"] = t(L, "live.indexer_down", e=str(e)[:160])
            return p  # nothing else can be checked through the indexer
        try:
            for a in await self.ix.allocation() or []:
                pc = _int(a.get("disk.percent"))
                if a.get("node") and pc is not None and pc >= 90:
                    p[f"indexer_disk:{a['node']}"] = t(L, "flag.indexer_disk", node=a["node"], p=pc)
        except Exception:  # noqa: BLE001
            pass
        try:
            last = await self.ix.search(self.env.alerts_index, {
                "size": 1, "sort": [{TS: "desc"}], "_source": [TS],
                "query": {"range": {TS: {"gte": "now-7d", "lte": "now+5m"}}}})
            hits = last["hits"]["hits"]
            if not hits:
                p["silence"] = t(L, "flag.no_alerts_7d")
            else:
                sil = round((now - _parse(hits[0]["_source"][TS])).total_seconds() / 60)
                if sil > silence_minutes:
                    p["silence"] = t(L, "flag.silence", m=sil, t=silence_minutes)
        except Exception as e:  # noqa: BLE001
            p["alerts_query"] = t(L, "live.query_failed", e=str(e)[:160])
        if self.api:
            try:
                ms = await self.api.manager_status()
                down = sorted(k for k in self.env.required_daemons if ms.get(k, "running") != "running")
                if down:
                    p["daemons"] = t(L, "flag.daemons", d=", ".join(down))
            except Exception as e:  # noqa: BLE001
                p["api_down"] = t(L, "live.api_down", e=str(e)[:160])
            try:
                cl = await self.api.cluster_health()
                if cl and cl.get("enabled") == "yes" and cl.get("running") != "yes":
                    p["cluster"] = t(L, "flag.cluster")
            except Exception:  # noqa: BLE001
                pass
        return p

    # ------------------------------------------------------------------ volume
    async def _volume(self, frm, to, hours) -> dict:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": rng(frm, to),
            "aggs": {
                "levels": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
                "hourly": {"date_histogram": {"field": TS, "fixed_interval": "1h", "min_doc_count": 0,
                                              "extended_bounds": {"min": iso(frm), "max": iso(to - timedelta(seconds=1))}}},
                "managers": {"terms": {"field": "manager.name", "size": 10}},
            },
        })
        total = r["hits"]["total"]["value"]
        levels = {str(b["key"]): b["doc_count"] for b in _b(r["aggregations"]["levels"])}
        hourly = [{"t": b["key_as_string"], "n": b["doc_count"]} for b in _b(r["aggregations"]["hourly"])]
        high = sum(v for k, v in levels.items() if int(k) >= self.env.high_level)
        empty = [h["t"] for h in hourly if h["n"] == 0]
        return {
            "total": total, "levels": levels, "high_level_total": high,
            "high_level_ratio_permille": round(high * 1000 / total, 2) if total else 0,
            "hourly": hourly, "empty_hours": empty,
            "per_manager": {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["managers"])},
        }

    # ------------------------------------------------------------------ rules
    async def _top_rules(self, frm, to, prev_frm) -> list[dict]:
        aggs = {"r": {"terms": {"field": "rule.id", "size": 40},
                      "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                               "l": {"max": {"field": "rule.level"}},
                               "a": {"terms": {"field": "agent.name", "size": 4}}}}}
        cur, prev = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": aggs}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(prev_frm, frm),
                                                  "aggs": {"r": {"terms": {"field": "rule.id", "size": 500}}}}),
        )
        prevm = {b["key"]: b["doc_count"] for b in _b(prev["aggregations"]["r"])}
        out = []
        for b in _b(cur["aggregations"]["r"]):
            d = _b(b["d"])
            out.append({
                "id": b["key"], "count": b["doc_count"], "prev": prevm.get(b["key"], 0),
                "level": int(b["l"]["value"] or 0), "desc": d[0]["key"] if d else "",
                "agents": {a["key"]: a["doc_count"] for a in _b(b["a"])},
            })
        return out

    async def _high_level(self, frm, to) -> list[dict]:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0,
            "query": {"bool": {"filter": [rng(frm, to), {"range": {"rule.level": {"gte": self.env.high_level}}}]}},
            "aggs": {"r": {"terms": {"field": "rule.id", "size": 60},
                           "aggs": {
                               "d": {"terms": {"field": "rule.description", "size": 1}},
                               "l": {"max": {"field": "rule.level"}},
                               "a": {"terms": {"field": "agent.name", "size": 8},
                                     "aggs": {"first": {"min": {"field": TS}}, "last": {"max": {"field": TS}}}},
                               "ip": {"terms": {"field": "data.srcip", "size": 5}},
                               "s": {"top_hits": {"size": 1, "sort": [{TS: "desc"}],
                                                  "_source": ["full_log", "data.url", "data.srcip", "data.srcuser",
                                                              "data.dstuser", "syscheck.path", "data.verb",
                                                              "data.objectRef", "data.user.username",
                                                              "data.vulnerability.cve", "location"]}},
                           }}},
        })
        out = []
        for b in _b(r["aggregations"]["r"]):
            d = _b(b["d"])
            hit = b["s"]["hits"]["hits"]
            sample = hit[0]["_source"] if hit else {}
            if "full_log" in sample:
                sample["full_log"] = sample["full_log"][:400]
            out.append({
                "id": b["key"], "count": b["doc_count"], "level": int(b["l"]["value"] or 0),
                "desc": d[0]["key"] if d else "",
                "agents": [{"name": a["key"], "n": a["doc_count"],
                            "first": a["first"].get("value_as_string"), "last": a["last"].get("value_as_string")}
                           for a in _b(b["a"])],
                "srcips": {i["key"]: i["doc_count"] for i in _b(b["ip"])},
                "sample": sample,
            })
        return out

    async def _agents_alerts(self, frm, to, prev_frm) -> list[dict]:
        a = {"a": {"terms": {"field": "agent.name", "size": 60},
                   "aggs": {"hi": {"filter": {"range": {"rule.level": {"gte": self.env.high_level}}}}}}}
        cur, prev = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": a}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(prev_frm, frm),
                                                  "aggs": {"a": {"terms": {"field": "agent.name", "size": 200}}}}),
        )
        pm = {b["key"]: b["doc_count"] for b in _b(prev["aggregations"]["a"])}
        return [{"agent": b["key"], "count": b["doc_count"], "prev": pm.get(b["key"], 0),
                 "high": b["hi"]["doc_count"]} for b in _b(cur["aggregations"]["a"])]

    async def _new_rules(self, frm, to) -> list[dict]:
        """Rule IDs seen in the window but not in the preceding 14 days."""
        cur, hist = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to),
                           "aggs": {"r": {"terms": {"field": "rule.id", "size": 2000},
                                          "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                                   "l": {"max": {"field": "rule.level"}}}}}}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm - timedelta(days=14), frm),
                           "aggs": {"r": {"terms": {"field": "rule.id", "size": 5000}}}}),
        )
        seen = {b["key"] for b in _b(hist["aggregations"]["r"])}
        out = []
        for b in _b(cur["aggregations"]["r"]):
            if b["key"] not in seen:
                d = _b(b["d"])
                out.append({"id": b["key"], "count": b["doc_count"], "level": int(b["l"]["value"] or 0),
                            "desc": d[0]["key"] if d else ""})
        return sorted(out, key=lambda x: (-x["level"], -x["count"]))[:40]

    async def _groups(self, frm, to) -> dict:
        r = await self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to),
                                 "aggs": {"g": {"terms": {"field": "rule.groups", "size": 50}}}})
        g = {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["g"])}
        if self.env.watch_groups:
            g = {"top": g, "watched": {k: g.get(k, 0) for k in self.env.watch_groups}}
        return g

    async def _srcips(self, frm, to) -> list[dict]:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"exists": {"field": "data.srcip"}}]}},
            "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 15},
                            "aggs": {"r": {"terms": {"field": "rule.id", "size": 3}},
                                     "l": {"max": {"field": "rule.level"}}}}}})
        return [{"ip": b["key"], "count": b["doc_count"], "max_level": int(b["l"]["value"] or 0),
                 "rules": {x["key"]: x["doc_count"] for x in _b(b["r"])}}
                for b in _b(r["aggregations"]["ip"])]

    async def _watch(self, frm, to) -> dict:
        if not self.env.watch_rules:
            return {}
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"terms": {"rule.id": self.env.watch_rules}}]}},
            "aggs": {"r": {"terms": {"field": "rule.id", "size": len(self.env.watch_rules)}}}})
        got = {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["r"])}
        return {rid: got.get(rid, 0) for rid in self.env.watch_rules}

    async def _vulns(self, now: datetime | None = None) -> dict | None:
        now = now or datetime.now(UTC)
        sla = self.env.vuln_sla.days()
        aggs: dict[str, Any] = {
            "sev": {"terms": {"field": "vulnerability.severity", "size": 10}},
            "crit_agents": {"filter": {"term": {"vulnerability.severity": "Critical"}},
                            "aggs": {"a": {"terms": {"field": "agent.name", "size": 15}}}},
            "crit_pkgs": {"filter": {"term": {"vulnerability.severity": "Critical"}},
                          "aggs": {"p": {"terms": {"field": "package.name", "size": 15}}}},
            "dated": {"filter": {"exists": {"field": "vulnerability.detected_at"}}},
        }
        for sev, days in sla.items():  # open longer than the SLA allows
            aggs[f"over_{sev}"] = {
                "filter": {"bool": {"filter": [
                    {"term": {"vulnerability.severity": sev}},
                    {"range": {"vulnerability.detected_at": {"lt": iso(now - timedelta(days=days))}}}]}},
                "aggs": {"a": {"terms": {"field": "agent.name", "size": 10}},
                         "p": {"terms": {"field": "package.name", "size": 8}},
                         "oldest": {"min": {"field": "vulnerability.detected_at"}}}}
        r = await self.ix.search(self.env.vuln_index, {"size": 0, "aggs": aggs})
        if r["hits"]["total"]["value"] == 0:
            return None
        ag = r["aggregations"]
        out = {"severity": {b["key"]: b["doc_count"] for b in _b(ag["sev"])},
               "critical_by_agent": {b["key"]: b["doc_count"] for b in _b(ag["crit_agents"]["a"])},
               "critical_by_package": {b["key"]: b["doc_count"] for b in _b(ag["crit_pkgs"]["p"])}}
        if sla:
            if not ag["dated"]["doc_count"]:
                out["sla"] = {"unavailable": True}
            else:
                out["sla"] = {sev: {"days": days, "overdue": ag[f"over_{sev}"]["doc_count"],
                                    "by_agent": {b["key"]: b["doc_count"] for b in _b(ag[f"over_{sev}"]["a"])},
                                    "by_package": {b["key"]: b["doc_count"] for b in _b(ag[f"over_{sev}"]["p"])},
                                    "oldest": (ag[f"over_{sev}"]["oldest"] or {}).get("value_as_string")}
                              for sev, days in sla.items()}
        return out

    # ------------------------------------------------------------------ anomalies (no AI)
    async def _anomalies(self, frm, to, days: int = 14) -> dict:
        """rule × agent counts in the window vs. the daily mean / spread of the previous `days` days."""
        hours = max(1.0, (to - frm).total_seconds() / 3600)
        b_from = frm - timedelta(days=days)
        pair = {"r": {"terms": {"field": "rule.id", "size": 150},
                      "aggs": {"a": {"terms": {"field": "agent.name", "size": 40}},
                               "d": {"terms": {"field": "rule.description", "size": 1}},
                               "l": {"max": {"field": "rule.level"}}}}}
        cur, base = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": pair}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(b_from, frm), "aggs": {
                "r": {"terms": {"field": "rule.id", "size": 400},
                      "aggs": {"a": {"terms": {"field": "agent.name", "size": 60},
                                     "aggs": {"day": {"date_histogram": {
                                         "field": TS, "fixed_interval": "1d", "min_doc_count": 0,
                                         "extended_bounds": {"min": iso(b_from), "max": iso(frm - timedelta(seconds=1))}}}}}}}}}))
        hist: dict[tuple, list[int]] = {}
        for rb in _b(base["aggregations"]["r"]):
            for ab in _b(rb["a"]):
                days_ = [d["doc_count"] for d in _b(ab["day"])]
                hist[(rb["key"], ab["key"])] = days_[1:-1] if len(days_) > 3 else days_   # edges are partial days
        spikes, new_pairs = [], []
        for rb in _b(cur["aggregations"]["r"]):
            lvl = int(rb["l"]["value"] or 0)
            desc = (_b(rb["d"]) or [{"key": ""}])[0]["key"]
            for ab in _b(rb["a"]):
                n = ab["doc_count"]
                per_day = n * 24 / hours
                h = hist.get((rb["key"], ab["key"]))
                if not h or not any(h):
                    if n >= 5 or lvl >= self.env.high_level:
                        new_pairs.append({"rule": rb["key"], "agent": ab["key"], "count": n, "level": lvl, "desc": desc})
                    continue
                vals = h or [0]
                mean = sum(vals) / len(vals)
                sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
                z = (per_day - mean) / max(sd, 1.0, mean * 0.1)
                if z >= 3 and n >= 20:
                    spikes.append({"rule": rb["key"], "agent": ab["key"], "count": n, "per_day": round(per_day),
                                   "baseline_per_day": round(mean, 1), "z": round(z, 1), "level": lvl, "desc": desc})
        spikes.sort(key=lambda x: (-x["z"]))
        new_pairs.sort(key=lambda x: (-x["level"], -x["count"]))
        return {"baseline_days": days, "spikes": spikes[:25], "new_pairs": new_pairs[:25]}

    # ------------------------------------------------------------------ e-mail channel saturation
    async def _mail_pressure(self, frm, to) -> dict:
        m = self.env.mail
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0,
            "query": {"bool": {"filter": [rng(frm, to), {"range": {"rule.level": {"gte": m.alert_level}}}]}},
            "aggs": {"h": {"date_histogram": {"field": TS, "fixed_interval": "1h", "min_doc_count": 1},
                           "aggs": {"r": {"terms": {"field": "rule.id", "size": 10},
                                          "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                                   "l": {"max": {"field": "rule.level"}},
                                                   "a": {"terms": {"field": "agent.name", "size": 3}}}}}}}})
        hours, buried = [], {}
        for b in _b(r["aggregations"]["h"]):
            if b["doc_count"] <= m.max_per_hour:
                continue
            rules = []
            for x in _b(b["r"]):
                d = _b(x["d"])
                rules.append({"id": x["key"], "n": x["doc_count"], "level": int(x["l"]["value"] or 0),
                              "desc": d[0]["key"] if d else "", "agents": [a["key"] for a in _b(x["a"])]})
            hours.append({"t": b["key_as_string"], "n": b["doc_count"], "over": b["doc_count"] - m.max_per_hour,
                          "flood": rules[:1]})
            # everything except the dominant rule competed for the same few mails
            for x in rules[1:]:
                k = buried.setdefault(x["id"], {**x, "n": 0, "hours": 0})
                k["n"] += x["n"]
                k["hours"] += 1
        return {"alert_level": m.alert_level, "max_per_hour": m.max_per_hour,
                "saturated_hours": hours[-48:], "excess": sum(h["over"] for h in hours),
                "possibly_unmailed": sorted(buried.values(), key=lambda x: (-x["level"], -x["n"]))[:25]}

    # ------------------------------------------------------------------ personal data in logs (GDPR / KVKK)
    async def _personal_data(self, frm, to, sample: int) -> dict:
        """Scan the newest ``sample`` alerts of the window (plus a share of the high-level ones) for personal data
        stored in clear text. Only counts and fully masked examples leave this function."""
        from .privacy import scan_alerts
        src = ["full_log", "data", "rule.id", "rule.description", "agent.name", "location", "decoder.name"]
        q = {"bool": {"filter": [rng(frm, to)]}}
        r = await self.ix.search(self.env.alerts_index, {"size": sample, "query": q, "_source": src,
                                                         "sort": [{TS: "desc"}]})
        hits = r["hits"]["hits"]
        # spread the sample over the window: the newest alerts alone are often one noisy source
        r2 = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": q,
            "aggs": {"loc": {"terms": {"field": "location", "size": 40},
                             "aggs": {"s": {"top_hits": {"size": 5, "_source": src, "sort": [{TS: "desc"}]}}}}}})
        seen = {h.get("_id") for h in hits}
        for b in _b(r2["aggregations"]["loc"]):
            for h in b["s"]["hits"]["hits"]:
                if h.get("_id") not in seen:
                    seen.add(h.get("_id"))
                    hits.append(h)
        pv = self.env.privacy
        return scan_alerts(hits, set(pv.kinds) if pv.kinds else None, pv.allow)

    # ------------------------------------------------------------------ agent coverage
    async def _coverage(self, now: datetime) -> dict:
        agents = [a for a in await self.api.agents(limit=5000) if str(a.get("id")) != "000"]
        info = await self._safe("api_info", self.api.info()) or {}
        mver = str(info.get("api_version") or "").lstrip("v")
        by_status: dict[str, int] = {}
        versions: dict[str, int] = {}
        by_node: dict[str, int] = {}
        drift, stale, never = [], [], []
        for a in agents:
            st = a.get("status") or "?"
            by_status[st] = by_status.get(st, 0) + 1
            v = str(a.get("version") or "").replace("Wazuh", "").strip().lstrip("v")
            if v:
                versions[v] = versions.get(v, 0) + 1
                if mver and v != mver:
                    drift.append({"name": a.get("name"), "version": v})
            node = a.get("node_name") or "-"
            if st == "active":
                by_node[node] = by_node.get(node, 0) + 1
            if st == "never_connected":
                never.append(a.get("name"))
            elif st != "active":
                ka = a.get("lastKeepAlive")
                try:
                    hrs = round((now - _parse(ka)).total_seconds() / 3600, 1) if ka else None
                except ValueError:
                    hrs = None
                stale.append({"name": a.get("name"), "status": st, "last_keepalive": ka, "hours": hrs})
        out = {"total": len(agents), "by_status": by_status, "manager_version": mver, "versions": versions,
               "version_drift": drift[:60], "active_by_node": by_node, "not_active": stale[:60], "never_connected": never}
        if self.inventory:
            have = {str(a.get("name")) for a in agents}
            inv = set(self.inventory)
            out["inventory"] = {"expected": len(inv), "missing": sorted(inv - have), "unexpected": sorted(have - inv)}
        return out

    # ------------------------------------------------------------------ flags
    def _flags(self, d: dict) -> list[dict]:
        """Deterministic health flags (independent of the LLM)."""
        f: list[dict] = []
        h = d.get("health") or {}
        v = d.get("volume") or {}
        L = self.lang

        def add(sev, code, **kw):
            f.append({"severity": sev, "code": code, "message": t(L, f"flag.{code}", **kw)})

        sil = h.get("silence_minutes")
        if h.get("last_alert") is None and "last_alert" in h:
            add("critical", "no_alerts_7d")
        elif sil is not None and sil > self.env.max_silence_minutes:
            add("critical", "silence", m=sil, t=self.env.max_silence_minutes)
        if v.get("empty_hours"):
            add("warn", "empty_hours", n=len(v["empty_hours"]))
        ix = h.get("indexer") or {}
        if ix.get("status") and ix["status"] != "green":
            add("critical" if ix["status"] == "red" else "warn", "indexer_status", s=ix["status"])
        for disk in h.get("indexer_disk") or []:
            p = disk.get("percent")
            if p is not None and p >= self.env.disk_warn_percent:
                add("critical" if p >= 90 else "warn", "indexer_disk", node=disk["node"], p=p)
        if h.get("daemons_not_running"):
            add("critical", "daemons", d=", ".join(h["daemons_not_running"]))
        bad = h.get("agents_not_active") or []
        if bad:
            add("warn", "agents", n=len(bad), a=", ".join(a["name"] for a in bad[:8]))
        cl = h.get("cluster")
        if cl and cl.get("enabled") == "yes" and cl.get("running") != "yes":
            add("critical", "cluster")
        if d.get("new_rules"):
            hi = [r for r in d["new_rules"] if r["level"] >= self.env.high_level]
            if hi:
                add("warn", "new_high_rules", n=len(hi), l=self.env.high_level)
        mp = d.get("mail_pressure") or {}
        if mp.get("saturated_hours"):
            add("warn", "mail_saturated", n=len(mp["saturated_hours"]), m=mp["max_per_hour"],
                b=len(mp.get("possibly_unmailed") or []))
        cov = d.get("coverage") or {}
        if (cov.get("inventory") or {}).get("missing"):
            miss = cov["inventory"]["missing"]
            add("warn", "inventory_missing", n=len(miss), a=", ".join(miss[:8]))
        if cov.get("version_drift"):
            add("info", "version_drift", n=len(cov["version_drift"]), v=cov.get("manager_version"))
        sla = (d.get("vulnerabilities") or {}).get("sla") or {}
        over = {k: v["overdue"] for k, v in sla.items() if isinstance(v, dict) and v.get("overdue")}
        if over:
            add("warn" if over.get("Critical") else "info", "vuln_overdue",
                s=", ".join(f"{k} {n}" for k, n in over.items()))
        pd = d.get("personal_data") or {}
        if pd.get("affected_alerts"):
            from .privacy import SENSITIVE
            kinds = pd.get("kinds") or {}
            sens = any(k in SENSITIVE for k in kinds)
            add("warn" if sens else "info", "personal_data", n=pd["affected_alerts"], s=pd.get("sampled", 0),
                k=", ".join(f"{k} {n}" for k, n in sorted(kinds.items(), key=lambda x: -x[1])),
                src=", ".join(f"{x['location'] or x['agent']} (rule {x['rule_id']})" for x in pd["sources"][:3]))
        if self.errors:
            add("warn", "collector_errors", n=len(self.errors))
        return f


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _parse(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":  # +0000 → +00:00
        ts = ts[:-2] + ":" + ts[-2:]
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def health_status(flags: list[dict]) -> str:
    if any(f["severity"] == "critical" for f in flags):
        return "critical"
    if any(f["severity"] == "warn" for f in flags):
        return "warn"
    return "ok"
