# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Deterministic fake LLM for demo mode and tests. It does no real analysis; it exercises the flow end to end."""
from __future__ import annotations

import json
import re

from .base import LLMResponse, ToolCall

TXT = {
    "en": {"demo": "**[DEMO / mock LLM]** {total} alerts in the window, {high} at level {lvl}+. This report was not "
                   "written by a real model; it only demonstrates the flow.",
           "health": "See the deterministic flags.", "flag": "Deterministic flag `{code}`.", "check": "Check it.",
           "detail": "Level {level}, agents: {agents}. Source IPs: {ips}", "dig": "Dig deeper with ip_profile and correlate_around.",
           "q": "SSH attempts against db01 from 198.51.100.23: should port 22/tcp on this server be reachable from the internet?",
           "why": "The server looks internal.", "open": "Measure the effect of an IP allow-list on Jenkins /manage",
           "top": "*(demo answer)* Most frequent level 7+ rules in the last 24 hours:\n{rows}",
           "ip": "*(demo answer)* This IP produced {total} alerts; rules: {rules}; {paths} distinct path(s), status codes {codes}.",
           "got": "*(demo answer)* Tool result received."},
    "tr": {"demo": "**[DEMO / sahte LLM]** Pencerede {total} alarm, seviye {lvl}+ {high}. Bu rapor gerçek bir model "
                   "tarafından yazılmadı; yalnızca akışı gösterir.",
           "health": "Deterministik bayraklara bakınız.", "flag": "Deterministik bayrak `{code}`.", "check": "Kontrol et.",
           "detail": "Seviye {level}, ajanlar: {agents}. Kaynak IP'ler: {ips}", "dig": "ip_profile ve correlate_around ile derinleş.",
           "q": "db01'e 198.51.100.23'ten gelen SSH denemeleri: bu sunucunun 22/tcp portu internete açık mı olmalı?",
           "why": "Sunucu iç ağda görünüyor.", "open": "Jenkins /manage için IP kısıtının etkisini ölç",
           "top": "*(demo yanıtı)* Son 24 saatte seviye 7+ en sık kurallar:\n{rows}",
           "ip": "*(demo yanıtı)* Bu IP {total} alarm üretmiş; kurallar: {rules}; {paths} farklı yol, durum kodları {codes}.",
           "got": "*(demo yanıtı)* Araç sonucu alındı."},
}


class MockLLM:
    name = "mock"

    async def complete(self, system, messages, tools):
        L = TXT["tr" if "in Turkish" in (system or "") else "en"]
        if not tools:
            return LLMResponse(text="OK")
        names = {t["name"] for t in tools}
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        if "submit_report" in names:
            return self._triage(L, messages, tool_msgs, names)
        return self._chat(L, messages, tool_msgs)

    @staticmethod
    def _collected(messages):
        for m in messages:
            if m["role"] == "user" and "```json" in (m.get("content") or ""):
                return json.loads(re.search(r"```json\n(.*?)\n```", m["content"], re.S).group(1))
        return {}

    def _triage(self, L, messages, tool_msgs, names):
        c = self._collected(messages)
        hi = c.get("high_level") or []
        if not tool_msgs and hi and "rule_timeline" in names:
            top = max(hi, key=lambda r: r["level"])
            return LLMResponse(tool_calls=[ToolCall("t1", "rule_timeline",
                                                    {"rule_ids": [top["id"]], "from": c["window"]["from"],
                                                     "to": c["window"]["to"], "interval": "10m"})],
                               input_tokens=1000, output_tokens=50)
        findings = []
        for f in c.get("flags") or []:
            crit = f["severity"] == "critical"
            findings.append({"label": "real_incident" if crit else "investigate", "severity": "high" if crit else "medium",
                             "title": f["message"], "detail": L["flag"].format(code=f["code"]),
                             "recommendation": L["check"]})
        for r in sorted(hi, key=lambda r: -r["level"])[:4]:
            ags = ", ".join(a["name"] for a in r["agents"])
            findings.append({"label": "investigate", "severity": "high" if r["level"] >= 10 else "medium",
                             "title": f"{r['id']} — {r['desc']} ({r['count']})",
                             "detail": L["detail"].format(level=r["level"], agents=ags, ips=r.get("srcips")),
                             "evidence": [f"{a['name']}: {a['n']} ({a['first']} → {a['last']})" for a in r["agents"]],
                             "rule_ids": [r["id"]], "agents": [a["name"] for a in r["agents"]],
                             "recommendation": L["dig"]})
        v = c.get("volume") or {}
        report = {"summary_md": L["demo"].format(total=v.get("total", 0), high=v.get("high_level_total", 0),
                                                 lvl=c.get("env", {}).get("high_level")),
                  "health_assessment": L["health"], "findings": findings,
                  "questions": [{"question": L["q"], "why": L["why"]}],
                  "open_items": [L["open"]], "closed_items": []}
        return LLMResponse(tool_calls=[ToolCall("t2", "submit_report", report)], input_tokens=1500, output_tokens=400)

    def _chat(self, L, messages, tool_msgs):
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        if not tool_msgs or messages[-1]["role"] == "user":
            ip = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", last_user)
            if ip:
                return LLMResponse(tool_calls=[ToolCall("c1", "ip_profile", {"ip": ip.group(0), "from": "now-7d"})])
            return LLMResponse(tool_calls=[ToolCall("c1", "aggregate_alerts",
                                                    {"field": "rule.id", "min_level": 7, "from": "now-24h", "size": 5})])
        raw = tool_msgs[-1]["content"]
        data = json.loads(raw.split("… [truncated")[0]) if raw.startswith("{") else {}
        if "buckets" in data:
            rows = "\n".join(f"- `{b['key']}`: {b['count']}" for b in data["buckets"])
            txt = L["top"].format(rows=rows)
        elif "status_codes" in data:
            txt = L["ip"].format(total=data["total"], rules=", ".join(f"{r['id']} ({r['n']})" for r in data["rules"]),
                                 paths=data["distinct_urls"], codes=data["status_codes"])
        else:
            txt = L["got"]
        return LLMResponse(text=txt)
