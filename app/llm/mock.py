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
           "check_purpose": "how many invalid-user attempts sshd logged locally",
           "draft_title": "100960: invalid-user SSH attempts as root/admin (demo draft)",
           "draft_body": "*(demo)* Child rule of 5710 that raises attempts with privileged user names to level 10."},
    "tr": {"demo": "**[DEMO / sahte LLM]** Pencerede {total} alarm, seviye {lvl}+ {high}. Bu rapor gerçek bir model "
                   "tarafından yazılmadı; yalnızca akışı gösterir.",
           "health": "Deterministik bayraklara bakınız.", "flag": "Deterministik bayrak `{code}`.", "check": "Kontrol et.",
           "detail": "Seviye {level}, ajanlar: {agents}. Kaynak IP'ler: {ips}", "dig": "ip_profile ve correlate_around ile derinleş.",
           "q": "db01'e 198.51.100.23'ten gelen SSH denemeleri: bu sunucunun 22/tcp portu internete açık mı olmalı?",
           "why": "Sunucu iç ağda görünüyor.", "open": "Jenkins /manage için IP kısıtının etkisini ölç",
           "check_purpose": "sshd'nin yerelde kaydettiği geçersiz kullanıcı denemesi sayısı",
           "draft_title": "100960: root/admin adıyla geçersiz kullanıcı SSH denemeleri (demo taslak)",
           "draft_body": "*(demo)* 5710'un çocuk kuralı; ayrıcalıklı kullanıcı adlarıyla denemeleri seviye 10'a çıkarır."},
}


class MockLLM:
    name = "mock"

    async def complete(self, system, messages, tools, force_tool=None):
        L = TXT["tr" if "in Turkish" in (system or "") else "en"]
        if not tools:
            return LLMResponse(text="OK")
        names = {t["name"] for t in tools}
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        if "submit_report" in names:
            return self._triage(L, messages, tool_msgs, names)
        return LLMResponse(text="OK")

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
        if len(tool_msgs) == 1 and "propose_knowledge" in names:
            xml = ('<group name="sshd,authentication_failed,">\n'
                   '  <rule id="100960" level="10">\n    <if_sid>5710</if_sid>\n'
                   '    <user>^root$|^admin$</user>\n'
                   '    <description>sshd: login attempt as a privileged non-existent user</description>\n'
                   '  </rule>\n</group>')
            return LLMResponse(tool_calls=[ToolCall("t3", "propose_knowledge", {
                "kind": "rule_draft", "title": L.get("draft_title", "Demo rule draft"), "rule_ids": ["100960", "5710"],
                "body": L.get("draft_body", "Demo draft."), "xml": xml,
                "tests": [{"event": "Oct 26 10:00:00 web01 sshd[1]: Invalid user admin from 198.51.100.23 port 4242",
                           "log_format": "syslog", "expect": "match"},
                          {"event": "Oct 26 10:00:00 web01 sshd[1]: Invalid user bob from 198.51.100.23 port 4242",
                           "log_format": "syslog", "expect": "no_match"}]})], input_tokens=1200, output_tokens=120)
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
                             "recommendation": L["dig"],
                             "manual_checks": [{"host": r["agents"][0]["name"], "purpose": L["check_purpose"],
                                                "command": "sudo journalctl -u ssh --since '-12h' | grep -c 'Invalid user'"}]
                             if r["agents"] else []})
        v = c.get("volume") or {}
        report = {"summary_md": L["demo"].format(total=v.get("total", 0), high=v.get("high_level_total", 0),
                                                 lvl=c.get("env", {}).get("high_level")),
                  "health_assessment": L["health"], "findings": findings,
                  "questions": [{"question": L["q"], "why": L["why"]}],
                  "open_items": [L["open"]], "closed_items": []}
        return LLMResponse(tool_calls=[ToolCall("t2", "submit_report", report)], input_tokens=1500, output_tokens=400)
