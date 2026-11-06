# SPDX-License-Identifier: AGPL-3.0-only
"""0.9.1: srcip/dstip validation, inbox visibility of rule drafts, stricter "already decided" matching,
accepted health flags and ignored agents."""
import os
from xml.etree import ElementTree as ET

import pytest

from app.agent.tools import ToolBox
from app.collector import Collector, accept_flags, health_status
from app.config import load_settings
from app.review import ReviewMixin
from app.rules import ip_element_issues, parse
from app.runtime import Runtime
from app.whatif import compile_rule

ROOT = os.path.dirname(os.path.dirname(__file__))

BAD_DRAFT = """<group name="local,">
  <rule id="100972" level="5">
    <if_sid>102601</if_sid>
    <srcip type="pcre2">^192\\.168\\.68\\.(52|53)$</srcip>
    <description>admin root ssh</description>
  </rule>
</group>"""
GOOD_DRAFT = BAD_DRAFT.replace('<srcip type="pcre2">^192\\.168\\.68\\.(52|53)$</srcip>',
                               "<srcip>192.168.68.52/31</srcip>")


@pytest.fixture(scope="module")
def settings():
    return load_settings(os.path.join(ROOT, "config/demo.yaml"))


# ---------------------------------------------------------------- srcip / dstip
def _el(xml):
    return ET.fromstring(xml)


@pytest.mark.parametrize("xml", ["<srcip>10.0.0.1</srcip>", "<srcip>10.0.0.0/24</srcip>", "<srcip>!10.0.0.0/8</srcip>",
                                 "<dstip>2001:db8::/32</dstip>", "<srcip>10.0.0.1, 10.0.0.2</srcip>"])
def test_ip_element_ok(xml):
    el = _el(xml)
    assert ip_element_issues(el.tag, el) == []


@pytest.mark.parametrize("xml,needle", [
    ('<srcip type="pcre2">10.0.0.1</srcip>', "no attributes"),
    ("<srcip>^192\\.168\\.68\\.(52|53)$</srcip>", "not an IP"),
    ("<dstip>10.0.0.*</dstip>", "not an IP"),
    ("<srcip></srcip>", "empty"),
])
def test_ip_element_bad(xml, needle):
    el = _el(xml)
    assert any(needle in m for m in ip_element_issues(el.tag, el))


def test_parse_rejects_regex_srcip():
    _, errors = parse(BAD_DRAFT)
    assert errors and all("100972" in e for e in errors)
    rules, errors = parse(GOOD_DRAFT)
    assert not errors and rules[0]["id"] == "100972"


async def test_validate_rule_xml_warns_on_srcip(settings):
    env = settings.environments[0]
    tb = ToolBox(env, None, None, None, mode="mcp")
    res = await tb.validate_rule_xml({"xml": BAD_DRAFT})
    assert res["xml_ok"] and any("srcip" in w for w in res["warnings"])
    res = await tb.validate_rule_xml({"xml": GOOD_DRAFT})
    assert not res["warnings"]


def test_whatif_several_srcip_are_ored():
    rule = _el('<rule id="1" level="3"><if_sid>5</if_sid><srcip>10.0.0.1</srcip><srcip>10.0.0.2</srcip></rule>')
    tests, skipped = compile_rule(rule)
    assert not skipped and len(tests) == 1
    assert tests[0]({"data": {"srcip": "10.0.0.2"}})
    assert tests[0]({"data": {"srcip": "10.0.0.1"}})
    assert not tests[0]({"data": {"srcip": "10.0.0.3"}})


# ---------------------------------------------------------------- inbox
def _f(fid, label, rules, agents, title, status="new", draft=None):
    f = {"id": fid, "label": label, "severity": "low", "title": title, "rule_ids": rules, "agents": agents,
         "user_status": status}
    if draft:
        f["rule_draft_xml"] = draft
    return f


def test_same_finding_strict_needs_rule_overlap():
    old = _f("a", "investigate", ["300212", "2501"], ["mail"], "card numbers in alerts")
    new = _f("b", "investigate", ["300215", "300218", "300219", "2501", "3332"], ["mail", "wazuh-server"],
             "e-mail addresses copied into rule descriptions")
    assert ReviewMixin.same_finding(old, new)                     # grouping stays fuzzy …
    assert not ReviewMixin.same_finding(old, new, strict=True)    # … but one shared rule does not settle it
    again = _f("c", "investigate", ["300215", "300218", "300219"], ["wazuh-server"], "e-mail in descriptions")
    assert ReviewMixin.same_finding(new, again, strict=True)


async def test_inbox_shows_drafts_and_keeps_distinct_findings(settings, monkeypatch):
    rt = Runtime(settings, demo=True)
    er = rt.get("demo")
    runs = [
        {"run_id": "r2", "started_at": "2026-11-06T05:00:00Z", "findings": [
            _f("f2", "expected", ["102601"], ["scrap-pgdb01"], "root SSH from admin IP", draft=GOOD_DRAFT),
            _f("f3", "measurement", ["23506"], ["PCSF1"], "Chrome critical CVEs"),
            _f("f4", "investigate", ["300215", "300218", "300219", "2501", "3332"], ["mail", "wazuh-server"],
               "e-mail addresses copied into rule descriptions"),
        ]},
        {"run_id": "r1", "started_at": "2026-11-01T05:00:00Z", "findings": [
            _f("f9", "investigate", ["300212", "2501"], ["mail"], "card numbers in alerts", status="closed"),
        ]},
    ]

    async def list_runs(*a, **k):
        return runs
    monkeypatch.setattr(er.repo, "list_runs", list_runs)
    items = await rt.inbox("demo")
    ids = {i["finding"]["id"] for i in items}
    assert "f2" in ids          # an "expected" finding that carries a rule draft is a waiting decision
    assert "f3" not in ids      # plain measurement stays out
    assert "f4" in ids          # not hidden by the earlier decision on a different finding sharing rule 2501


# ---------------------------------------------------------------- health
def test_accept_flags_only_downgrades_warnings():
    flags = [{"severity": "warn", "code": "vuln_overdue", "message": "x"},
             {"severity": "warn", "code": "agents", "message": "y"},
             {"severity": "critical", "code": "silence", "message": "z"}]
    accept_flags(flags, ["vuln_overdue", "silence"])
    assert flags[0]["severity"] == "info" and flags[0]["accepted"]
    assert flags[1]["severity"] == "warn"
    assert flags[2]["severity"] == "critical" and "accepted" not in flags[2]
    assert health_status(flags) == "critical"
    assert health_status(flags[:1]) == "ok"


def test_ignore_agents_and_accept_in_collector(settings):
    env = settings.environments[0].model_copy(update={"ignore_agents": ["old-*", "laptop1"],
                                                      "health_accept": ["vuln_overdue"]})
    c = Collector(env, None, None, "en")
    d = {"health": {"agents_not_active": [{"name": "old-web"}, {"name": "laptop1"}]},
         "vulnerabilities": {"sla": {"Critical": {"overdue": 3}}}}
    flags = c._flags(d)
    assert not [f for f in flags if f["code"] == "agents"]
    vo = next(f for f in flags if f["code"] == "vuln_overdue")
    assert vo["severity"] == "info" and vo.get("accepted")
    assert health_status(flags) == "ok"
    d["health"]["agents_not_active"].append({"name": "db01"})
    assert any(f["code"] == "agents" and "db01" in f["message"] for f in c._flags(d))
