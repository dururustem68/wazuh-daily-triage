# SPDX-License-Identifier: AGPL-3.0-only
import os

import pytest

from app import rules as R
from app.config import RuleDeployCfg, load_settings
from app.runtime import Runtime

ROOT = os.path.dirname(os.path.dirname(__file__))

DETECT = """<group name="sshd,">
  <rule id="100950" level="12">
    <if_sid>5715</if_sid>
    <srcip>198.51.100.0/24</srcip>
    <description>sshd: success from a watched range</description>
  </rule>
</group>"""
SILENCE = '<rule id="100951" level="0">\n  <if_sid>5710</if_sid>\n  <description>noise</description>\n</rule>'


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(R, "POLL_FIRST", 0.01)
    monkeypatch.setattr(R, "POLL_EVERY", 0.01)


def test_extract_xml():
    assert R.extract_xml({"xml": DETECT}) == DETECT
    body = "Reason...\n```xml\n" + DETECT + "\n```\nmore"
    assert R.extract_xml({"body": body}).startswith("<group")
    assert R.extract_xml({"body": "text " + SILENCE + " tail"}).startswith("<rule")
    assert R.extract_xml({"body": "no xml"}) == ""


async def test_analyse_errors_and_risk():
    cfg = RuleDeployCfg(enabled=True)
    a = await R.analyse(DETECT, cfg, None)
    assert a["ok"] and not a["risky"] and a["ids"] == ["100950"]
    a = await R.analyse(SILENCE, cfg, None)
    assert a["ok"] and any("level 0" in x for x in a["risky"]) and a["xml"].startswith("<group")
    a = await R.analyse(DETECT.replace("100950", "5999"), cfg, None)
    assert not a["ok"] and "range" in a["errors"][0]
    a = await R.analyse("<rule id='1'", cfg, None)
    assert not a["ok"]
    a = await R.analyse(DETECT.replace("sshd,", "wdt:x"), cfg, None)
    assert not a["ok"]


def test_block_replace_and_commands():
    c1 = R.with_block(None, "k1", DETECT, "t")
    c2 = R.with_block(c1, "k1", DETECT.replace('level="12"', 'level="11"'), "t")
    assert c2.count("wdt:begin k1") == 1 and 'level="11"' in c2
    assert "k1" not in R.remove_block(c2, "k1")
    sh = R.commands("k1", DETECT, RuleDeployCfg(), "t", ["100950"], [{"event": "x", "expect": "match"}])
    assert "wazuh-analysisd -t" in sh and "WDT_RULE_EOF" in sh and "/var/ossec/etc/rules/wdt_rules.xml" in sh


async def test_deploy_flow():
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    rt = Runtime(s, demo=True)
    er = rt.get("demo")
    api = er.api
    k = await er.repo.add_knowledge("rule_draft", "detect", "why", status="proposed", created_by="ai",
                                    extra={"xml": DETECT})
    v = await rt.rule_view("demo", k["id"])
    assert v["deploy_enabled"] and v["analysis"]["ok"] and "cat >>" in v["commands"]

    rec = await rt.rule_deploy("demo", k["id"], "alice")
    assert rec["state"] == "deployed", rec
    assert "100950" in api.loaded and api.restarts == 1
    d = await er.repo.s.get("knowledge", k["id"])
    assert d["status"] == "active" and d["deploy"]["by"] == "alice"

    # redeploy replaces the block instead of duplicating it
    await rt.rule_deploy("demo", k["id"], "alice")
    assert api.files["wdt_rules.xml"].count("wdt:begin " + k["id"]) == 1

    # silencing needs the typed ids
    k2 = await er.repo.add_knowledge("rule_draft", "silence", "", status="proposed", extra={"xml": SILENCE})
    with pytest.raises(PermissionError):
        await rt.rule_deploy("demo", k2["id"], "alice")
    assert (await rt.rule_deploy("demo", k2["id"], "alice", confirm="100951"))["state"] == "deployed"

    # validation failure → rolled back, file unchanged, no restart
    before, restarts = api.files["wdt_rules.xml"], api.restarts
    k3 = await er.repo.add_knowledge("rule_draft", "x", "", extra={"xml": DETECT.replace("100950", "100952")})
    api.fail_validation = True
    rec = await rt.rule_deploy("demo", k3["id"], "alice")
    api.fail_validation = False
    assert rec["state"] == "failed" and api.files["wdt_rules.xml"] == before and api.restarts == restarts
    assert any(st["step"] == "rollback" for st in rec["steps"])

    # remove
    rec = await rt.rule_deploy("demo", k["id"], "alice", remove=True)
    assert rec["state"] == "removed" and "100950" not in api.loaded
    assert (await er.repo.s.get("knowledge", k["id"]))["status"] == "closed"


async def test_deploy_disabled_by_default(tmp_path):
    p = tmp_path / "e.yaml"
    p.write_text('llm: {provider: mock}\nenvironments:\n  - id: x\n    name: X\n'
                 '    indexer: {url: "https://192.0.2.1:9200"}\n    api: {url: "https://192.0.2.1:55000"}\n')
    rt = Runtime(load_settings(p), demo=True)
    er = rt.get("x")
    k = await er.repo.add_knowledge("rule_draft", "d", "", extra={"xml": DETECT})
    with pytest.raises(PermissionError):
        await rt.rule_deploy("x", k["id"], "bob")
    assert not (await rt.rule_view("x", k["id"]))["deploy_enabled"]


async def test_kb_import_export():
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    rt = Runtime(s, demo=True)
    items = [{"kind": "baseline", "title": "31101 scanner noise", "body": "a", "rule_ids": [31101], "key": "n-31101"},
             {"kind": "baseline", "title": "60106 DC machine logon", "body": "b"},
             {"kind": "nope", "title": "x"}, {"title": "no kind"}]
    r = await rt.kb_import("demo", items, dry_run=True)
    assert r["added"] == 2 and len(r["errors"]) == 2 and not (await rt.kb_export("demo", kinds=["baseline"]))[2:]
    r = await rt.kb_import("demo", items)
    assert r["added"] == 2
    r = await rt.kb_import("demo", items)                       # idempotent
    assert r["added"] == 0 and r["skipped"] == 2
    items[0]["title"], items[0]["body"] = "31101 scanner noise (~10k/day)", "changed"
    r = await rt.kb_import("demo", items, update=True)           # same key → updated, not duplicated
    assert r["updated"] == 1 and r["added"] == 0
    out = await rt.kb_export("demo", kinds=["baseline"])
    e = next(x for x in out if x.get("key") == "n-31101")
    assert e["body"] == "changed" and e["rule_ids"] == ["31101"]


async def test_parent_load_order():
    class API:
        async def rules(self, ids):
            return [{"id": 99919, "level": 9, "filename": "zz_local_rules_seviye.xml", "relative_dirname": "etc/rules"},
                    {"id": 60106, "level": 3, "filename": "0580-win-security_rules.xml", "relative_dirname": "ruleset/rules"}]
    cfg = RuleDeployCfg(enabled=True)
    x = '<group name="x,"><rule id="100951" level="12"><if_sid>{p}</if_sid><description>t</description></rule></group>'
    a = await R.analyse(x.format(p="99919"), cfg, API())
    assert not a["ok"] and "loads after" in a["errors"][0]
    assert (await R.analyse(x.format(p="99919"), RuleDeployCfg(file="zz_wdt_rules.xml"), API()))["ok"]
    assert (await R.analyse(x.format(p="60106"), cfg, API()))["ok"]
