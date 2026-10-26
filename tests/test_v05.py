# SPDX-License-Identifier: AGPL-3.0-only
"""0.5.0: mail channel saturation, agent coverage, vulnerability SLA, live verification, promotion, audit report."""
import os
from datetime import UTC, datetime, timedelta

import pytest

from app import rules as R
from app.collector import Collector
from app.config import load_settings
from app.runtime import Runtime

ROOT = os.path.dirname(os.path.dirname(__file__))
XML = """<group name="sshd,">
  <rule id="100970" level="4">
    <if_sid>5710</if_sid>
    <srcip>198.51.100.23</srcip>
    <description>known scanner</description>
  </rule>
</group>"""


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(R, "POLL_FIRST", 0.01)
    monkeypatch.setattr(R, "POLL_EVERY", 0.01)


def rt_demo():
    return Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)


async def test_collector_sections():
    rt = rt_demo()
    er = rt.get("demo")
    now = datetime.now(UTC)
    inv = er.env.inventory_names(rt.settings.base_dir)
    c = await Collector(er.env, er.ix, er.api, "en", inventory=inv).collect(now - timedelta(hours=24), now)
    mp = c["mail_pressure"]
    assert mp["saturated_hours"] and mp["max_per_hour"] == 12
    assert all(h["n"] > 12 for h in mp["saturated_hours"])
    cov = c["coverage"]
    assert cov["total"] == 8 and cov["inventory"]["missing"] == ["backup01"]
    assert cov["version_drift"] and cov["manager_version"] == "4.14.8"
    sla = c["vulnerabilities"]["sla"]
    assert set(sla) == {"Critical", "High", "Medium"} and sla["Medium"]["overdue"] > 0
    codes = {f["code"] for f in c["flags"]}
    assert {"mail_saturated", "inventory_missing", "version_drift", "vuln_overdue"} <= codes
    assert not c["errors"], c["errors"]


async def test_verify_promote_and_audit():
    rt = rt_demo()
    er = rt.get("demo")
    k = await er.repo.add_knowledge("rule_draft", "scanner", "200+ attempts from one scanner", status="proposed",
                                    extra={"xml": XML})
    rec = await rt.rule_deploy("demo", k["id"], "alice", confirm="100970")
    assert rec["state"] == "deployed"
    # demo alerts never carry 100970 → waiting; inject one event → seen
    v = (await rt.verify_rules("demo", k["id"]))[0]
    assert v["state"] == "waiting"
    ev = dict(er.ix.alerts[-1])
    ev = {**ev, "rule": {"id": "100970", "level": 4, "description": "known scanner", "groups": ["sshd"]},
          "timestamp": (datetime.now(UTC) + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")}
    er.ix.alerts.append(ev)
    v = (await rt.verify_rules("demo", k["id"]))[0]
    assert v["state"] == "seen" and v["seen"]["100970"]["n"] == 1

    p = await rt.promote_view("demo", k["id"], "alice")
    assert p["still_deployed"] and not p["errors"], p["errors"]
    assert "wazuh-analysisd -t" in p["script"] and "100970" in p["block"] and "| 100970 | 5710 | 4 |" in p["catalog_md"]
    assert "press Remove" in p["script"]
    with pytest.raises(ValueError):
        await rt.mark_promoted("demo", k["id"], "alice")
    await rt.rule_deploy("demo", k["id"], "alice", remove=True)
    d = await rt.mark_promoted("demo", k["id"], "alice")
    assert d["promoted"]["ids"] == ["100970"] and d["status"] == "closed"
    assert (await rt.verify_rules("demo"))[0]["id"] == k["id"]   # promoted entries keep being verified

    # k8s mode script
    er.env.promote.mode = "kubernetes"
    er.env.promote.kustomize_dir = "k8s/wazuh"
    p = await rt.promote_view("demo", k["id"])
    assert "kubectl apply -k" in p["script"] and "rollout status" not in p["script"].replace("no rollout status", "")

    # liveness outage history
    er.ix.cluster_health = _red
    await rt.liveness_check("demo")
    er.ix.cluster_health = _green
    st = await rt.liveness_check("demo")
    assert st["events"] and st["events"][-1]["code"] == "indexer_status"

    run_id = await rt.start_run("demo")
    for t in list(rt._tasks):
        await t
    a = await rt.audit("demo")
    assert a["volume"]["total"] > 0 and a["runs"]["count"] == 1
    assert any(x["action"] == "promote" for x in a["rule_changes"])
    assert any(x["action"] == "deploy" for x in a["rule_changes"])
    assert a["liveness"]["events"] and a["coverage"]["inventory"]["missing"] == ["backup01"]
    from app.audit import markdown
    md = markdown(a, "tr")
    assert "Kural değişiklikleri" in md and "100970" in md and run_id


async def _red():
    return {"status": "red"}


async def _green():
    return {"status": "green", "number_of_nodes": 1}


def test_audit_pages():
    from fastapi.testclient import TestClient
    os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", APP_SECRET="s", WDT_SCHEDULER="false",
                      WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))
    from app.main import app
    with TestClient(app) as c:
        c.post("/login", data={"password": "pw"})
        assert c.get("/e/demo/audit?month=bad").status_code == 400
        page = c.get("/e/demo/audit").text
        assert "data-print" in page and "abar" in page
        r = c.get("/api/e/demo/audit.md")
        assert r.status_code == 200 and r.text.startswith("# ")
