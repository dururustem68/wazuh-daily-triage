# SPDX-License-Identifier: AGPL-3.0-only
"""0.6.0: anomalies, Prometheus/Loki/Kubernetes tools, incident drafts, MCP endpoint, evaluation scoring."""
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.collector import Collector
from app.config import KubernetesSource, SourceEndpoint, load_settings
from app.eval import score
from app.runtime import Runtime
from app.sources import Kubernetes, Loki, Prometheus

ROOT = os.path.dirname(os.path.dirname(__file__))


def rt_demo():
    return Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)


def _fake(req: httpx.Request) -> httpx.Response:
    p = req.url.path
    if p == "/api/v1/query":
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"instance": "node1"}, "value": [1, "0.93"]}]}})
    if p == "/api/v1/query_range":
        return httpx.Response(200, json={"data": {"resultType": "matrix", "result": [
            {"metric": {"pod": "a"}, "values": [[1761400000 + i * 60, str(i)] for i in range(200)]}]}})
    if p == "/loki/api/v1/query_range":
        return httpx.Response(200, json={"data": {"resultType": "streams", "result": [
            {"stream": {"namespace": "wazuh", "pod": "wazuh-manager-worker-0", "x": "y"},
             "values": [["1761400000000000000", "ERROR analysisd: something"], ["1761400060000000000", "ok"]]}]}})
    if p == "/loki/api/v1/labels":
        return httpx.Response(200, json={"data": ["namespace", "pod"]})
    if p == "/api/v1/namespaces/wazuh/pods":
        return httpx.Response(200, json={"items": [{"metadata": {"name": "wazuh-manager-worker-0", "namespace": "wazuh"},
            "spec": {"nodeName": "w7", "containers": [{"image": "wazuh/wazuh-manager:4.14.9"}]},
            "status": {"phase": "Running", "containerStatuses": [{"name": "m", "ready": True, "restartCount": 3,
                       "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}]}}]})
    if p == "/api/v1/namespaces/wazuh/pods/wazuh-manager-worker-0/log":
        return httpx.Response(200, text="2026-10-26T10:00:00Z line1\n2026-10-26T10:00:01Z line2\n")
    if p == "/api/v1/nodes":
        return httpx.Response(200, json={"items": [{"metadata": {"name": "w7"}, "spec": {},
            "status": {"conditions": [{"type": "Ready", "status": "True"}, {"type": "DiskPressure", "status": "True"}],
                       "nodeInfo": {"kubeletVersion": "v1.36"}}}]})
    return httpx.Response(404, text="nope")


def _sources():
    t = httpx.MockTransport(_fake)
    return {"prometheus": Prometheus(SourceEndpoint(url="http://prom"), transport=t),
            "loki": Loki(SourceEndpoint(url="http://loki"), transport=t),
            "kubernetes": Kubernetes(KubernetesSource(enabled=True, in_cluster=False, api_url="https://k8s",
                                                      token="x", namespaces=["wazuh"]), transport=t)}


async def test_anomalies():
    rt = rt_demo()
    er = rt.get("demo")
    now = datetime.now(UTC)
    c = await Collector(er.env, er.ix, er.api, "en").collect(now - timedelta(hours=24), now)
    a = c["anomalies"]
    assert a["baseline_days"] == 14
    assert any(x["rule"] == "100212" and x["agent"] == "jenkins" for x in a["new_pairs"])
    # a burst of a rule that has a baseline on this agent → spike
    base = [e for e in er.ix.alerts if e["rule"]["id"] == "31101"][-1]
    for i in range(400):
        er.ix.alerts.append({**base, "timestamp": (now - timedelta(minutes=30, seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")})
    c = await Collector(er.env, er.ix, er.api, "en").collect(now - timedelta(hours=24), now)
    assert any(x["rule"] == "31101" and x["z"] >= 3 for x in c["anomalies"]["spikes"])


async def test_source_tools():
    rt = rt_demo()
    er = rt.get("demo")
    er.sources = _sources()
    from app.agent.tools import ToolBox
    tb = ToolBox(er.env, er.ix, er.api, er.repo, mode="tools", sources=er.sources)
    for n in ("prom_query", "prom_range", "loki_query", "loki_labels", "k8s_get", "k8s_logs"):
        assert n in tb._handlers
    r = json.loads(await tb.call("prom_query", {"expr": "up"}))
    assert r["series"][0]["value"] == "0.93"
    r = json.loads(await tb.call("prom_range", {"expr": "x", "from": "now-6h"}))
    assert len(r["series"][0]["points"]) <= 61 and r["series"][0]["max"] == 199
    r = json.loads(await tb.call("loki_query", {"query": '{namespace="wazuh"}', "from": "now-1h"}))
    assert r["count"] == 2 and r["lines"][0]["labels"] == {"namespace": "wazuh", "pod": "wazuh-manager-worker-0"}
    r = json.loads(await tb.call("k8s_get", {"kind": "pods", "namespace": "wazuh"}))
    assert r["items"][0]["restarts"] == 3 and r["items"][0]["last_termination"][0]["reason"] == "OOMKilled"
    r = json.loads(await tb.call("k8s_get", {"kind": "secrets", "namespace": "wazuh"}))
    assert "not allowed" in r["error"]
    r = json.loads(await tb.call("k8s_get", {"kind": "pods", "namespace": "kube-system"}))
    assert "allow-list" in r["error"]
    r = json.loads(await tb.call("k8s_logs", {"namespace": "wazuh", "pod": "wazuh-manager-worker-0"}))
    assert r["count"] == 2
    r = json.loads(await tb.call("k8s_get", {"kind": "nodes"}))
    assert r["items"][0]["pressure"] == ["DiskPressure"]
    # connection test lists the sources
    res = {c["key"]: c for c in await rt.check("demo", with_llm=False)}
    assert res["prometheus"]["ok"] and res["loki"]["ok"]


async def test_incident_draft_and_ticket():
    rt = rt_demo()
    er = rt.get("demo")
    run_id = await rt.start_run("demo")
    for t in list(rt._tasks):
        await t
    run = await er.repo.get_run(run_id)
    fid = run["findings"][0]["id"]
    rec = await rt.incident_draft("demo", run_id, fid, "alice", "tr")
    assert rec["id"].startswith("INC-") and rec["md"]
    assert (await er.repo.get_run(run_id))["findings"][0]["incident"]["id"] == rec["id"]
    # Zammad
    from app.config import ZammadCfg
    er.env.incident.zammad = ZammadCfg(url="https://zammad.example.com", token="t", group="SecOps")
    seen = {}

    def z(req):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(201, json={"id": 42, "number": "70042"})
    rt.notify_transport = httpx.MockTransport(z)
    t = await rt.incident_ticket("demo", run_id, fid)
    assert t["number"] == "70042" and seen["auth"] == "Token token=t" and seen["body"]["article"]["internal"]
    assert (await rt.incident_ticket("demo", run_id, fid))["id"] == 42   # idempotent


async def test_incident_jira_ticket():
    rt = rt_demo()
    er = rt.get("demo")
    run_id = await rt.start_run("demo")
    for t in list(rt._tasks):
        await t
    run = await er.repo.get_run(run_id)
    fid = run["findings"][0]["id"]
    await rt.incident_draft("demo", run_id, fid, "alice")
    from app.config import JiraCfg
    er.env.incident.jira = JiraCfg(url="https://wazuh.atlassian.net", email="a@b.c", token="t",
                                   project="SEC", issue_type="Incident")
    seen = {}

    def j(req):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(201, json={"id": "10042", "key": "SEC-42"})
    rt.notify_transport = httpx.MockTransport(j)
    t = await rt.incident_ticket("demo", run_id, fid, provider="jira")
    assert t["key"] == "SEC-42" and t["number"] == "SEC-42" and t["provider"] == "jira"
    f = seen["body"]["fields"]
    assert f["project"]["key"] == "SEC" and f["issuetype"]["name"] == "Incident"
    assert f["description"]["type"] == "doc" and seen["auth"].startswith("Basic ")
    assert (await rt.incident_ticket("demo", run_id, fid, provider="jira"))["key"] == "SEC-42"   # idempotent
    # wrong provider → permission error when not configured
    with pytest.raises(PermissionError):
        er.env.incident.zammad = None
        await rt.incident_ticket("demo", run_id, fid, provider="zammad")


def test_mcp_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", APP_SECRET="s", WDT_SCHEDULER="false",
                      WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))
    from app.main import app
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    with TestClient(app) as c:
        assert c.post("/mcp", json={}).status_code == 404            # off without a token
        monkeypatch.setenv("MCP_TOKEN", "s3cret-token")
        assert c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
        h = {"Authorization": "Bearer s3cret-token"}
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                            "params": {"protocolVersion": "2025-06-18"}}).json()
        assert r["result"]["serverInfo"]["name"] == "wazuh-daily-triage"
        assert c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "method": "notifications/initialized"}).status_code == 202
        tools = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()["result"]["tools"]
        names = {x["name"] for x in tools}
        assert {"list_environments", "search_alerts", "ip_profile", "inbox", "audit_report", "knowledge"} <= names
        assert "submit_report" not in names
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "aggregate_alerts", "arguments": {"env": "demo", "field": "rule.id", "from": "now-24h"}}}).json()
        assert not r["result"]["isError"] and "100212" in r["result"]["content"][0]["text"]
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                            "params": {"name": "list_environments", "arguments": {}}}).json()
        assert json.loads(r["result"]["content"][0]["text"])[0]["id"] == "demo"
        r = c.post("/mcp", headers=h, json={"jsonrpc": "2.0", "id": 5, "method": "nope"}).json()
        assert r["error"]["code"] == -32601


def test_eval_score():
    findings = [{"label": "investigate", "title": "SSH brute force on odooserver", "rule_ids": ["5712"], "agents": ["odooserver"]},
                {"label": "investigate", "title": "WP plugin update flood", "rule_ids": ["100591"]}]
    case = {"expect": [{"id": "ssh", "rules": ["5712"], "keywords": ["odooserver"]},
                       {"id": "crash", "rules": ["40704"]}],
            "forbid": [{"id": "wp", "rules": ["100591"]}]}
    s = score(case, findings)
    assert s["recall"] == 0.5 and [h["id"] for h in s["hits"]] == ["ssh"] and s["noise_violations"][0]["id"] == "wp"
