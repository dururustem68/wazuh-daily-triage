# SPDX-License-Identifier: AGPL-3.0-only
import os
import time

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", APP_SECRET="s", WDT_SCHEDULER="false",
                  WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def test_auth_required(c):
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.post("/api/e/demo/run", json={}).status_code == 401
    assert c.post("/login", data={"password": "wrong"}).status_code == 401
    assert "Source code" in c.get("/login").text  # AGPL §13 link


def test_flow(c):
    r = c.post("/login", data={"password": "pw"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Content-Security-Policy" in c.get("/").headers
    rid = c.post("/api/e/demo/run", json={"hours": 24}).json()["run_id"]
    for _ in range(50):
        st = c.get(f"/api/e/demo/r/{rid}/status").json()
        if st["status"] in ("done", "error"):
            break
        time.sleep(0.2)
    assert st["status"] == "done", st
    page = c.get(f"/e/demo/r/{rid}")
    assert page.status_code == 200 and "Findings" in page.text
    assert c.post(f"/api/e/demo/r/{rid}/f/f1", json={"user_status": "baseline", "user_note": "known"}).json()["knowledge_id"]
    assert c.post(f"/api/e/demo/r/{rid}/f/f1", json={"user_status": "bogus"}).status_code == 400
    assert c.post(f"/api/e/demo/r/{rid}/q/q1", json={"answer": "yes"}).json()["ok"]
    k = c.post("/api/e/demo/k", json={"kind": "decision", "title": "Do not suggest NFS alerts"}).json()
    assert c.post(f"/api/e/demo/k/{k['id']}", json={"status": "closed"}).json()["status"] == "closed"
    assert "NFS" in c.get("/e/demo/k").text
    ch = c.post("/api/e/demo/chat", json={"text": "<script>alert(1)</script> 192.0.2.45"}).json()
    assert ch["session"] and "<script>" not in ch["html"]
    assert "&lt;script&gt;" in c.get(f"/e/demo/chat?s={ch['session']}").text
    chk = c.post("/api/e/demo/check").json()["results"]
    assert {x["key"] for x in chk} == {"indexer", "alerts", "vulns", "storage", "api", "llm"}
    assert all(x["ok"] for x in chk), chk
    for p in ("/", "/e/demo", "/e/demo/chat", "/healthz"):
        assert c.get(p).status_code == 200


def test_language_switch(c):
    c.post("/login", data={"password": "pw"})
    r = c.post("/lang", data={"lang": "tr"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Nöbet panosu" in c.get("/").text
    c.post("/lang", data={"lang": "en"})
    assert "Watch board" in c.get("/").text


def test_xss_in_markdown():
    from app.main import _md
    assert "<img" not in _md.render('<img src=x onerror=alert(1)>')
    assert 'href="javascript' not in _md.render("[x](javascript:alert(1))")


def test_rule_draft_ui_and_deploy(c):
    from app import rules as R
    R.POLL_FIRST = R.POLL_EVERY = 0.01
    c.post("/login", data={"password": "pw"})
    k = c.post("/api/e/demo/k", json={"kind": "rule_draft", "title": "d", "status": "proposed",
                                      "body": "```xml\n<group name=\"x,\"><rule id=\"100970\" level=\"9\"><if_sid>5710</if_sid>"
                                              "<description>t</description></rule></group>\n```"}).json()
    page = c.get("/e/demo/k?status=proposed").text
    assert "data-deploy" in page and "data-cmds" in page and "100970" in page
    v = c.get(f"/api/e/demo/k/{k['id']}/rule").json()
    assert v["analysis"]["ok"] and "wazuh-analysisd -t" in v["commands"]
    rec = c.post(f"/api/e/demo/k/{k['id']}/deploy", json={}).json()
    assert rec["state"] == "deployed" and rec["by"] == "ui"
    assert "data-undeploy" in c.get("/e/demo/k").text
    assert c.post(f"/api/e/demo/k/{k['id']}/undeploy").json()["state"] == "removed"


def test_kb_import_export_web(c):
    c.post("/login", data={"password": "pw"})
    y = "- kind: baseline\n  title: web-import\n  body: x\n"
    assert c.post("/api/e/demo/kb/import", json={"text": y, "dry_run": True}).json()["added"] == 1
    assert c.post("/api/e/demo/kb/import", json={"text": y}).json()["added"] == 1
    assert c.post("/api/e/demo/kb/import", json={"text": y}).json()["skipped"] == 1
    assert c.post("/api/e/demo/kb/import", json={"text": "- [unclosed"}).status_code == 400
    r = c.get("/api/e/demo/kb/export?kind=baseline")
    assert r.status_code == 200 and "web-import" in r.text and "attachment" in r.headers["content-disposition"]
    assert "data-kimport" in c.get("/e/demo/k").text


def test_watch_board_sections(c):
    c.post("/login", data={"password": "pw"})
    c.post("/lang", data={"lang": "en"})
    page = c.get("/").text
    assert "Waiting for your decision" in page and "Rule changes" in page and "Requests and open items" in page
