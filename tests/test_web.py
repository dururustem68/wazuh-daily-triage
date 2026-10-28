# SPDX-License-Identifier: AGPL-3.0-only
import os
import time
from html import unescape
from re import findall

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

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
    assert c.get("/healthz").json()["ok"] is True   # liveness: public, no dependencies
    assert c.get("/readyz").status_code == 200      # readiness: public, storage answers


def test_viewer_read_only(c):
    r = c.post("/login", data={"password": "vwpw"}, follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/").status_code == 200                       # GET is allowed
    assert c.post("/api/e/demo/run", json={}).status_code == 403          # mutating API blocked
    assert c.post("/api/e/demo/k", json={"kind": "decision", "title": "x"}).status_code == 403
    assert c.post("/lang", data={"lang": "en"}, follow_redirects=False).status_code == 303   # lang still works
    assert c.post("/logout", follow_redirects=False).status_code == 303                       # logout still works
    assert c.get("/", follow_redirects=False).status_code == 303                                # now logged out


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
    chk = c.post("/api/e/demo/check").json()["results"]
    assert {x["key"] for x in chk} == {"indexer", "alerts", "vulns", "storage", "api", "llm"}
    assert all(x["ok"] for x in chk), chk
    assert page.text.count("data-copy-text") >= 2          # every finding and question can be copied
    copied = [unescape(a) for a in findall(r'data-copy-text="([^"]*)"', page.text)]
    assert copied and all("\n" in x for x in copied)      # multi-line text survives the attribute
    assert "data-copy-text" in c.get("/e/demo/inbox").text
    for p in ("/", "/e/demo", "/healthz"):
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


async def test_safe_records_storage_error():
    from types import SimpleNamespace

    from app.web.common import safe

    req = SimpleNamespace(state=SimpleNamespace())

    async def boom():
        raise RuntimeError("indexer down")

    assert await safe(boom(), [], request=req) == []
    assert req.state.storage_errors == ["indexer down"]


def test_readyz_ignores_indexer_outage(c, monkeypatch):
    # Readiness must NOT fail on an indexer outage: the UI has to stay reachable to explain the outage.
    ix = c.app.state.rt.envs["demo"].ix

    async def boom():
        raise RuntimeError("indexer down")

    monkeypatch.setattr(ix, "cluster_health", boom)
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json()["ready"] is True and r.json()["environments"] == ["demo"]


def test_storage_failure_shows_banner(c, monkeypatch):
    c.post("/login", data={"password": "pw"})
    er = c.app.state.rt.envs["demo"]

    async def boom(*a, **kw):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(er.repo, "list_runs", boom)
    page = c.get("/").text
    assert "disk gone" in page and "Request ID" in page      # visible, not just an empty list


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


def test_metrics(c, monkeypatch):
    c.post("/login", data={"password": "pw"})
    r = c.get("/metrics")
    assert r.status_code == 200 and "wdt_build_info" in r.text and "wdt_http_requests_total" in r.text

    monkeypatch.setenv("METRICS_TOKEN", "tok")
    assert c.get("/metrics").status_code == 401                 # token replaces the session requirement
    assert c.get("/metrics", headers={"Authorization": "Bearer tok"}).status_code == 200
    monkeypatch.delenv("METRICS_TOKEN")

    c.post("/login", data={"password": "vwpw"})
    assert c.get("/metrics").status_code == 403                 # viewer is not an administrator
    c.post("/login", data={"password": "pw"})


def test_environment_scope_denies_other_env(c, monkeypatch):
    c.post("/login", data={"password": "pw"})
    monkeypatch.setenv("ADMIN_ENVS", "prod")
    assert c.post("/api/e/demo/check").status_code == 403
    assert c.get("/e/demo").status_code == 403
    monkeypatch.delenv("ADMIN_ENVS")
    assert c.get("/e/demo").status_code == 200



def test_edit_rule_draft_xml(c):
    c.post("/login", data={"password": "pw"})
    k = c.post("/api/e/demo/k", json={"kind": "rule_draft", "title": "t", "body": "b"}).json()
    r = c.post(f"/api/e/demo/k/{k['id']}", json={"xml": '<rule id="119001" level="3"><if_sid>5710</if_sid>'
                                                     '<description>x</description></rule>'}).json()
    assert "119001" in r["xml"]
    page = c.get("/e/demo/k").text
    assert "data-copy-report" in page, page[:300]
    assert "119001" in c.get("/e/demo/k?kind=rule_draft").text


def test_about_templates_and_simple_import(c):
    assert c.post("/login", data={"password": "pw"}, follow_redirects=False).status_code == 303
    page = c.get("/about")
    assert page.status_code == 200 and "MCP" in page.text and 'class="topbar"' in page.text
    for fmt in ("txt", "csv", "yaml"):
        r = c.get(f"/api/kb/template?fmt={fmt}")
        assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    txt = c.get("/api/kb/template?fmt=txt").text
    r = c.post("/api/e/demo/kb/import", json={"text": txt, "dry_run": True, "filename": "x.txt"}).json()
    assert r["added"] == 4 and not r["errors"], r
    csv_t = c.get("/api/kb/template?fmt=csv").text
    r = c.post("/api/e/demo/kb/import", json={"text": csv_t, "dry_run": True, "filename": "x.csv"}).json()
    assert r["added"] == 3 and not r["errors"], r
    k = c.get("/e/demo/k?kind=rule_draft")
    assert k.status_code == 200
