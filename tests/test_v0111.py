# SPDX-License-Identifier: AGPL-3.0-only
"""0.11.1: long operations run as background jobs; stateful (frequency) rules are logtested by replay."""
import asyncio
import os
import time

import pytest

from app import rules as R
from app.config import RuleDeployCfg, load_settings
from app.jobs import JobError, Jobs
from app.runtime import Runtime

ROOT = os.path.dirname(os.path.dirname(__file__))

FREQ = """<group name="sshd,">
  <rule id="100975" level="10" frequency="4" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>sshd: repeated invalid users from one source</description>
  </rule>
</group>"""
TESTS = [{"event": "Nov 12 06:00:00 host sshd[1]: Invalid user zz from 198.51.100.23 port 1 ssh2",
          "expect": "match"}]


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    monkeypatch.setattr(R, "POLL_FIRST", 0.01)
    monkeypatch.setattr(R, "POLL_EVERY", 0.01)


# ----------------------------------------------------------------------------- jobs
async def test_jobs_lifecycle_dedupe_and_errors():
    jobs = Jobs()
    gate = asyncio.Event()

    async def slow(job):
        job.progress.append({"step": "a", "ok": True})
        await gate.wait()
        return {"x": 1}

    j1 = jobs.start("deploy", "e", "k1", "alice", slow)
    j2 = jobs.start("deploy", "e", "k1", "bob", slow)          # double click → the same job
    assert j1 is j2 and j1.state == "running"
    await asyncio.sleep(0)
    assert j1.public()["progress"] == [{"step": "a", "ok": True}]
    assert j1.public()["poll"] == f"/api/e/e/jobs/{j1.id}"
    gate.set()
    await jobs.wait(j1)
    assert j1.state == "done" and j1.result == {"x": 1} and j1.finished_at

    async def refused(job):
        raise JobError("busy", 409)

    async def broken(job):
        raise KeyError("x")

    j3, j4 = jobs.start("x", "e", "k3", "a", refused), jobs.start("x", "e", "k4", "a", broken)
    await jobs.wait(j3)
    await jobs.wait(j4)
    assert (j3.state, j3.status, j3.error) == ("error", 409, "busy")
    assert j4.state == "error" and j4.status == 500 and "KeyError" in j4.error
    # a finished job can be started again
    assert jobs.start("deploy", "e", "k1", "alice", slow) is not j1


async def test_jobs_drain_cancels_what_does_not_finish():
    jobs = Jobs()

    async def forever(job):
        await asyncio.sleep(3600)

    j = jobs.start("deploy", "e", "k", "a", forever)
    await jobs.drain(0.05)
    assert j.state == "error" and j.status == 503 and "shutting down" in j.error


# ----------------------------------------------------------------------------- stateful logtest
async def test_replay_count():
    rules, _ = R.parse(FREQ)
    assert R.replay_count(rules) == 6
    assert R.replay_count(R.parse('<rule id="1" level="3"><if_sid>5</if_sid></rule>')[0]) == 1
    assert R.replay_count(R.parse('<rule id="1" level="3"><if_matched_sid>5</if_matched_sid></rule>')[0]) == 2
    assert R.replay_count(R.parse('<rule id="1" level="3" frequency="500"><if_matched_sid>5</if_matched_sid>'
                                  '</rule>')[0]) == R.MAX_REPLAY
    a = await R.analyse(FREQ, RuleDeployCfg(enabled=True), None)
    assert a["replay"] == 6
    sh = R.commands("k", FREQ, RuleDeployCfg(), "t", ["100975"], TESTS)
    assert "6 times in ONE session" in sh


async def test_frequency_rule_deploys_after_replay():
    """Before 0.11.1 a frequency rule always failed: one logtest event only ever reaches the parent rule."""
    rt = Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)
    er = rt.get("demo")
    k = await er.repo.add_knowledge("rule_draft", "freq", "", status="proposed", extra={"xml": FREQ, "tests": TESTS})
    seen = []
    rec = await rt.rule_deploy("demo", k["id"], "alice", on_step=seen.append)
    assert rec["state"] == "deployed", rec
    lt = next(s for s in rec["steps"] if s["step"] == "logtest")
    assert lt["ok"] and "100975 (event 4/6)" in lt["detail"], lt
    assert any(s["step"] == "logtest replay" for s in rec["steps"])
    assert [s["step"] for s in seen] == [s["step"] for s in rec["steps"]]     # live progress = final steps

    # single-shot logtest reaches only the parent → this is what used to fail
    res = await R._run_tests(er.api, ["100975"], TESTS, replay=1)
    assert res[0]["state"] == "failed" and res[0]["got_rule"] == "5710"


async def test_interrupted_deploy_is_recovered():
    rt = Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)
    er = rt.get("demo")
    k = await er.repo.add_knowledge("rule_draft", "x", "", extra={"xml": FREQ})
    d = await er.repo.s.get("knowledge", k["id"])
    d["deploy"] = {"state": "running", "action": "deploy", "file": "wdt_rules.xml", "ids": ["100975"]}
    await er.repo.s.put("knowledge", k["id"], d)
    await rt.recover_stale()
    dep = (await er.repo.s.get("knowledge", k["id"]))["deploy"]
    assert dep["state"] == "interrupted" and dep["rollback_state"] == "unknown" and "wdt_rules.xml" in dep["error"]


# ----------------------------------------------------------------------------- HTTP: 202 + polling
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))


@pytest.fixture(scope="module")
def c():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as client:
        client.post("/login", data={"password": "pw"})
        yield client


def _wait(c, job, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        j = c.get(job["poll"]).json()
        if j["state"] != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_deploy_answers_202_and_is_polled(c):
    R.POLL_FIRST = R.POLL_EVERY = 0.01
    k = c.post("/api/e/demo/k", json={"kind": "rule_draft", "title": "freq", "status": "proposed",
                                      "body": "```xml\n" + FREQ.replace("100975", "100976") + "\n```"}).json()
    r = c.post(f"/api/e/demo/k/{k['id']}/deploy", json={})
    assert r.status_code == 202 and r.json()["state"] == "running" and r.json()["kind"] == "deploy"
    j = _wait(c, r.json())
    assert j["state"] == "done" and j["result"]["state"] == "deployed" and j["progress"]
    assert c.get(f"/api/e/demo/k/{k['id']}/rule").json()["deploy"]["state"] == "deployed"
    r = c.post(f"/api/e/demo/k/{k['id']}/undeploy")
    assert r.status_code == 202 and _wait(c, r.json())["result"]["state"] == "removed"


def test_deploy_refusals_are_immediate(c):
    k = c.post("/api/e/demo/k", json={"kind": "rule_draft", "title": "silence", "status": "proposed",
                                      "body": "```xml\n<rule id=\"100977\" level=\"0\"><if_sid>5710</if_sid>"
                                              "<description>n</description></rule>\n```"}).json()
    assert c.post(f"/api/e/demo/k/{k['id']}/deploy", json={}).status_code == 403     # typed ids missing
    assert c.post("/api/e/demo/k/nope/deploy", json={}).status_code == 404


def test_check_whatif_and_job_visibility(c):
    r = c.post("/api/e/demo/check")
    assert r.status_code == 202
    j = _wait(c, r.json())
    assert j["state"] == "done" and j["result"]["results"]
    assert c.get("/api/e/demo/jobs/unknown-123").status_code == 404
    assert c.post("/api/e/demo/check?wait=true").json()["results"]           # synchronous for API clients
