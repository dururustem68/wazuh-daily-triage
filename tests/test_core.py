# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.agent.runner import run_agent
from app.agent.tools import ToolBox
from app.collector import Collector
from app.config import LLMConfig, load_settings
from app.demo import FakeAPI, FakeIndexer
from app.llm.anthropic import AnthropicLLM
from app.llm.openai_compat import OpenAICompatLLM
from app.redact import redact
from app.runtime import Runtime
from app.store import MemoryStore, Repo

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="module")
def settings():
    return load_settings(os.path.join(ROOT, "config/demo.yaml"))


@pytest.fixture(scope="module")
def ix():
    return FakeIndexer()


def test_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("X_PASS", "s3cr3t")
    p = tmp_path / "c.yaml"
    p.write_text("environments:\n- id: a\n  name: A\n  indexer: {url: 'https://x', password: '${X_PASS}', username: '${NOPE:-varsayilan}'}\n")
    s = load_settings(p)
    assert s.environments[0].indexer.password == "s3cr3t"
    assert s.environments[0].indexer.username == "varsayilan"


async def test_collector(settings, ix):
    env = settings.environments[0]
    now = datetime.now(UTC)
    c = await Collector(env, ix, FakeAPI()).collect(now - timedelta(hours=24), now)
    assert not c["errors"], c["errors"]
    assert c["volume"]["total"] > 1000
    assert c["watch"]["100212"] == 1600
    codes = {f["code"] for f in c["flags"]}
    assert "agents" in codes and "daemons" not in codes   # optional daemons (maild...) must not raise a flag
    assert any(r["id"] == "100213" for r in c["new_rules"])
    assert len(c["volume"]["hourly"]) in (24, 25)


async def test_silence_flag(settings):
    env = settings.environments[0]
    old = FakeIndexer(alerts=[a for a in FakeIndexer().alerts
                              if a["timestamp"] < (datetime.now(UTC) - timedelta(hours=5)).strftime("%Y-%m-%dT%H")])
    now = datetime.now(UTC)
    c = await Collector(env, old, None).collect(now - timedelta(hours=24), now)
    codes = {f["code"]: f["severity"] for f in c["flags"]}
    assert codes.get("silence") == "critical"
    assert "empty_hours" in codes


async def test_all_tools(settings, ix):
    env = settings.environments[0]
    tb = ToolBox(env, ix, FakeAPI(), Repo(MemoryStore(), env.id), mode="chat")
    calls = {
        "search_alerts": {"rule_ids": ["5710"], "size": 3},
        "aggregate_alerts": {"field": "data.srcip", "min_level": 5, "sub_field": "rule.id"},
        "rule_timeline": {"rule_ids": ["100213"], "interval": "10m"},
        "ip_profile": {"ip": "192.0.2."},
        "correlate_around": {"timestamp": datetime.now(UTC).isoformat(), "minutes": 300},
        "vulnerabilities": {"severity": "Critical"},
        "agent_info": {"agent": "db01"},
        "rule_info": {"rule_ids": ["5710", "100213"]},
        "logtest": {"event": "sshd[1]: Invalid user x from 192.0.2.4 port 22"},
        "validate_rule_xml": {"xml": '<group name="x"><rule id="100299" level="3"><if_sid>31101</if_sid>'
                                      '<field name="id">^(400|408)$</field><description>t</description></rule></group>'},
        "propose_knowledge": {"kind": "baseline", "title": "test"},
        "list_reports": {}, "get_report": {}, "knowledge": {},
    }
    assert set(calls) == {s["name"] for s in tb.specs()}
    for name, args in calls.items():
        out = json.loads((await tb.call(name, args)).split("… [truncated")[0])
        assert not (isinstance(out, dict) and out.get("error") and name != "get_report"), (name, out)
    v = json.loads(await tb.call("validate_rule_xml", calls["validate_rule_xml"]))
    assert v["xml_ok"] and v["warnings"]
    ipp = json.loads(await tb.call("ip_profile", {"ip": "192.0.2.45"}))
    assert ipp["distinct_urls"] == 1 and ipp["status_codes"] == {"401": 1680}
    bad = json.loads(await tb.call("validate_rule_xml", {"xml": "<rule id='1'>"}))
    assert bad["xml_ok"] is False


async def test_triage_and_chat_mock(settings):
    rt = Runtime(settings, demo=True)
    er = rt.get("demo")
    await er.repo.add_knowledge("request", "look at db01 ssh")
    run = await rt.run_triage(er, "demo-r1")
    assert run["status"] == "done", run.get("error")
    assert run["findings"] and run["questions"]
    assert run["agent"]["stopped"] == "submit_report"
    seeded = await er.repo.list_knowledge(kinds=["lesson"])
    assert seeded and seeded[0]["created_by"] == "seed"
    reqs = await er.repo.list_knowledge(kinds=["request"], status="active")
    assert reqs == []  # requests are consumed by the run
    # second run: window starts at the last run but is at least 24 h
    run2 = await rt.run_triage(er, "demo-r2")
    assert run2["window"]["hours"] == 24
    r = await rt.chat("demo", None, "son 24 saat")
    assert "demo answer" in r["answer"] and r["trace"]


def test_redact():
    s = redact('user=a@b.com password=Hunter2 Authorization: Bearer abc.def-123 "token":"xyz"')
    assert "a@b.com" not in s and "Hunter2" not in s and "abc.def" not in s and "xyz" not in s
    assert "10.0.0.1" in redact("from 10.0.0.1")


# ---------------------------------------------------------------- provider adapters
class Script:
    """Fake LLM server answering from a script; records incoming requests."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def handler(self, request: httpx.Request):
        self.requests.append(json.loads(request.content))
        return httpx.Response(200, json=self.responses.pop(0))


async def _loop(llm, script, settings, ix):
    env = settings.environments[0]
    tb = ToolBox(env, ix, FakeAPI(), Repo(MemoryStore(), env.id), mode="triage")
    llm.client = httpx.AsyncClient(transport=httpx.MockTransport(script.handler))
    res = await run_agent(llm, "sys", [{"role": "user", "content": "start"}], tb, 5, stop_on="submit_report")
    return res, tb


async def test_anthropic_tool_loop(settings, ix):
    s = Script([
        {"content": [{"type": "text", "text": "looking"},
                     {"type": "tool_use", "id": "tu1", "name": "aggregate_alerts", "input": {"field": "rule.id"}},
                     {"type": "tool_use", "id": "tu2", "name": "rule_timeline", "input": {"rule_ids": ["5710"]}}],
         "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 3}},
        {"content": [{"type": "tool_use", "id": "tu3", "name": "submit_report",
                      "input": {"summary_md": "ok", "findings": []}}], "stop_reason": "tool_use",
         "usage": {"input_tokens": 20, "output_tokens": 5}},
    ])
    llm = AnthropicLLM(LLMConfig(provider="anthropic", model="m", api_key="k"))
    res, tb = await _loop(llm, s, settings, ix)
    assert tb.submitted == {"summary_md": "ok", "findings": []}
    assert res.input_tokens == 33
    second = s.requests[1]["messages"]
    assert second[1]["role"] == "assistant" and second[1]["content"][1]["type"] == "tool_use"
    # two tool_results must be merged into one user message
    assert second[2]["role"] == "user" and [b["tool_use_id"] for b in second[2]["content"]] == ["tu1", "tu2"]
    assert s.requests[0]["system"][0]["cache_control"]["type"] == "ephemeral"
    assert {t["name"] for t in s.requests[0]["tools"]} >= {"submit_report", "search_alerts"}


async def test_openai_tool_loop(settings, ix):
    s = Script([
        {"choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "search_alerts", "arguments": '{"size": 2}'}}]}}],
         "usage": {"prompt_tokens": 7, "completion_tokens": 2}},
        {"choices": [{"finish_reason": "stop", "message": {"content": "writing the report"}}]},
        {"choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "submit_report",
                                                          "arguments": '{"summary_md": "x", "findings": []}'}}]}}]},
    ])
    llm = OpenAICompatLLM(LLMConfig(provider="openai", model="m", base_url="http://ollama:11434/v1"))
    res, tb = await _loop(llm, s, settings, ix)
    assert tb.submitted["summary_md"] == "x"
    m = s.requests[1]["messages"]
    assert m[0]["role"] == "system" and m[2]["tool_calls"][0]["function"]["name"] == "search_alerts"
    assert m[3]["role"] == "tool" and m[3]["tool_call_id"] == "c1"
    # if it stops with text it must be nudged to submit
    assert "submit_report" in s.requests[2]["messages"][-1]["content"]


def test_normalize_report():
    from app.runtime import normalize_report
    r = normalize_report({"summary_md": ["a", "b"], "findings": '[{"title": "x", "evidence": "tek"}, 5]',
                          "questions": ["Bu sizin miydi?", {"why": "soru yok"}], "open_items": "tek madde"})
    assert r["summary_md"].startswith("- a")
    assert len(r["findings"]) == 1 and r["findings"][0]["evidence"] == ["tek"] and r["findings"][0]["id"] == "f1"
    assert [q["question"] for q in r["questions"]] == ["Bu sizin miydi?"]
    assert r["open_items"] == ["tek madde"]
    assert normalize_report(None, "metin")["summary_md"] == "metin"


async def test_start_run_race(settings):
    import asyncio
    rt = Runtime(settings, demo=True)
    a = await rt.start_run("demo")
    with pytest.raises(RuntimeError):
        await rt.start_run("demo")
    for _ in range(100):
        if rt.get("demo").current_run is None:
            break
        await asyncio.sleep(0.05)
    assert (await rt.get("demo").repo.get_run(a))["status"] == "done"


async def test_empty_aggs_when_index_missing():
    from app.config import Endpoint
    from app.wazuh.indexer import Indexer

    def h(req):
        return httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    ix = Indexer(Endpoint(url="https://x"), transport=httpx.MockTransport(h))
    r = await ix.search("nope-*", {"size": 0, "aggs": {"r": {"terms": {"field": "a"}, "aggs": {"d": {"max": {"field": "b"}}}}}})
    assert r["aggregations"]["r"]["buckets"] == []


def test_settings_from_env(monkeypatch, tmp_path):
    for k, v in {"WAZUH_INDEXER_URL": "https://ix:9200", "WAZUH_INDEXER_USER": "u", "WAZUH_INDEXER_PASSWORD": "p",
                 "WAZUH_API_URL": "", "WAZUH_VERIFY_TLS": "false", "SCHEDULE_DAYS": "mon,fri", "APP_LANGUAGE": "tr"}.items():
        monkeypatch.setenv(k, v)
    s = load_settings(tmp_path / "missing.yaml")
    e = s.environments[0]
    assert e.indexer.url == "https://ix:9200" and e.indexer.verify_tls is False and e.api is None
    assert e.schedule.days == ["mon", "fri"] and s.app.language == "tr"


def test_i18n_catalogs_match():
    from app.i18n import EN, TR
    assert set(EN) == set(TR)


async def test_turkish_report_language(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(open(os.path.join(ROOT, "config/demo.yaml")).read().replace("${APP_LANGUAGE:-en}", "tr"))
    s = load_settings(p)
    rt = Runtime(s, demo=True)
    run = await rt.run_triage(rt.get("demo"), "tr-1")
    assert "sahte LLM" in run["summary_md"]
    assert any("ajan aktif değil" in f["message"] for f in run["flags"])
