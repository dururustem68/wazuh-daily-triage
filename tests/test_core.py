# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.agent.runner import run_agent
from app.agent.tools import ToolBox
from app.collector import Collector
from app.config import AppConfig, LLMConfig, load_settings
from app.demo import FakeAPI, FakeIndexer
from app.formatting import finding_text, question_text
from app.llm.anthropic import AnthropicLLM
from app.llm.openai_compat import OpenAICompatLLM
from app.redact import redact
from app.runtime import Runtime
from app.store import IndexStore, MemoryStore, Repo

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="module")
def settings():
    return load_settings(os.path.join(ROOT, "config/demo.yaml"))


@pytest.fixture(scope="module")
def ix():
    return FakeIndexer()


def test_timezone_is_validated():
    assert AppConfig(timezone="Europe/Istanbul").timezone == "Europe/Istanbul"
    with pytest.raises(ValueError, match="tzdata"):
        AppConfig(timezone="Mars/Olympus_Mons")


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
    tb = ToolBox(env, ix, FakeAPI(), Repo(MemoryStore(), env.id), mode="tools")
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


async def test_triage_mock(settings):
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
    # second run: the window starts where the first one ended, so the same 24 h are not analysed again
    run2 = await rt.run_triage(er, "demo-r2")
    assert 0 < run2["window"]["hours"] < 24


def test_copy_text_for_findings_and_questions():
    f = {"title": "SSH brute force", "label": "real_incident", "severity": "high",
         "detail": "1 200 failures.", "evidence": ["5710 ×1200"], "rule_ids": ["5710"], "agents": ["db01"],
         "recommendation": "Block 198.51.100.23.",
         "manual_checks": [{"host": "db01", "purpose": "count failures",
                            "command": "grep -c 'Failed' /var/log/auth.log"}]}
    txt = finding_text(f, "tr")
    for part in ("SSH brute force", "Gerçek olay · yüksek", "5710", "db01", "Öneri:", "grep -c", "5710 ×1200"):
        assert part in txt
    q = {"question": "Should 22/tcp be public?", "why": "db01 is internal.", "answer": "No."}
    qt = question_text(q)
    assert "Should 22/tcp be public?" in qt and "db01 is internal." in qt and "✓ No." in qt
    # copied text carries where it came from, and the payload stays bounded
    ctx = "prod — report of 26.10.2026 06:00"
    assert question_text(q, "en", context=ctx).startswith(ctx + "\n\n")
    huge = finding_text({**f, "rule_draft_xml": "<rule/>" * 9000}, "en")
    assert len(huge) <= 12_050 and huge.endswith("…")


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
    from app.i18n import CATALOG, EN
    for lang, catalog in CATALOG.items():
        missing, extra = set(EN) - set(catalog), set(catalog) - set(EN)
        assert not missing and not extra, f"{lang}: missing={sorted(missing)} extra={sorted(extra)}"


async def test_turkish_report_language(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(open(os.path.join(ROOT, "config/demo.yaml")).read().replace("${APP_LANGUAGE:-en}", "tr"))
    s = load_settings(p)
    rt = Runtime(s, demo=True)
    run = await rt.run_triage(rt.get("demo"), "tr-1")
    assert "sahte LLM" in run["summary_md"]
    assert any("ajan aktif değil" in f["message"] for f in run["flags"])


def test_llm_from_env(monkeypatch):
    from app.config import LLMConfig, llm_from_env
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_TEMPERATURE", "none")
    monkeypatch.setenv("LLM_TOKEN_PARAM", "max_completion_tokens")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "medium")
    monkeypatch.setenv("LLM_EXTRA_BODY", '{"top_p": 0.9}')
    c = LLMConfig(**llm_from_env())
    assert c.temperature is None and c.token_param == "max_completion_tokens"
    assert c.extra_body == {"reasoning_effort": "medium", "top_p": 0.9}


async def test_openai_body_params():
    from app.config import LLMConfig
    seen = {}

    def h(req):
        seen.update(json.loads(req.content))
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    cfg = LLMConfig(provider="openai", model="m", api_key="k", temperature=None,
                    token_param="max_completion_tokens", extra_body={"reasoning_effort": "low"},
                    base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
    llm = OpenAICompatLLM(cfg)
    llm.client = httpx.AsyncClient(transport=httpx.MockTransport(h))
    await llm.complete("s", [{"role": "user", "content": "x"}], [])
    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert "temperature" not in seen and seen["max_completion_tokens"] == 4096 and seen["reasoning_effort"] == "low"


async def test_retry_on_overload(monkeypatch):
    import asyncio as _a

    from app.config import LLMConfig
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)
    monkeypatch.setattr(_a, "sleep", fake_sleep)
    calls = {"n": 0}

    def h(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"error": {"status": "UNAVAILABLE"}})
        if calls["n"] == 2:
            return httpx.Response(429, headers={"retry-after": "7"}, json={})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    llm = OpenAICompatLLM(LLMConfig(provider="openai", model="m", api_key="k"))
    llm.client = httpx.AsyncClient(transport=httpx.MockTransport(h))
    r = await llm.complete("s", [{"role": "user", "content": "x"}], [])
    assert r.text == "ok" and calls["n"] == 3 and sleeps[1] == 7


async def test_llm_failure_keeps_deterministic_report(settings, monkeypatch):
    from app.llm.base import LLMError
    rt = Runtime(settings, demo=True)

    class Down:
        name = "down"

        async def complete(self, *a, **k):
            raise LLMError("LLM 503: high demand")
    monkeypatch.setattr(rt, "llm_for", lambda env: Down())
    run = await rt.run_triage(rt.get("demo"), "down-1")
    assert run["status"] == "done" and run["ai_error"].startswith("LLM 503")
    assert run["findings"] and run["collected"]["volume"]["total"] > 0
    assert "AI analysis unavailable" in run["summary_md"]


def test_schedule_times(tmp_path):
    from app.config import Schedule
    s = Schedule(times=["19:50", "07:50"], days=["mon"])
    assert s.all_times == ["07:50", "19:50"]
    assert Schedule(time="06:00").all_times == ["06:00"]
    with pytest.raises(ValueError):
        Schedule(times=["7:5"])


async def test_inbox_dedupe_and_act(settings):
    rt = Runtime(settings, demo=True)
    er = rt.get("demo")
    await rt.run_triage(er, "ib-1")
    await rt.run_triage(er, "ib-2", hours=24)   # explicit window: the same findings again, to test grouping
    items = await rt.inbox("demo")
    assert items and all(it["seen"] == 2 for it in items)          # same findings in both runs → grouped
    first = items[0]
    assert len(first["refs"]) == 2
    checks = [it for it in items if it["finding"].get("manual_checks")]
    assert checks and checks[0]["finding"]["manual_checks"][0]["command"]
    n = await rt.inbox_act("demo", first["refs"], "false_positive", "known scanner")
    assert n == 2
    after = await rt.inbox("demo")
    assert len(after) == len(items) - 1 and first["key"] not in {i["key"] for i in after}


async def test_notifications(settings, monkeypatch):
    from app import notify as N
    sent = {"tg": [], "teams": [], "mail": []}

    def h(req):
        body = json.loads(req.content)
        if req.url.host == "api.telegram.org":
            sent["tg"].append(body)
        else:
            sent["teams"].append(body)
        return httpx.Response(200, json={"ok": True})
    monkeypatch.setattr(N, "_send_email", lambda cfg, msg: sent["mail"].append(msg))
    settings2 = settings.model_copy(deep=True)
    settings2.notify = N.NotifyCfg(ui_url="http://127.0.0.1:18080",
                                   email=N.EmailCfg(host="smtp.example", sender="a@example.org", to=["b@example.org"]),
                                   telegram=N.TelegramCfg(bot_token="123:abc", chat_id="42"),
                                   teams=N.TeamsCfg(webhook_url="https://example.invalid/workflows/hook"))
    rt = Runtime(settings2, demo=True)
    er = rt.get("demo")
    er.env.liveness.enabled = False      # with liveness on, health flags are left to the liveness check
    run = {"run_id": "n-1", "env": "demo", "status": "done", "started_at": "2026-10-26T07:50:00.000Z",
           "flags": [{"severity": "critical", "code": "silence", "message": "Last alert was 300 min ago"},
                     {"severity": "warn", "code": "agents", "message": "1 agent not active"}],
           "findings": [{"id": "f1", "label": "real_incident", "severity": "high", "title": "SSH brute force succeeded",
                         "rule_ids": ["5715"], "agents": ["db01"]},
                        {"id": "f2", "label": "investigate", "severity": "medium", "title": "noise"}]}
    await er.repo.save_run(run)
    tr = httpx.MockTransport(h)
    res = await rt.notify_run(er, run, transport=tr)
    assert res == {"email": "ok", "telegram": "ok", "teams": "ok"}
    txt = sent["tg"][0]["text"]
    assert "Last alert was 300" in txt and "SSH brute force" in txt and "noise" not in txt and "/e/demo/r/n-1" in txt
    assert sent["teams"][0]["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert sent["mail"][0]["title"].endswith("CRITICAL")
    # same items again 12 h later → suppressed
    run2 = dict(run, run_id="n-2", notified=None)
    await er.repo.save_run(run2)
    assert await rt.notify_run(er, run2, transport=tr) == {}
    assert len(sent["tg"]) == 1
    assert (await rt.notify_test("demo", transport=tr))["telegram"] == "ok"

    # run summary: off by default, on → one message after every run, even without critical items
    quiet = {"run_id": "n-3", "env": "demo", "status": "done", "health": "ok", "started_at": "2026-10-26T19:50:00.000Z",
             "metrics": {"total": 1200, "high": 30}, "flags": [],
             "findings": [{"id": "f1", "label": "investigate", "severity": "medium", "title": "x"}]}
    await er.repo.save_run(quiet)
    n = len(sent["tg"])
    assert await rt.notify_run(er, quiet, transport=tr) == {}
    rt.settings.notify.on_run_summary = True
    assert (await rt.notify_run(er, quiet, transport=tr))["telegram"] == "ok"
    txt = sent["tg"][n]["text"]
    assert "1,200" in txt and "/e/demo/r/n-3" in txt
    # rule deploy notification
    from app import rules as R
    R.POLL_FIRST = R.POLL_EVERY = 0.01
    k = await er.repo.add_knowledge("rule_draft", "notify me", "", extra={"xml":
        '<group name="x,"><rule id="100990" level="9"><if_sid>5710</if_sid><description>t</description></rule></group>'})
    n = len(sent["tg"])
    rt.notify_transport = tr
    rec = await rt.rule_deploy("demo", k["id"], "alice")
    assert rec["state"] == "deployed" and "100990" in sent["tg"][n]["text"] and "alice" in sent["tg"][n]["text"]


async def test_slack_discord_webhook_ntfy(settings):
    from app import notify as N
    seen = []

    def h(req):
        body = None
        if req.content:
            try:
                body = json.loads(req.content)
            except ValueError:
                body = req.content.decode("utf-8", "replace")
        seen.append({"host": req.url.host, "path": req.url.path, "auth": req.headers.get("authorization"),
                     "title": req.headers.get("title"), "body": body})
        return httpx.Response(200, json={"ok": True})
    s2 = settings.model_copy(deep=True)
    s2.notify = N.NotifyCfg(slack=N.SlackCfg(webhook_url="https://hooks.slack.com/services/x"),
                            discord=N.DiscordCfg(webhook_url="https://discord.com/api/webhooks/y"),
                            webhook=N.WebhookCfg(url="https://soar.example.invalid/hook", token="t"),
                            ntfy=N.NtfyCfg(topic="wazuh-triage"))
    rt = Runtime(s2, demo=True)
    er = rt.get("demo")
    er.env.liveness.enabled = False
    run = {"run_id": "n-web", "env": "demo", "status": "done", "started_at": "2026-10-26T07:50:00.000Z",
           "flags": [{"severity": "critical", "code": "silence", "message": "Last alert was 300 min ago"}]}
    await er.repo.save_run(run)
    res = await rt.notify_run(er, run, transport=httpx.MockTransport(h))
    assert res == {"slack": "ok", "discord": "ok", "webhook": "ok", "ntfy": "ok"}, res
    by_host = {s["host"]: s for s in seen}
    assert {"hooks.slack.com", "discord.com", "soar.example.invalid", "ntfy.sh"} <= set(by_host)
    slack = by_host["hooks.slack.com"]
    assert slack["body"]["blocks"][0]["type"] == "header" and "Last alert was 300" in slack["body"]["blocks"][1]["text"]["text"]
    assert by_host["discord.com"]["body"]["content"].startswith("[Wazuh Daily Triage]")
    wh = by_host["soar.example.invalid"]
    assert wh["auth"] == "Bearer t" and wh["body"]["title"] and wh["body"]["lines"]
    nt = by_host["ntfy.sh"]
    assert nt["path"] == "/wazuh-triage" and nt["title"] and nt["auth"] is None


def test_empty_env_vars_fall_back(tmp_path, monkeypatch):
    from app.config import load_settings, notify_from_env
    monkeypatch.setenv("SMTP_PORT", "")
    monkeypatch.setenv("SMTP_TO", "a@example.org, b@example.org")
    assert notify_from_env()["email"]["port"] == 587
    p = tmp_path / "environments.yaml"
    p.write_text('llm: {provider: mock}\nnotify:\n  email: {host: h, port: "${SMTP_PORT:-587}", sender: s@example.org, '
                 'to: ["${SMTP_TO:-}"]}\nenvironments:\n  - id: x\n    name: X\n    indexer: {url: "https://192.0.2.1:9200"}\n')
    s = load_settings(p)
    n = s.notify_for(s.environments[0])
    assert n.email.port == 587 and n.email.to == ["a@example.org", "b@example.org"] and n.channels == ["email"]


async def test_agent_resubmits_after_truncated_report(settings):
    from app.agent.runner import run_agent
    from app.agent.tools import ToolBox
    from app.llm.base import LLMResponse, ToolCall
    calls = []

    class FakeLLM:
        name = "fake"

        async def complete(self, system, messages, tools, force_tool=None):
            calls.append(force_tool)
            if len(calls) == 1:
                return LLMResponse(text="I'll dig into it.", tool_calls=[ToolCall("1", "submit_report", {"_raw": '{"summ'})],
                                   stop_reason="length")
            return LLMResponse(tool_calls=[ToolCall("2", "submit_report", {"summary_md": "ok", "findings": []})])
    rt = Runtime(settings, demo=True)
    er = rt.get("demo")
    tb = ToolBox(er.env, er.ix, er.api, er.repo, mode="triage", run_id="x")
    res = await run_agent(FakeLLM(), "s", [{"role": "user", "content": "u"}], tb, 3, stop_on="submit_report")
    assert tb.submitted == {"summary_md": "ok", "findings": []} and res.stopped == "submit_report"
    assert any("rejected" in n for n in res.notes) and any("output limit" in n for n in res.notes)


async def test_agent_forced_final_and_fallback(settings):
    from app.agent.runner import FINAL_ATTEMPTS, run_agent
    from app.agent.tools import ToolBox
    from app.llm.base import LLMResponse
    forced = []

    class Chatty:
        name = "chatty"

        async def complete(self, system, messages, tools, force_tool=None):
            forced.append(force_tool)
            return LLMResponse(text="thinking out loud")
    rt = Runtime(settings, demo=True)
    er = rt.get("demo")
    tb = ToolBox(er.env, er.ix, er.api, er.repo, mode="triage", run_id="y")
    res = await run_agent(Chatty(), "s", [{"role": "user", "content": "u"}], tb, 3, stop_on="submit_report")
    assert tb.submitted is None and len(forced) == 3 + FINAL_ATTEMPTS
    assert forced[:2] == [None, None] and all(f == "submit_report" for f in forced[2:])
    assert res.stopped in ("text", "max_steps")


async def test_liveness_problem_reminder_recovery(settings):
    from app import notify as N
    sent = []

    def h(req):
        sent.append(json.loads(req.content)["text"])
        return httpx.Response(200, json={"ok": True})
    s2 = settings.model_copy(deep=True)
    s2.notify = N.NotifyCfg(telegram=N.TelegramCfg(bot_token="1:a", chat_id="1"))
    rt = Runtime(s2, demo=True)
    er = rt.get("demo")
    tr = httpx.MockTransport(h)

    async def broken():
        raise RuntimeError("connection refused")
    real = er.ix.cluster_health
    er.ix.cluster_health = broken
    st = await rt.liveness_check("demo", transport=tr)
    assert "indexer_down" in st["problems"] and len(sent) == 1 and "connection refused" in sent[0]
    await rt.liveness_check("demo", transport=tr)            # still failing, within repeat_hours → quiet
    assert len(sent) == 1
    er.ix.cluster_health = real
    er.env.liveness.silence_minutes = 10 ** 7                # demo data is old; ignore silence here
    st = await rt.liveness_check("demo", transport=tr)
    assert not st["problems"] and len(sent) == 2 and "connection refused" in sent[1]
    assert (await rt.liveness_state("demo"))["checked_at"]


def test_run_window_follows_the_last_report(settings):
    rt = Runtime(settings, demo=True)
    env = settings.environments[0].model_copy(update={"window_min_hours": 12, "window_max_hours": 96})
    to = datetime(2026, 10, 27, 6, 0, tzinfo=UTC)
    six_h_ago = {"window": {"to": (to - timedelta(hours=6)).isoformat()}}

    # no previous report: the default (min) window
    assert to - rt._window(env, None, to, None) == timedelta(hours=12)
    # a report six hours ago: exactly six hours, never inflated to min/max
    assert to - rt._window(env, six_h_ago, to, None) == timedelta(hours=6)
    # a manual request can only widen the window
    assert to - rt._window(env, six_h_ago, to, 24) == timedelta(hours=24)
    assert to - rt._window(env, six_h_ago, to, 1) == timedelta(hours=6)
    # the maximum caps a long gap (e.g. after a weekend), the minimum never shortens one
    week_ago = {"window": {"to": (to - timedelta(days=7)).isoformat()}}
    assert to - rt._window(env, week_ago, to, None) == timedelta(hours=96)
    assert to - rt._window(env, week_ago, to, 1000) == timedelta(hours=96)
    # a corrupt or future timestamp falls back instead of analysing a negative window
    assert to - rt._window(env, {"window": {"to": "not-a-date"}}, to, None) == timedelta(hours=12)
    future = {"window": {"to": (to + timedelta(hours=1)).isoformat()}}
    assert to - rt._window(env, future, to, None) == timedelta(hours=12)


async def test_run_retention_prunes_runs_not_knowledge():
    store = MemoryStore()
    repo = Repo(store, "prod")
    for run in ({"run_id": "old", "env": "prod", "status": "done", "started_at": "2020-01-01T00:00:00.000Z"},
                {"run_id": "new", "env": "prod", "status": "done", "started_at": "2999-01-01T00:00:00.000Z"},
                {"run_id": "other", "env": "staging", "status": "done", "started_at": "2020-01-01T00:00:00.000Z"}):
        await repo.save_run(run)
    knowledge = await repo.add_knowledge("decision", "keep this decision")
    await store.put("knowledge", knowledge["id"], {**knowledge, "created_at": "2020-01-01T00:00:00.000Z"})

    assert await repo.prune_runs(0) == 0            # 0 disables retention
    assert await repo.prune_runs(30) == 1
    assert await store.get("runs", "old") is None
    assert await store.get("runs", "new") is not None
    assert await store.get("runs", "other") is not None   # other environment untouched
    assert await store.get("knowledge", knowledge["id"]) is not None


async def test_run_retention_uses_delete_by_query():
    ix = FakeIndexer()
    store = IndexStore(ix, "daily-triage")
    repo = Repo(store, "prod")
    await repo.save_run({"run_id": "old", "env": "prod", "status": "done", "started_at": "2020-01-01T00:00:00.000Z"})
    await repo.save_run({"run_id": "new", "env": "prod", "status": "done", "started_at": "2999-01-01T00:00:00.000Z"})
    assert await repo.prune_runs(30) == 1
    assert await store.get("runs", "old") is None
    assert (await store.get("runs", "new"))["run_id"] == "new"
