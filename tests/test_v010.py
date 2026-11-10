# SPDX-License-Identifier: AGPL-3.0-only
"""0.10: the watch (rule-based alerts, no AI), the AI round's verdicts, settings, masking profile,
backup/restore, storage safety, per-environment pseudonyms, client address and proxy checks."""
import base64
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.datastructures import Headers

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app import backup as B  # noqa: E402
from app import privacy, security, storagecheck  # noqa: E402
from app import watch as W  # noqa: E402
from app.backupcfg import S3Cfg  # noqa: E402
from app.config import Schedule, load_settings  # noqa: E402
from app.demo import AGENTS, FakeIndexer, _ev  # noqa: E402
from app.main import app  # noqa: E402
from app.notify import NotifyCfg, TeamsCfg, TelegramCfg  # noqa: E402
from app.runtime import Runtime  # noqa: E402
from app.settingsdoc import AiRound, EnvSettings, MaskProfile, QuietHours, WatchSettings  # noqa: E402
from app.store import IndexStore  # noqa: E402
from app.web import auth as web_auth  # noqa: E402
from app.web import common  # noqa: E402

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def _settings(**notify):
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    if notify:
        s.notify = NotifyCfg(**notify)
    return s


def _rt(alerts=None, **notify) -> Runtime:
    rt = Runtime(_settings(**notify), demo=True)
    if alerts is not None:
        rt.get("demo").ix.alerts = alerts
    return rt


def _at(minutes_ago: float) -> datetime:
    return NOW - timedelta(minutes=minutes_ago)


def _sent(rt) -> list[str]:
    box: list[str] = []

    def h(req: httpx.Request) -> httpx.Response:
        box.append(json.loads(req.content)["text"])
        return httpx.Response(200, json={"ok": True})

    rt.notify_transport = httpx.MockTransport(h)
    return box


TG = {"telegram": TelegramCfg(bot_token="1:abcdefgh", chat_id="1")}


# ------------------------------------------------------------------ settings model
def test_settings_defaults_and_validation():
    st = EnvSettings()
    assert not st.watch.enabled and st.ai.times is None and st.backup.remind_days == 30
    assert st.schedule(Schedule(time="07:30")).all_times == ["07:30"]            # nothing set: the YAML schedule
    st = EnvSettings(ai=AiRound(times=["19:00", "07:00"], days=["Mon", "tue"]))
    sch = st.schedule(Schedule(time="07:30"))
    assert sch.all_times == ["07:00", "19:00"] and sch.days == ["mon", "tue"]
    with pytest.raises(ValidationError, match="at most two"):
        AiRound(times=["01:00", "02:00", "03:00"])
    with pytest.raises(ValidationError):
        WatchSettings(channels=["pager"])
    with pytest.raises(ValidationError):
        WatchSettings(interval_minutes=1)
    w = WatchSettings(rules="5710, 5712", groups=None, mute=["b", "a", "a"], triggers={"spike": False})
    assert w.rules == ["5710", "5712"] and w.groups is None and w.mute == ["a", "b"]
    assert w.triggers["spike"] is False and w.triggers["level"] is True
    assert not w.on("level")                                                     # the watch itself is off


def test_quiet_hours_cross_midnight():
    q = QuietHours(enabled=True, start="23:00", end="07:00", days=["mon"])
    assert q.active("23:30", "mon", "sun") and q.active("06:59", "tue", "mon")
    assert not q.active("07:00", "tue", "mon") and not q.active("23:30", "tue", "mon")
    day = QuietHours(enabled=True, start="12:00", end="14:00")
    assert day.active("13:00", "wed", "tue") and not day.active("14:00", "wed", "tue")
    assert not QuietHours(enabled=False).active("23:30", "mon", "sun")


# ------------------------------------------------------------------ watch: local rules
def _scanner(alerts, **cfg):
    s = _settings()
    env = s.environments[0]
    ix = FakeIndexer(alerts=alerts)
    return W.Scanner(env, ix, None, WatchSettings(enabled=True, **cfg)), env


async def test_watch_level_rules_groups_and_active_response():
    web, db = AGENTS[0], AGENTS[1]
    alerts = [
        _ev(_at(3), "100213", AGENTS[2], srcip="203.0.113.9"),          # level 12 → critical level
        _ev(_at(2), "100213", AGENTS[2], srcip="203.0.113.9"),
        _ev(_at(2), "100212", web),                                     # watched rule (demo.yaml), level 5
        _ev(_at(2), "31151", web, srcip="203.0.113.10"),                # watched group web_scan at level 10
        _ev(_at(2), "5710", db, srcip="198.51.100.23"),                 # watched group but level 5 → nothing
        _ev(_at(2), "31101", web),                                      # ordinary noise
        _ev(_at(30), "100213", AGENTS[2]),                              # outside the window
    ]
    alerts[0]["rule"]["groups"] = ["web_bruteforce"]
    ar = _ev(_at(1), "550", db)
    ar["rule"].update(id="651", level=3, groups=["ossec", "active_response"], description="Host blocked by firewall-drop")
    sc, env = _scanner(alerts + [ar])
    evs = {e["key"]: e for e in await sc.alerts(_at(5), NOW)}
    assert set(evs) == {"level:100213:jenkins", "rules:100212:web01", "groups:31151:web01", "active_response:651:db01"}
    lvl = evs["level:100213:jenkins"]
    assert lvl["count"] == 2 and lvl["severity"] == "high" and lvl["srcips"] == ["203.0.113.9"]
    assert evs["active_response:651:db01"]["trigger"] == "active_response"
    sc2, _ = _scanner(alerts, critical_level=16, triggers={"rules": False, "groups": False})
    assert await sc2.alerts(_at(5), NOW) == []
    alerts[1]["rule"]["level"] = 15
    sc3, _ = _scanner(alerts)
    assert next(e for e in await sc3.alerts(_at(5), NOW) if e["trigger"] == "level")["severity"] == "critical"


async def test_watch_brute_force_then_success():
    db = AGENTS[1]
    bad = [_ev(_at(20 - i), "5710", db, srcip="198.51.100.23") for i in range(12)]
    ok = _ev(_at(2), "5715", db, srcip="198.51.100.23", dstuser="root")
    routine = _ev(_at(2), "5715", AGENTS[3], srcip="100.124.10.5", dstuser="deploy")       # no failures before it
    sc, _ = _scanner(bad + [ok, routine])
    evs = await sc.brute_force(_at(5), NOW)
    assert len(evs) == 1 and evs[0]["key"] == "brute_force:198.51.100.23" and evs[0]["severity"] == "critical"
    assert evs[0]["count"] == 12 and evs[0]["agents"] == ["db01"] and evs[0]["users"] == ["root"]
    sc, _ = _scanner(bad[:5] + [ok])
    assert await sc.brute_force(_at(5), NOW) == []                       # below the threshold
    late = [_ev(_at(1), "5710", db, srcip="198.51.100.23") for _ in range(12)]
    sc, _ = _scanner(late + [ok])
    assert await sc.brute_force(_at(5), NOW) == []                       # failures after the success


async def test_watch_spike():
    web = AGENTS[0]
    base = [_ev(_at(60 + i * 10), "31101", web) for i in range(100)]     # ~100 in the day before
    burst = [_ev(_at(0.5 + i * 0.004), "31101", web) for i in range(600)]
    sc, _ = _scanner(base + burst)
    evs = await sc.spike(_at(5), NOW)
    assert len(evs) == 1 and evs[0]["key"] == "spike:total" and evs[0]["count"] == 600 and evs[0]["factor"] > 5
    sc, _ = _scanner(base + burst[:100])
    assert await sc.spike(_at(5), NOW) == []                             # under spike_min
    sc, _ = _scanner(base + burst, triggers={"spike": False})
    assert await sc.spike(_at(5), NOW) == []


async def test_watch_agents_learns_first_then_reports():
    class API:
        def __init__(self, rows):
            self.rows = rows

        async def agents(self, status=None, search=None, limit=100):
            return self.rows

    old = (NOW - timedelta(hours=2)).isoformat()
    s = _settings()
    env = s.environments[0]
    env.ignore_agents = ["laptop-*"]
    rows = [{"name": "db01", "lastKeepAlive": old}, {"name": "laptop-ops", "lastKeepAlive": old},
            {"name": "web01", "lastKeepAlive": (NOW - timedelta(minutes=3)).isoformat()}]
    sc = W.Scanner(env, FakeIndexer(alerts=[]), API(rows), WatchSettings(enabled=True))
    evs, known = await sc.agents(NOW, None)
    assert evs == [] and known == {"db01"}                               # first scan: learn, do not announce
    evs, known = await sc.agents(NOW, set())
    assert len(evs) == 1 and evs[0]["agents"] == ["db01"] and evs[0]["severity"] == "high"
    evs, _ = await sc.agents(NOW, {"db01"})
    assert evs == []                                                     # already known


def test_sorting_out_and_channels():
    ev = {"key": "groups:31151:web01", "trigger": "groups", "severity": "high", "rule_ids": ["31151"]}
    assert W.muted(ev, ["groups:31151:web01"]) and W.muted(ev, ["groups:31151:*"]) and W.muted(ev, ["rule:31151"])
    assert not W.muted(ev, ["rule:5710", "level:*"])
    assert W.known_noise(ev, {"31151", "1"}) and not W.known_noise(ev, {"5710"})
    assert not W.known_noise({**ev, "severity": "critical"}, {"31151"})          # critical is never "known noise"
    assert not W.known_noise({**ev, "trigger": "brute_force", "rule_ids": []}, {"31151"})
    cfg = NotifyCfg(telegram=TelegramCfg(bot_token="1:x", chat_id="1"), teams=TeamsCfg(webhook_url="https://t/x"))
    assert W.channels_for(cfg, []).channels == ["telegram", "teams"]
    only = W.channels_for(cfg, ["teams"])
    assert only.channels == ["teams"] and cfg.channels == ["telegram", "teams"]  # the original is untouched


async def test_watch_scan_notifies_once_holds_in_quiet_hours_and_flushes():
    jen, web = AGENTS[2], AGENTS[0]
    alerts = [_ev(_at(2), "100213", jen, srcip="203.0.113.9"), _ev(_at(2), "31151", web, srcip="203.0.113.10")]
    rt = _rt(alerts, **TG)
    sent = _sent(rt)
    assert (await rt.watch_scan("demo", now=NOW)) == {"enabled": False}          # off by default
    await rt.save_settings("demo", {"watch": {"enabled": True}}, "admin")
    r = await rt.watch_scan("demo", transport=rt.notify_transport, now=NOW)
    assert r["events"] == 2 and r["sent"] == 2 and len(sent) == 1
    assert "not reviewed by AI" in sent[0] and "100213" in sent[0] and "rule-based alert" in sent[0]
    er = rt.get("demo")
    assert {e["status"] for e in await er.repo.list_events()} == {"notified"}
    # the same alerts again inside the repeat window: counted, not announced
    alerts.append(_ev(NOW + timedelta(minutes=2), "100213", jen, srcip="203.0.113.9"))
    r = await rt.watch_scan("demo", transport=rt.notify_transport, now=NOW + timedelta(minutes=5))
    assert r["events"] == 0 and len(sent) == 1
    ev = next(e for e in await er.repo.list_events() if e["key"] == "level:100213:jenkins")
    assert ev["count"] == 2 and ev["repeats"] == 1
    # quiet hours: a high event is held, a critical one still goes out, the held one follows afterwards
    night = datetime(2026, 11, 10, 21, 30, tzinfo=UTC)                           # 00:30 in the demo's time zone
    assert rt.tz.key == "Europe/Istanbul"
    await rt.save_settings("demo", {"watch": {"enabled": True, "quiet": {"enabled": True, "start": "23:00",
                                                                        "end": "07:00"}}}, "admin")
    hi = _ev(night - timedelta(minutes=2), "110014", AGENTS[3])
    hi["rule"]["level"] = 13
    crit = _ev(night - timedelta(minutes=2), "23505", AGENTS[1])
    crit["rule"]["level"] = 15
    alerts += [hi, crit]
    await er.repo.put_state("watch", {"cursor": (night - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                                      "disconnected": ["mail01"]})
    r = await rt.watch_scan("demo", transport=rt.notify_transport, now=night)
    assert r["quiet"] and r["events"] == 2 and r["sent"] == 1 and len(sent) == 2
    assert "23505" in sent[1] and "110014" not in sent[1]
    assert [e["key"] for e in await er.repo.list_events(status="held")] == ["level:110014:k8s-cp1"]
    r = await rt.watch_scan("demo", transport=rt.notify_transport, now=night + timedelta(hours=7))
    assert len(sent) == 3 and "110014" in sent[2] and "quiet hours" in sent[2]
    assert await er.repo.list_events(status="held") == []


async def test_watch_mute_baseline_and_selected_channel():
    web = AGENTS[0]
    alerts = [_ev(_at(2), "31151", web, srcip="203.0.113.10"), _ev(_at(2), "100212", web)]
    rt = _rt(alerts, telegram=TelegramCfg(bot_token="1:abcdefgh", chat_id="1"),
             teams=TeamsCfg(webhook_url="https://teams.example/hook"))
    hosts: list[str] = []
    rt.notify_transport = httpx.MockTransport(lambda req: (hosts.append(req.url.host), httpx.Response(200, json={}))[1])
    er = rt.get("demo")
    await er.repo.add_knowledge("baseline", "scanner noise", rule_ids=["31151"])
    await rt.save_settings("demo", {"watch": {"enabled": True, "mute": ["rule:100212"], "channels": ["teams"]}}, "a")
    r = await rt.watch_scan("demo", transport=rt.notify_transport, now=NOW)
    assert r["events"] == 2 and r["sent"] == 0 and hosts == []                   # both sorted out, nothing sent
    why = {e["key"]: e["why_silent"] for e in await er.repo.list_events()}
    assert why == {"groups:31151:web01": "baseline", "rules:100212:web01": "mute"}
    alerts.append(_ev(_at(1), "100213", AGENTS[2]))
    await er.repo.put_state("watch", {"cursor": _at(5).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "disconnected": []})
    await rt.watch_scan("demo", transport=rt.notify_transport, now=NOW + timedelta(seconds=1))
    assert hosts == ["teams.example"]                                            # only the selected channel


async def test_watch_never_calls_the_model():
    rt = _rt([_ev(_at(2), "100213", AGENTS[2])])

    def boom(env):
        raise AssertionError("the watch must not call the LLM")

    rt.llm_for = boom
    await rt.save_settings("demo", {"watch": {"enabled": True}}, "a")
    assert (await rt.watch_scan("demo", now=NOW))["events"] == 1


# ------------------------------------------------------------------ AI round: verdicts and suggestions
def test_normalize_verdicts():
    raw = [{"event_id": "w1", "verdict": "noise", "reason": "x", "suggestion": {"mute": True, "why": "daily"}},
           {"event_id": "w2", "verdict": "banana", "suggestion": {"param": "spike_factor", "value": "8"}},
           {"event_id": "w3", "verdict": "expected", "suggestion": {"param": "spike_factor", "value": 9999}},
           {"event_id": "w4", "verdict": "expected", "suggestion": {"param": "indexer.password", "value": 1}},
           {"event_id": "nope", "verdict": "noise"}, "garbage"]
    out = {v["event_id"]: v for v in W.normalize_verdicts(raw, {"w1", "w2", "w3", "w4"})}
    assert set(out) == {"w1", "w2", "w3", "w4"}
    assert out["w1"]["suggestion"] == {"type": "mute", "why": "daily"}
    assert out["w2"]["verdict"] == "investigate" and out["w2"]["suggestion"]["value"] == 8.0
    assert out["w3"]["suggestion"] is None and out["w4"]["suggestion"] is None   # out of range / not tunable
    assert W.normalize_verdicts("x", {"w1"}) == []


async def test_ai_round_judges_all_events_and_admin_applies_suggestion():
    now = datetime.now(UTC)
    web, jen = AGENTS[0], AGENTS[2]
    rt = _rt()
    er = rt.get("demo")
    er.ix.alerts += [_ev(now - timedelta(minutes=2), "100213", jen, srcip="203.0.113.9"),
                     _ev(now - timedelta(minutes=2), "31151", web, srcip="203.0.113.10")]
    await rt.save_settings("demo", {"watch": {"enabled": True, "triggers": {"spike": False, "brute_force": False}}}, "a")
    assert (await rt.watch_scan("demo", now=now))["events"] >= 2
    pending = await rt.watch_pending(er)
    run = await rt.run_triage(er, "demo-w1")                                     # mock model, one call per round
    assert run["status"] == "done" and run["watch"]["events"] == len(pending) == run["watch"]["judged"]
    events = await er.repo.list_events()
    assert all(e["status"] == "judged" and e["verdict"] for e in events)
    assert await rt.watch_pending(er) == []                                      # handed over exactly once
    noisy = next(e for e in events if e["trigger"] == "groups")
    assert noisy["verdict"] == "noise" and noisy["suggestion"] == {"type": "mute", "why": "(demo) known scanner noise",
                                                                  "state": "open"}
    assert (await rt.env_settings(er)).watch.mute == []                          # a suggestion changes nothing …
    await rt.watch_suggestion("demo", noisy["id"], "apply", "admin")
    assert (await rt.env_settings(er)).watch.mute == [noisy["key"]]              # … until an admin accepts it
    with pytest.raises(ValueError):
        await rt.watch_suggestion("demo", noisy["id"], "apply", "admin")         # only once
    assert "privacy" in run and run["privacy"]["profile_version"] == 0


async def test_param_suggestion_keeps_type_and_range():
    rt = _rt()
    er = rt.get("demo")
    await er.repo.save_event({"id": "w9", "env": "demo", "key": "spike:total", "trigger": "spike", "severity": "high",
                              "status": "judged", "created_at": "2026-11-10T00:00:00.000Z",
                              "suggestion": {"type": "param", "param": "brute_failures", "value": 25.0, "state": "open"}})
    await rt.watch_suggestion("demo", "w9", "apply", "admin")
    st = await rt.env_settings(er)
    assert st.watch.brute_failures == 25 and isinstance(st.watch.brute_failures, int)


def test_ai_schedule_from_settings_drives_the_scheduler():
    rt = _rt()
    er = rt.get("demo")
    assert rt.schedule_for(er).all_times == er.env.schedule.all_times
    er.settings = EnvSettings(ai=AiRound(times=["06:00", "18:00"]))
    assert rt.schedule_for(er).all_times == ["06:00", "18:00"]


# ------------------------------------------------------------------ masking profile, scopes (G9)
def test_pseudonyms_do_not_resolve_across_environments(monkeypatch):
    monkeypatch.setenv("PRIVACY_SALT", "k" * 32)
    a, b = privacy.Masker(scope="prod"), privacy.Masker(scope="customer")
    ta, tb = a.mask("user betul@example.com"), b.mask("user betul@example.com")
    assert ta != tb                                                              # different token per environment
    assert privacy.Masker.unmask(ta, "prod") == "user betul@example.com"
    assert privacy.Masker.unmask(ta, "customer") == ta and privacy.Masker.unmask(ta) == ta


def test_mask_profile_rules():
    with pytest.raises(ValidationError, match="cannot be switched off"):
        MaskProfile(disabled=["password"])
    with pytest.raises(ValidationError, match="unknown detector"):
        MaskProfile(disabled=["nope"])
    with pytest.raises(ValidationError, match="x_"):
        MaskProfile(custom=[{"name": "email", "pattern": r"\d+"}])
    with pytest.raises(ValidationError):
        MaskProfile(custom=[{"name": "x_a", "pattern": "(?=x)y"}])
    with pytest.raises(ValidationError, match="unique"):
        MaskProfile(custom=[{"name": "x_a", "pattern": r"A\d+"}, {"name": "x_a", "pattern": r"B\d+"}])
    with pytest.raises(ValidationError, match="longer"):
        MaskProfile(custom=[{"name": "x_a", "pattern": "a" * 300}])
    p = MaskProfile(custom=[{"name": "X_Cust", "pattern": r"CUST-\d{6}"}], allow=[r"noreply@example\.com"],
                    disabled=["phone"])
    assert p.custom[0].name == "x_cust"
    env = _settings().environments[0]
    env.privacy = env.privacy.model_copy(update={"mode": "mask"})
    m = privacy.masker_for(env, p)
    out = m.mask("CUST-123456 noreply@example.com a@b.org +90 532 123 45 67 password=hunter22")
    assert "<x_cust:" in out and "noreply@example.com" in out and "<email:" in out and "<password>" in out
    assert "+90 532 123 45 67" in out                                            # phone switched off
    assert privacy.Masker.unmask(out, env.id).startswith("CUST-123456")
    assert privacy.profile_info(env, p) == {"mode": "mask", "ips": env.privacy.ips, "profile_version": 0,
                                            "custom": ["x_cust"], "disabled": ["phone"]}
    # a profile can never switch a secret detector off, even if it tried through the masker
    assert "<password>" in privacy.Masker(disabled=["password"]).mask("password=hunter22")


def test_custom_pattern_guard_without_re2(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "re2", None)
    for ok in (r"CUST-\d{6}", r"(?i)musteri[_ ]?no[:=]\s*\d+", r"[a-z]+@corp\.local", r"(?:foo|bar)-\d+"):
        privacy.compile_custom(ok)
    for bad in (r"(a+)+$", r"(a|aa)*b", r"(?=x)y", r"(.)\1", r".*.*x", r"a*", "", r"(\w+\s?)*$", r"([a-z]+)*\d"):
        with pytest.raises(ValueError):
            privacy.compile_custom(bad)


# ------------------------------------------------------------------ storage safety
async def test_fresh_install_upgrade_and_lost_index():
    ix = FakeIndexer(alerts=[])
    st = IndexStore(ix, "daily-triage")
    h = await st.verify()
    assert h["fresh"] and h["lost"] == [] and h["initialised_at"]               # new installation: said once
    assert set(ix.docs) == {f"daily-triage-{k}" for k in ("runs", "knowledge", "events", "settings")}
    await st.put("knowledge", "k1", {"id": "k1", "env": "e"})

    st2 = IndexStore(ix, "daily-triage")                                        # restart: nothing to report
    h = await st2.verify()
    assert not h["fresh"] and h["lost"] == []

    del ix.docs["daily-triage-knowledge"]                                       # a retention policy struck
    st3 = IndexStore(ix, "daily-triage")
    h = await st3.verify()
    assert [x["kind"] for x in h["lost"]] == ["knowledge"] and "daily-triage-knowledge" in ix.docs
    assert (await IndexStore(ix, "daily-triage").verify())["lost"]              # stays until acknowledged
    assert await st3.acknowledge_loss("admin") == 1
    assert (await IndexStore(ix, "daily-triage").verify())["lost"] == []

    old = FakeIndexer(alerts=[])                                                # 0.9 installation: two indices
    old.docs = {"p-runs": {}, "p-knowledge": {"k": {"id": "k"}}}
    h = await IndexStore(old, "p").verify()
    assert not h["fresh"] and h["lost"] == [] and "p-settings" in old.docs      # upgrade is not a loss

    half = FakeIndexer(alerts=[])                                               # 0.9 installation that lost one
    half.docs = {"p-runs": {"r": {"run_id": "r"}}}
    h = await IndexStore(half, "p").verify()
    assert [x["kind"] for x in h["lost"]] == ["knowledge"]


def test_prefix_and_policy_delete_age():
    assert storagecheck.prefix_issue("wazuh-triage") == "wazuh" and storagecheck.prefix_issue("daily-triage") is None
    assert storagecheck.prefix_issue(".triage") == "system"
    pol = {"default_state": "hot", "states": [
        {"name": "hot", "actions": [], "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "30d"}}]},
        {"name": "warm", "actions": [{"read_only": {}}],
         "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "180d"}}]},
        {"name": "delete", "actions": [{"delete": {}}], "transitions": []}]}
    assert storagecheck.delete_age(pol) == 180 * 86400
    assert storagecheck.delete_age({"default_state": "a", "states": [{"name": "a", "actions": [], "transitions": []}]}) is None
    by_size = {"default_state": "a", "states": [
        {"name": "a", "actions": [], "transitions": [{"state_name": "d", "conditions": {"min_size": "50gb"}}]},
        {"name": "d", "actions": [{"delete": {}}]}]}
    assert storagecheck.delete_age(by_size) == 0                                # not age-based: assume the worst
    assert storagecheck.delete_age(None) is None


async def test_storage_report_and_flags():
    pol = {"default_state": "hot", "states": [
        {"name": "hot", "transitions": [{"state_name": "del", "conditions": {"min_index_age": "180d"}}]},
        {"name": "del", "actions": [{"delete": {}}]}]}
    ix = FakeIndexer(alerts=[])
    await IndexStore(ix, "daily-triage").verify()
    ix.ism = {"daily-triage-knowledge": {"index.plugins.index_state_management.policy_id": "six-months"},
              "daily-triage-runs": {"index.plugins.index_state_management.policy_id": None}, "total_managed_indices": 1}
    ix.policies = {"six-months": pol}
    rep = await storagecheck.storage_report(ix, "daily-triage")
    row = {r["index"]: r for r in rep["indices"]}
    assert rep["checked"] and rep["deletes"] and row["daily-triage-knowledge"]["delete_after_days"] == 180
    assert row["daily-triage-knowledge"]["deletes_on"].startswith("2026-0") and not row["daily-triage-runs"]["deletes"]

    async def denied(pattern):
        raise RuntimeError("indexer authorization error 403")

    ix.ism_explain = denied
    rep = await storagecheck.storage_report(ix, "daily-triage")
    assert not rep["checked"] and all(r["state"] == "unchecked" for r in rep["indices"]) and not rep["deletes"]

    rt = _rt()
    er = rt.get("demo")
    er.store.health = {"lost": [{"kind": "knowledge", "index": "daily-triage-knowledge",
                                 "detected_at": "2026-11-10T09:00:00.000Z"}], "initialised_at": None}
    er.env.storage_prefix = "wazuh-triage"
    codes = {f["code"]: f["severity"] for f in await rt.storage_flags(er, "en")}
    assert codes == {"storage_lost": "critical", "storage_prefix": "warn"}
    run = await rt.run_triage(er, "demo-s1")
    assert run["health"] == "critical" and any(f["code"] == "storage_lost" for f in run["flags"])


async def test_loss_and_backup_reminder_are_announced_once():
    rt = _rt(**TG)
    sent = _sent(rt)
    er = rt.get("demo")
    health = {"fresh": False, "initialised_at": "2026-01-01T00:00:00.000Z",
              "lost": [{"kind": "knowledge", "index": "daily-triage-knowledge", "detected_at": "2026-11-10T09:00:00.000Z"}]}
    await rt._storage_announce(er, health)
    assert len(sent) == 1 and "APPLICATION DATA LOST" in sent[0] and "No backup for" in sent[0]
    await rt._storage_announce(er, health)
    assert len(sent) == 1                                                        # not again
    assert await rt._storage_announce(er, {"fresh": False, "lost": [], "initialised_at": None}) is None


# ------------------------------------------------------------------ backup
def test_archive_encryption():
    blob = B.encrypt({"format": B.FORMAT, "version": 1, "data": {"knowledge": [{"id": "k1"}]}}, "correct horse battery")
    assert blob.startswith(B.MAGIC) and b"knowledge" not in blob
    assert B.decrypt(blob, "correct horse battery")["data"]["knowledge"] == [{"id": "k1"}]
    with pytest.raises(B.BackupError, match="wrong passphrase"):
        B.decrypt(blob, "another passphrase!")
    with pytest.raises(B.BackupError, match="wrong passphrase"):
        B.decrypt(blob[:-1] + bytes([blob[-1] ^ 1]), "correct horse battery")    # tampered
    with pytest.raises(B.BackupError, match="not a wazuh-daily-triage"):
        B.decrypt(b"PK\x03\x04 something else entirely, long enough to pass the size check", "x" * 12)
    with pytest.raises(B.BackupError, match="at least"):
        B.encrypt({}, "short")
    assert blob != B.encrypt({"format": B.FORMAT, "version": 1, "data": {"knowledge": [{"id": "k1"}]}},
                             "correct horse battery")                              # fresh salt and nonce


def test_import_plan_and_rule_draft_reset():
    draft = {"id": "k2", "kind": "rule_draft", "status": "active", "title": "r", "deploy": {"state": "deployed"},
             "verify": {"state": "seen"}, "approved_by": "x"}
    arch = {"data": {"knowledge": [{"id": "k1", "kind": "decision", "title": "new text"}, draft,
                                   {"id": "_live_demo", "env": "__meta__"}, {"id": "k3", "kind": "lesson"}],
                     "runs": [{"run_id": "r1"}], "events": [], "settings": {"watch": {"enabled": True}}}}
    have = {"knowledge": {"k1": {"id": "k1", "kind": "decision", "title": "old text"}}, "runs": {}, "events": {}}
    p = B.plan(arch, have, "missing")
    assert p["kinds"]["knowledge"] == {"in_archive": 4, "add": 2, "change": 0, "unchanged": 1} and not p["settings"]
    d = next(x for x in p["writes"]["knowledge"] if x["id"] == "k2")
    assert d["status"] == "proposed" and d["imported"] and "deploy" not in d and "approved_by" not in d
    assert p["rule_drafts_reset"] == 1 and all(x["id"] != "_live_demo" for x in p["writes"]["knowledge"])
    p = B.plan(arch, have, "overwrite")
    assert p["kinds"]["knowledge"]["change"] == 1 and p["settings"]
    with pytest.raises(B.BackupError):
        B.plan(arch, have, "merge")


async def test_export_then_restore_into_an_empty_installation():
    src = _rt()
    es = src.get("demo")
    await es.repo.add_knowledge("decision", "port 22 is closed on purpose", "body")
    k = await es.repo.add_knowledge("rule_draft", "draft", "x", status="active", extra={"deploy": {"state": "deployed"}})
    await src.save_settings("demo", {"watch": {"enabled": True, "critical_level": 13}}, "admin")
    await src.run_triage(es, "demo-b1")
    res = await src.backup_export("demo", "correct horse battery", "admin")
    assert res["counts"]["knowledge"] >= 2 and res["counts"]["runs"] == 1 and res["s3"] is None
    assert (await es.repo.get_state("backup"))["last_by"] == "admin"

    dst = _rt()
    ed = dst.get("demo")
    dry = await dst.backup_import("demo", res["blob"], "correct horse battery", "missing", True, "admin")
    assert dry["dry_run"] and dry["kinds"]["knowledge"]["add"] >= 2 and await ed.repo.list_knowledge() == []
    done = await dst.backup_import("demo", res["blob"], "correct horse battery", "overwrite", False, "admin")
    assert not done["dry_run"] and done["rule_drafts_reset"] == 1
    titles = {x["title"]: x for x in await ed.repo.list_knowledge()}
    assert "port 22 is closed on purpose" in titles
    assert titles["draft"]["status"] == "proposed" and "deploy" not in titles["draft"] and titles["draft"]["id"] == k["id"]
    assert (await ed.repo.get_run("demo-b1"))["status"] == "done"
    assert (await dst.env_settings(ed, fresh=True)).watch.critical_level == 13
    again = await dst.backup_import("demo", res["blob"], "correct horse battery", "missing", True, "admin")
    assert again["kinds"]["knowledge"]["add"] == 0                               # idempotent
    with pytest.raises(B.BackupError):
        await dst.backup_import("demo", res["blob"], "wrong passphrase!!", "missing", True, "admin")


def test_s3_signature_matches_the_aws_reference_shape():
    cfg = S3Cfg(endpoint="https://s3.example.com", bucket="backups", region="eu-central-1",
                access_key="AKIDEXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    url, h = B.s3_request(cfg, "wdt/demo/a b.wdtbak", b"hello", now=datetime(2026, 11, 10, 9, 0, tzinfo=UTC))
    assert url == "https://s3.example.com/backups/wdt/demo/a%20b.wdtbak"
    assert h["x-amz-date"] == "20261110T090000Z"
    assert h["x-amz-content-sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert h["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261110/eu-central-1/s3/aws4_request, "
                                         "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=")
    assert len(h["authorization"].rsplit("=", 1)[1]) == 64
    assert "wJalrXUtnFEMI" not in json.dumps(h)
    virt, h2 = B.s3_request(cfg.model_copy(update={"path_style": False}), "k", b"")
    assert virt == "https://backups.s3.example.com/k" and h2["host"] == "backups.s3.example.com"


async def test_export_to_s3_and_failure_is_reported():
    rt = _rt()
    rt.settings.backup.s3 = S3Cfg(endpoint="https://s3.example.com", bucket="b", access_key="a", secret_key="s")
    seen = {}

    def ok(req: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"], seen["body"] = str(req.url), req.headers["authorization"], req.content
        return httpx.Response(200)

    res = await rt.backup_export("demo", "correct horse battery", "admin", to_s3=True,
                                 transport=httpx.MockTransport(ok))
    assert res["s3"].startswith("s3://b/wazuh-daily-triage/demo/wdt-demo-") and seen["body"] == res["blob"]
    res = await rt.backup_export("demo", "correct horse battery", "admin", to_s3=True,
                                 transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    assert res["s3"] is None and "403" in res["s3_error"]
    assert (await rt.get("demo").repo.get_state("backup"))["s3_error"]


# ------------------------------------------------------------------ G10 / G11
class _Req:
    def __init__(self, peer, headers=None, path="/", method="GET"):
        self.client = type("C", (), {"host": peer})()
        self.headers = Headers(headers or {})
        self.url = type("U", (), {"path": path})()
        self.method = method


def test_client_ip_needs_trusted_proxies(monkeypatch):
    r = _Req("10.0.0.5", {"X-Forwarded-For": "203.0.113.7, 10.0.0.9"})
    monkeypatch.setattr(common, "TRUSTED_PROXIES", [])
    assert common.client_ip(r) == "10.0.0.5"                                     # header ignored: it can be forged
    monkeypatch.setattr(common, "TRUSTED_PROXIES", common._networks("10.0.0.0/8"))
    assert common.client_ip(r) == "203.0.113.7"                                  # right-most untrusted hop
    assert common.client_ip(_Req("198.51.100.1", {"X-Forwarded-For": "1.2.3.4"})) == "198.51.100.1"
    assert common.client_ip(_Req("10.0.0.5")) == "10.0.0.5"
    assert common._networks("10.0.0.0/8, nonsense, 192.168.1.1")[1].num_addresses == 1


def test_throttle():
    th = common.Throttle(limit=3, window=60)
    for i in range(3):
        assert not th.blocked("a", now=1000 + i)
        th.add("a", now=1000 + i)
    assert th.blocked("a", now=1003) and not th.blocked("b", now=1003)
    assert not th.blocked("a", now=1061)                                         # window passed
    assert not common.Throttle(limit=0, window=60).blocked("x")                  # 0 = unlimited


def test_proxy_checks_in_sso_mode(monkeypatch):
    monkeypatch.setattr(common, "AUTH_DISABLED", True)
    monkeypatch.setattr(common, "TRUSTED_PROXIES", [])
    monkeypatch.setattr(common, "PROXY_SECRET", "")
    monkeypatch.setattr(common, "SSO_REQUIRE_USER", True)
    assert common.proxy_problem(_Req("10.0.0.5")) == "no_user"                   # nobody logged in
    ok = {"X-Forwarded-User": "ruestem"}
    assert common.proxy_problem(_Req("10.0.0.5", ok)) == ""
    monkeypatch.setattr(common, "TRUSTED_PROXIES", common._networks("10.0.0.5"))
    assert common.proxy_problem(_Req("10.0.0.6", ok)) == "untrusted_peer"
    assert common.proxy_problem(_Req("10.0.0.5", ok)) == ""
    monkeypatch.setattr(common, "PROXY_SECRET", "s3cr3t-value")
    assert common.proxy_problem(_Req("10.0.0.5", ok)) == "proxy_secret"
    assert common.proxy_problem(_Req("10.0.0.5", {**ok, "X-WDT-Proxy-Secret": "s3cr3t-value"})) == ""
    monkeypatch.setattr(common, "AUTH_DISABLED", False)
    assert common.proxy_problem(_Req("203.0.113.1")) == ""                       # password mode: not applicable


def test_production_warns_about_unverified_proxy():
    env = {"ENVIRONMENT": "production", "AUTH_DISABLED": "true", "COOKIE_SECURE": "true", "AUDIT_LOG": "true"}
    s = _settings()
    s.environments[0].rule_deploy = s.environments[0].rule_deploy.model_copy(update={"enabled": False})
    _, w = security.validate(s, env)
    assert any("TRUSTED_PROXIES" in x for x in w)
    _, w = security.validate(s, {**env, "TRUSTED_PROXIES": "10.0.0.0/8"})
    assert not any("TRUSTED_PROXIES or PROXY_SECRET" in x for x in w)
    _, w = security.validate(s, {**env, "PROXY_SECRET": "x", "SSO_REQUIRE_USER": "false"})
    assert any("SSO_REQUIRE_USER" in x for x in w)


# ------------------------------------------------------------------ web
@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        assert client.post("/login", data={"password": "pw"}, follow_redirects=False).status_code == 303
        yield client


def test_settings_routes_are_admin_only():
    for m, p in (("GET", "/e/demo/settings"), ("GET", "/api/e/demo/settings"), ("GET", "/api/e/demo/settings/mask.yaml"),
                 ("POST", "/api/e/demo/settings"), ("POST", "/api/e/demo/backup/export"),
                 ("POST", "/api/e/demo/backup/import"), ("POST", "/api/e/demo/settings/storage/ack")):
        assert web_auth.explicit_perm(m, p) == "admin", (m, p)
    assert web_auth.explicit_perm("POST", "/api/e/demo/watch/scan") == "run"
    assert web_auth.explicit_perm("GET", "/e/demo/watch") == "read"
    with TestClient(app) as v:
        assert v.post("/login", data={"password": "vwpw"}, follow_redirects=False).status_code == 303
        assert v.get("/e/demo/watch").status_code == 200
        assert v.get("/e/demo/settings").status_code == 403
        assert v.get("/api/e/demo/settings/mask.yaml").status_code == 403
        assert v.post("/api/e/demo/backup/export", json={"passphrase": "x" * 20}).status_code == 403
        assert v.post("/api/e/demo/watch/scan").status_code == 403
        assert "/e/demo/settings" not in v.get("/e/demo").text                   # no link for the read-only role


def test_settings_page_and_save(c):
    r = c.get("/e/demo/settings")
    assert r.status_code == 200 and 'id="watch"' in r.text and 'id="backup"' in r.text and 'id="storage"' in r.text
    r = c.post("/api/e/demo/settings", json={"watch": {"enabled": True, "critical_level": 14, "channels": []},
                                             "ai": {"times": ["06:15", "18:15"]}})
    assert r.status_code == 200 and r.json()["settings"]["watch"]["critical_level"] == 14
    assert c.get("/api/e/demo/settings").json()["ai"]["times"] == ["06:15", "18:15"]
    assert "In force now: 06:15, 18:15" in c.get("/e/demo/settings").text
    assert c.post("/api/e/demo/settings", json={"watch": {"interval_minutes": 0}}).status_code == 400
    assert c.post("/api/e/demo/settings", json={"watch": {"channels": ["pager"]}}).status_code == 400
    assert c.post("/api/e/demo/settings", json={}).status_code == 400
    assert c.post("/api/e/demo/watch/scan").json()["enabled"] is True
    assert c.get("/e/demo/watch").status_code == 200
    c.post("/api/e/demo/settings", json={"ai": {"times": None}, "watch": {"enabled": False}})


def test_mask_profile_api(c):
    prof = {"custom": [{"name": "x_cust", "pattern": r"CUST-\d{6}"}], "allow": [], "disabled": []}
    r = c.post("/api/e/demo/settings/mask/preview", json={"text": "CUST-123456 a@b.org password=hunter22", "mask": prof})
    body = r.json()
    assert "<x_cust:" in body["masked"] and "<password>" in body["masked"] and body["counts"]["x_cust"] == 1
    assert c.post("/api/e/demo/settings/mask/preview",
                  json={"text": "x", "mask": {"custom": [{"name": "x_a", "pattern": "(?=x)y"}]}}).status_code == 400
    r = c.post("/api/e/demo/settings", json={"mask": prof})
    assert r.status_code == 200 and r.json()["settings"]["mask"]["version"] == 1
    assert c.post("/api/e/demo/settings", json={"mask": prof}).json()["settings"]["mask"]["version"] == 1   # unchanged
    off = {**prof, "disabled": ["email"]}
    r = c.post("/api/e/demo/settings", json={"mask": off})
    assert r.status_code == 409 and r.json()["detail"].startswith("confirm:")    # needs an explicit confirmation
    r = c.post("/api/e/demo/settings", json={"mask": off, "confirm": True})
    assert r.status_code == 200 and r.json()["settings"]["mask"]["version"] == 2
    assert c.post("/api/e/demo/settings", json={"mask": {**prof, "disabled": ["password"]}, "confirm": True}).status_code == 400
    y = c.get("/api/e/demo/settings/mask.yaml")
    assert y.status_code == 200 and "x_cust" in y.text and "wazuh-daily-triage-mask-profile" in y.text
    r = c.post("/api/e/demo/settings/mask/import", json={"text": "custom: []\nallow: ['svc@example\\.org']\ndisabled: []\n"})
    assert r.status_code == 200 and r.json()["settings"]["mask"]["allow"] == ["svc@example\\.org"]
    assert c.post("/api/e/demo/settings/mask/import", json={"text": "- just\n- a list"}).status_code == 400


def test_backup_api_round_trip(c):
    assert c.post("/api/e/demo/backup/export", json={"passphrase": "short"}).status_code == 400
    r = c.post("/api/e/demo/backup/export", json={"passphrase": "correct horse battery"})
    assert r.status_code == 200
    j = r.json()
    blob = base64.b64decode(j["data_b64"])
    assert j["filename"].endswith(".wdtbak") and blob.startswith(B.MAGIC) and j["bytes"] == len(blob)
    r = c.post("/api/e/demo/backup/import", json={"data_b64": j["data_b64"], "passphrase": "correct horse battery"})
    assert r.status_code == 200 and r.json()["dry_run"] is True and r.json()["other_env"] is False
    assert c.post("/api/e/demo/backup/import",
                  json={"data_b64": j["data_b64"], "passphrase": "not the passphrase"}).status_code == 400
    assert c.post("/api/e/demo/backup/import", json={"data_b64": "!!!", "passphrase": "x"}).status_code == 400
    assert c.post("/api/e/demo/settings/storage/ack").json()["ok"] is True


def test_mcp_rate_limit(monkeypatch):
    from app import mcp
    monkeypatch.setenv("MCP_TOKEN", "tok-123456789")
    monkeypatch.setattr(mcp, "MCP_REQUESTS", common.Throttle(limit=3, window=60))
    monkeypatch.setattr(mcp, "MCP_AUTH_FAILS", common.Throttle(limit=2, window=300))
    with TestClient(app) as cl:
        ok = {"Authorization": "Bearer tok-123456789"}
        ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        assert [cl.post("/mcp", json=ping, headers=ok).status_code for _ in range(4)] == [200, 200, 200, 429]
        monkeypatch.setattr(mcp, "MCP_REQUESTS", common.Throttle(limit=0, window=60))
        bad = {"Authorization": "Bearer wrong"}
        assert [cl.post("/mcp", json=ping, headers=bad).status_code for _ in range(3)] == [401, 401, 429]
        assert cl.post("/mcp", json=ping, headers=ok).status_code == 429          # the address is locked out for a while


async def test_automatic_backup_needs_s3_passphrase_and_the_switch():
    rt = _rt()
    calls = []

    async def fake_export(env_id, passphrase, by, **kw):
        calls.append((env_id, by, kw.get("to_s3"), kw.get("trigger")))
        return {"s3": "s3://b/x", "s3_error": None}

    rt.backup_export = fake_export
    await rt._backup_tick()
    assert calls == []                                                           # nothing configured
    rt.settings.backup.s3 = S3Cfg(endpoint="https://s3.example.com", bucket="b", access_key="a", secret_key="s")
    rt.settings.backup.passphrase = "correct horse battery"
    rt._backup_done.clear()
    await rt._backup_tick()
    assert calls == []                                                           # configured, but not switched on
    await rt.save_settings("demo", {"backup": {"auto": True}}, "admin")
    rt._backup_done.clear()
    await rt._backup_tick()
    assert calls == [("demo", "scheduler", True, "schedule")]
    await rt._backup_tick()
    assert len(calls) == 1                                                       # once a day at most


async def test_upgraded_installation_gets_the_backup_reminder_clock():
    old = FakeIndexer(alerts=[])
    old.docs = {"p-runs": {}, "p-knowledge": {}}
    h = await IndexStore(old, "p").verify()
    assert h["initialised_at"] is None and h["since"]                            # counted from the upgrade


def test_pages_render_events_suggestions_and_the_loss_banner_in_every_language(c):
    er = app.state.rt.get("demo")
    base = {"env": "demo", "created_at": "2026-11-10T09:00:00.000Z", "last_seen": "2026-11-10T09:01:00.000Z", "count": 3,
            "agents": ["web01"], "srcips": ["203.0.113.9"], "rule_ids": ["31151"], "level": 10, "sample": "GET /.env"}
    evs = [
        {**base, "id": "wr1", "key": "groups:31151:web01", "trigger": "groups", "severity": "high", "status": "judged",
         "verdict": "noise", "reason": "daily scanner", "title": "t", "suggestion": {"type": "mute", "state": "open"}},
        {**base, "id": "wr2", "key": "brute_force:1.2.3.4", "trigger": "brute_force", "severity": "critical",
         "status": "notified", "verdict": None, "title": "t", "rule_ids": []},
        {**base, "id": "wr3", "key": "spike:total", "trigger": "spike", "severity": "high", "status": "judged",
         "verdict": "expected", "reason": "patch day", "title": "t",
         "suggestion": {"type": "param", "param": "spike_factor", "value": 8.0, "why": "w", "state": "open"}},
        {**base, "id": "wr4", "key": "rules:1:web01", "trigger": "rules", "severity": "high", "status": "muted",
         "why_silent": "baseline", "verdict": None, "title": "t"},
        {**base, "id": "wr5", "key": "level:1:a", "trigger": "level", "severity": "high", "status": "held",
         "verdict": "real_incident", "reason": "r", "title": "t", "suggestion": {"type": "mute", "state": "applied"}},
    ]

    async def seed():
        for e in evs:
            await er.repo.save_event(e)

    c.portal.call(seed)
    er.store.health["lost"] = [{"kind": "knowledge", "index": "daily-triage-knowledge",
                                "detected_at": "2026-11-10T09:00:00.000Z"}]
    try:
        for lang in ("en", "tr", "es", "de"):
            c.post("/lang", data={"lang": lang})
            for p in ("/e/demo/watch", "/e/demo/watch?status=judged", "/e/demo/settings", "/", "/e/demo", "/about"):
                assert c.get(p).status_code == 200, (lang, p)
            s = c.get("/e/demo/settings").text
            assert 'id="suggestions"' in s and 'id="lost"' in s and "groups:31151:web01" in s
            assert "daily-triage-knowledge" in c.get("/").text                   # banner on every page
        r = c.post("/api/e/demo/settings/suggestion", json={"event_id": "wr3", "action": "apply"})
        assert r.json() == {"ok": True, "state": "applied"}
        assert c.get("/api/e/demo/settings").json()["watch"]["spike_factor"] == 8.0
        assert c.post("/api/e/demo/settings/suggestion", json={"event_id": "wr3", "action": "apply"}).status_code == 400
        assert c.post("/api/e/demo/settings/suggestion", json={"event_id": "wr1", "action": "dismiss"}).json()["state"] == "dismissed"
    finally:
        er.store.health["lost"] = []
        c.post("/lang", data={"lang": "en"})
