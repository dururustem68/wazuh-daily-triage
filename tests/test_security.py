# SPDX-License-Identifier: AGPL-3.0-only
"""Security posture: role/environment authorization, audit trail, query guard rails, startup checks."""
import json
import os

import pytest

from app import auditlog, authz, security
from app.agent.tools import ToolBox
from app.config import load_settings
from app.demo import FakeAPI, FakeIndexer
from app.query_guard import QueryError, check_interval, field, parse_time, query_string, size, time_range
from app.store import MemoryStore, Repo

ROOT = os.path.dirname(os.path.dirname(__file__))


# ------------------------------------------------------------------ authorization
def test_permission_matrix():
    assert authz.permitted("viewer", authz.READ)
    for perm in (authz.RUN, authz.DECIDE, authz.KNOWLEDGE, authz.DEPLOY, authz.ADMINISTER):
        assert not authz.permitted("viewer", perm)
        assert authz.permitted("admin", perm)
    assert authz.permitted(None, authz.DEPLOY)          # auth delegated to a proxy = admin


def test_env_scope(monkeypatch):
    monkeypatch.delenv("ADMIN_ENVS", raising=False)
    monkeypatch.delenv("VIEWER_ENVS", raising=False)
    assert authz.env_scope("admin") is None and authz.may_access_env("admin", "prod")
    monkeypatch.setenv("ADMIN_ENVS", "staging, lab")
    monkeypatch.setenv("VIEWER_ENVS", "lab")
    assert authz.env_scope("admin") == {"staging", "lab"}
    assert authz.may_access_env("admin", "staging") and not authz.may_access_env("admin", "prod")
    assert authz.may_access_env("viewer", "lab") and not authz.may_access_env("viewer", "staging")


def test_mcp_envs(monkeypatch):
    monkeypatch.delenv("MCP_ENVS", raising=False)
    assert authz.mcp_envs(["prod", "lab"]) == {"prod", "lab"}
    monkeypatch.setenv("MCP_ENVS", "lab")
    assert authz.mcp_envs(["prod", "lab"]) == {"lab"}


# ------------------------------------------------------------------ metrics
def test_metrics_render_is_valid_prometheus():
    from app.observability import Metrics
    m = Metrics()
    m.inc("wdt_runs_total", trigger="schedule")
    m.inc("wdt_runs_total", trigger="manual")
    m.observe("wdt_run_seconds", 1.5)
    m.observe("wdt_run_seconds", 2.5)
    text = m.render()
    assert text.count("# TYPE wdt_runs_total counter") == 1          # one TYPE per family
    assert 'wdt_runs_total{trigger="schedule"} 1' in text
    assert "wdt_run_seconds_count 2" in text and "wdt_run_seconds_sum 4" in text
    assert 'quantile="0.95"' in text
    for line in text.splitlines():
        if line and not line.startswith("#"):
            assert line.rsplit(" ", 1)[1].replace(".", "").replace("-", "").isdigit(), line
    assert "wdt_build_info" in text and "wdt_uptime_seconds" in text

    # the sample window is bounded (memory), the counters stay cumulative
    for i in range(5000):
        m.observe("wdt_http_request_seconds", i / 1000, method="GET")
    h = m._h[("wdt_http_request_seconds", (("method", "GET"),))]
    assert h["count"] == 5000 and len(h["vals"]) == m.WINDOW


# ------------------------------------------------------------------ audit trail
def test_audit_hash_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG", "true")
    p = tmp_path / "audit.jsonl"
    auditlog.configure(p)
    auditlog.record("rule.deploy", actor="ui", role="admin", env="prod", target="k1", result="deployed")
    auditlog.record("login", actor="ui", role="admin", result="ok")
    lines = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2 and lines[0]["prev"] is None and lines[1]["prev"] == lines[0]["hash"]
    assert auditlog.verify(p)["ok"] and auditlog.verify(p)["lines"] == 2

    # tampering with a line breaks the chain (that is the point of the hash)
    lines[0]["actor"] = "someone-else"
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    v = auditlog.verify(p)
    assert not v["ok"] and v["broken"]["line"] == 1


def test_audit_never_raises_on_unwritable_path(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG", "true")
    auditlog.configure(tmp_path)          # a directory cannot be opened for append
    assert auditlog.record("login", actor="x", role="admin") is None


def test_audit_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG", "false")
    p = tmp_path / "audit.jsonl"
    auditlog.configure(p)
    assert auditlog.record("login", actor="x") is None and not p.exists()


def test_audit_rotation_keeps_generations_verifiable(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG", "true")
    monkeypatch.setattr(auditlog, "MAX_BYTES", 10)
    p = tmp_path / "audit.jsonl"
    auditlog.configure(p)
    auditlog.record("first", actor="a", role="admin")
    auditlog.record("second", actor="b", role="admin")      # size >= 10 → rotate, new chain
    assert auditlog.verify(p)["ok"]
    assert [json.loads(x)["action"] for x in p.with_suffix(".jsonl.1").read_text(encoding="utf-8").splitlines()] \
        == ["first"]
    assert [json.loads(x)["action"] for x in p.read_text(encoding="utf-8").splitlines()] == ["second"]

    auditlog.record("third", actor="c", role="admin")       # .1 → .2, second → .1
    assert p.with_suffix(".jsonl.2").exists()
    assert [json.loads(x)["action"] for x in p.with_suffix(".jsonl.2").read_text(encoding="utf-8").splitlines()] \
        == ["first"]
    for f in (p, p.with_suffix(".jsonl.1"), p.with_suffix(".jsonl.2")):
        assert auditlog.verify(f)["ok"]


# ------------------------------------------------------------------ query guard
def test_parse_time():
    from datetime import UTC, datetime
    now = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
    assert parse_time("now", now) == now
    assert (now - parse_time("now-6h", now)).total_seconds() == 6 * 3600
    assert parse_time("2026-10-27T09:00:00Z", now).hour == 9
    with pytest.raises(QueryError):
        parse_time("yesterday", now)


def test_time_range_limit():
    a, b = time_range("now-6h", "now", 24)
    assert (b - a).total_seconds() == pytest.approx(6 * 3600, abs=2)
    with pytest.raises(QueryError, match="maximum"):
        time_range("now-40d", "now", 24 * 14)
    with pytest.raises(QueryError, match="after"):
        time_range("now", "now-1h", 24)


def test_field_allowlist():
    assert field("rule.id") == "rule.id"
    assert field("data.custom", extra=["data.custom"]) == "data.custom"
    with pytest.raises(QueryError, match="allow-listed"):
        field("data.custom")
    with pytest.raises(QueryError):
        field("rule.id},")


def test_size_and_interval():
    assert size(1000, 25) == 25 and size(3, 25) == 3
    with pytest.raises(QueryError):
        size(0, 25)
    assert size("7", 25) == 7
    with pytest.raises(QueryError):
        check_interval("1m", "1m", 24 * 7, 200)        # 10 080 buckets
    assert check_interval("1h", "1m", 24, 200) == "1h"
    with pytest.raises(QueryError, match="smaller"):
        check_interval("10s", "1m", 1, 200)


def test_query_string_sanity():
    assert query_string("  ") is None
    assert query_string("data.srcip:192.0.2.1") == "data.srcip:192.0.2.1"
    with pytest.raises(QueryError, match="unbalanced"):
        query_string("(a AND b")
    with pytest.raises(QueryError, match="too long"):
        query_string("a OR " * 600)


# ------------------------------------------------------------------ tool integration
async def test_tools_reject_expensive_or_unknown_queries():
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    env.query = env.query.model_copy(update={"max_range_hours": 24})
    tb = ToolBox(env, FakeIndexer(), FakeAPI(), Repo(MemoryStore(), env.id), mode="tools")

    out = json.loads(await tb.call("aggregate_alerts", {"field": "not.a.field"}))
    assert "allow-listed" in out["error"] and "hint" in out

    out = json.loads(await tb.call("search_alerts", {"from": "now-40d"}))
    assert "maximum" in out["error"]

    out = json.loads(await tb.call("rule_timeline", {"from": "now-24h", "interval": "1m"}))
    assert "buckets" in out["error"]

    out = json.loads(await tb.call("aggregate_alerts", {"field": "agent.name"}))
    assert out["field"] == "agent.name" and out["buckets"]


# ------------------------------------------------------------------ startup validation
def _prod_env(**kw):
    e = {"ENVIRONMENT": "production", "APP_PASSWORD": "s3cret-very-long", "APP_SECRET": "x" * 64,
         "COOKIE_SECURE": "true", "AUDIT_LOG": "true"}
    e.update(kw)
    return e


def _settings():
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    e = s.environments[0]
    e.rule_deploy = e.rule_deploy.model_copy(update={"enabled": False})   # no deploy user in this fixture
    return s


def test_production_config_is_accepted():
    errors, warnings = security.validate(_settings(), _prod_env())
    assert not errors, errors


def test_production_rejects_example_password():
    errors, _ = security.validate(_settings(), _prod_env(APP_PASSWORD="change-me"))
    assert any("APP_PASSWORD" in e for e in errors)


def test_production_requires_secret_and_secure_cookie():
    errors, _ = security.validate(_settings(), _prod_env(APP_SECRET="", COOKIE_SECURE="false"))
    assert any("APP_SECRET" in e for e in errors) and any("COOKIE_SECURE" in e for e in errors)


def test_production_allows_documented_exceptions():
    errors, _ = security.validate(_settings(), _prod_env(COOKIE_SECURE="false", WDT_ALLOW_INSECURE_COOKIE="1"))
    assert not errors


def test_production_rejects_demo_mode():
    errors, warnings = security.validate(_settings(), _prod_env(AUTH_DISABLED="true"), demo=True)
    assert any("WDT_DEMO" in e for e in errors)
    assert any("AUTH_DISABLED" in w for w in warnings)


def test_development_only_warns():
    errors, warnings = security.validate(_settings(), {"APP_PASSWORD": "change-me"})
    assert not errors and any("example value" in w for w in warnings)


def test_production_requires_deploy_credentials():
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    e = s.environments[0]
    e.rule_deploy = e.rule_deploy.model_copy(update={"enabled": True, "username": "", "password": ""})
    errors, _ = security.validate(s, _prod_env())
    assert any("rule_deploy.enabled" in x for x in errors)


def test_check_raises_in_production():
    with pytest.raises(security.SecurityError, match="refusing to start"):
        security.check(_settings(), _prod_env(APP_PASSWORD="admin"))
