# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""0.11: SSO roles from the proxy's group header, the dashboard numbers, ATT&CK matrix and charts."""
from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app import charts, dash, demo, mitre, security  # noqa: E402
from app.config import load_settings  # noqa: E402
from app.reporting import normalize_report, technique_ids  # noqa: E402
from app.web import auth as web_auth  # noqa: E402
from app.web import common  # noqa: E402


class _Req:
    def __init__(self, ip="10.0.0.5"):
        self.client = type("C", (), {"host": ip})()
        self.cookies = {}


class _Hdr(dict):
    def get(self, k, d=None):
        return super().get(k.lower(), d)


def _req(headers=None):
    r = _Req()
    r.headers = _Hdr({k.lower(): v for k, v in (headers or {}).items()})
    return r


@pytest.fixture
def sso(monkeypatch):
    monkeypatch.setattr(common, "AUTH_DISABLED", True)
    monkeypatch.setattr(common, "SSO_ADMIN_GROUPS", {"wazuh-admins"})
    monkeypatch.setattr(common, "SSO_VIEWER_GROUPS", set())
    monkeypatch.setattr(common, "SSO_DEFAULT_ROLE", "viewer")
    return monkeypatch


def test_group_parsing():
    assert common._group_set("Wazuh-Admins|soc, /Ops ;x") == {"wazuh-admins", "soc", "ops", "x"}
    assert common._group_set("") == set()


def test_sso_role_from_groups(sso):
    assert common.role(_req({"X-authentik-groups": "soc|wazuh-admins"})) == "admin"
    assert common.role(_req({"X-Forwarded-Groups": "/Wazuh-Admins"})) == "admin"          # Keycloak full path
    assert common.role(_req({"X-Forwarded-Groups": "soc"})) == "viewer"                   # default role
    assert common.role(_req({})) == "viewer"
    sso.setattr(common, "SSO_VIEWER_GROUPS", {"soc"})
    sso.setattr(common, "SSO_DEFAULT_ROLE", "deny")
    assert common.role(_req({"X-Auth-Request-Groups": "soc"})) == "viewer"
    assert common.role(_req({"X-Auth-Request-Groups": "sales"})) is None                  # no role → refused
    sso.setattr(common, "SSO_DEFAULT_ROLE", "admin")
    assert common.role(_req({})) == "admin"                                               # pre-0.11 behaviour


def test_sso_viewer_cannot_change_anything(sso):
    from app.main import app
    sso.setattr(common, "TRUSTED_PROXIES", [])
    sso.setattr(common, "PROXY_SECRET", "")
    sso.setattr(common, "SSO_REQUIRE_USER", True)
    sso.setattr(web_auth, "AUTH_DISABLED", True)
    with TestClient(app) as c:
        viewer = {"X-Forwarded-User": "ayse", "X-Forwarded-Groups": "soc"}
        admin = {"X-Forwarded-User": "ruestem", "X-Forwarded-Groups": "wazuh-admins"}
        r = c.get("/", headers=viewer)
        assert r.status_code == 200 and 'class="role-badge viewer"' in r.text
        assert c.post("/api/e/demo/run", headers=viewer).status_code == 403
        assert c.get("/e/demo/settings", headers=viewer).status_code == 403
        assert c.get("/e/demo/settings", headers=admin).status_code == 200
        sso.setattr(common, "SSO_DEFAULT_ROLE", "deny")
        r = c.get("/", headers={"X-Forwarded-User": "eve", "X-Forwarded-Groups": "sales"})
        assert r.status_code == 403


def test_security_warns_about_sso_roles():
    env = {"ENVIRONMENT": "production", "AUTH_DISABLED": "true", "TRUSTED_PROXIES": "10.0.0.0/8"}
    s = load_settings("config/demo.yaml")
    s.environments[0].rule_deploy = s.environments[0].rule_deploy.model_copy(update={"enabled": False})
    _, w = security.validate(s, env)
    assert any("SSO_ADMIN_GROUPS" in x for x in w)
    _, w = security.validate(s, {**env, "SSO_ADMIN_GROUPS": "wazuh-admins"})
    assert not any("SSO_ADMIN_GROUPS" in x for x in w)
    _, w = security.validate(s, {**env, "SSO_DEFAULT_ROLE": "admin"})
    assert any("SSO_DEFAULT_ROLE=admin" in x for x in w)


# ------------------------------------------------------------------ numbers
@pytest.fixture(scope="module")
def data():
    s = load_settings("config/demo.yaml")
    now = datetime.now(UTC)
    return s.environments[0], demo.FakeIndexer(demo.generate(now=now)), now


def test_overview(data):
    env, ix, now = data
    o = asyncio.run(dash.overview(env, ix, "24h", now=now, use_cache=False))
    assert o["total"] == sum(s["total"] for s in o["series"]) and o["total"] > 0
    assert sum(b["count"] for b in o["bands"]) == o["total"]
    assert o["high"] >= o["crit"] > 0
    names = [t["tactic"] for t in o["tactics"]]
    assert names[:3] == ["Reconnaissance", "Resource Development", "Initial Access"] and len(names) >= 14
    cred = next(t for t in o["tactics"] if t["tactic"] == "Credential Access")
    assert cred["count"] > 0 and cred["heat"] == "h5"
    assert o["top_sources"][0]["ip"] == "192.0.2.45"


def test_matrix(data):
    env, ix, now = data
    m = asyncio.run(mitre.matrix(env, ix, days=7, now=now))
    assert [c["tactic"] for c in m["columns"][:14]] == mitre.TACTIC_NAMES
    assert 0 < m["mapped"] <= m["total"]
    cred = next(c for c in m["columns"] if c["tactic"] == "Credential Access")
    assert {c["id"] for c in cred["cells"]} >= {"T1110", "T1110.001"}
    assert "Exfiltration" in m["silent"]
    t = next(x for x in m["techniques"] if x["id"] == "T1110.001")
    assert t["url"] == "https://attack.mitre.org/techniques/T1110/001/" and t["new"]


def test_enrich_and_normalize(data):
    env, ix, now = data
    rep = normalize_report({"findings": [{"title": "x", "detail": "y", "rule_ids": ["5712"],
                                          "mitre": ["t1110", "bogus", "T1078.004", "T1110"]}]})
    assert rep["findings"][0]["mitre"] == ["T1110", "T1078.004"]
    asyncio.run(mitre.enrich_mitre(env, ix, rep["findings"], now - timedelta(days=1), now))
    f = rep["findings"][0]
    assert f["mitre"][:2] == ["T1110", "T1078.004"] and f["mitre_tactics"] == ["Credential Access"]
    assert technique_ids(["T1", "T12345", "T1059.001"]) == ["T1059.001"]


def test_tactic_names_and_heat():
    assert mitre.canonical_tactic("credential access") == "Credential Access"
    assert mitre.canonical_tactic("Something Else") == "Something Else"
    assert [mitre.heat_class(n, 100) for n in (0, 1, 5, 10, 30, 80)] == ["h0", "h1", "h2", "h3", "h4", "h5"]
    assert mitre.attack_url("TA0006").endswith("/tactics/TA0006/")


def test_charts_are_safe_svg():
    s = [{"t": f"2026-11-11T0{i}:00:00Z", "total": i * 10, "high": i} for i in range(6)]
    svg = charts.area(s, [("total", "c-total", "All <b>"), ("high", "c-high", "High")], "Volume <x>",
                      xlabel=lambda p: p["t"][11:16])
    assert svg.startswith("<svg") and "style=" not in svg and "<b>" not in svg and "&lt;x&gt;" in svg
    assert "<title>" in svg
    d = charts.donut([("a", 3, "c-crit"), ("b", 0, "c-low"), ("c", 1, "c-high")], "lvl", center="4")
    assert d.count('class="seg') == 2
    assert charts.nice_max(73) == 100 and charts.nice_max(0) == 1 and charts.compact(12500) == "12.5k"
    assert charts.area([], [("total", "c", "x")], "e") == ""


def test_pages_render(data):
    from app.main import app
    with TestClient(app) as c:
        assert c.post("/login", data={"password": "pw"}, follow_redirects=False).status_code == 303
        for url in ("/", "/?period=7d", "/?env=demo&period=30d", "/e/demo/attack", "/e/demo/attack?days=30"):
            r = c.get(url)
            assert r.status_code == 200, url
            assert "<svg" in r.text and 'style="' not in r.text.split("<main>")[1], url
        r = c.get("/e/demo/attack")
        assert "Credential Access" in r.text and "T1110" in r.text
