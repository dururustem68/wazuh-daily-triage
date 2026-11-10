# SPDX-License-Identifier: AGPL-3.0-only
"""0.9.2 hardening: pseudonym key, cross-origin writes, fail-closed permissions, error texts, Lucene
field allow-list, SMTP checks, fail-closed audit trail, credentials in logs."""
import json
import logging
import os

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app import auditlog, authz, notify, privacy, security  # noqa: E402
from app.agent.tools import ToolBox  # noqa: E402
from app.config import load_settings  # noqa: E402
from app.demo import FakeAPI, FakeIndexer  # noqa: E402
from app.errors import classify, public_error  # noqa: E402
from app.main import app  # noqa: E402
from app.observability import ScrubFilter, install_logging, scrub  # noqa: E402
from app.query_guard import QueryError, field, query_string  # noqa: E402
from app.sources import SourceError, SourcePolicyError  # noqa: E402
from app.store import MemoryStore, Repo  # noqa: E402
from app.wazuh.indexer import Indexer, IndexerError  # noqa: E402
from app.web import auth as web_auth  # noqa: E402


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        assert client.post("/login", data={"password": "pw"}, follow_redirects=False).status_code == 303
        yield client


def _settings():
    s = load_settings(os.path.join(ROOT, "config/demo.yaml"))
    e = s.environments[0]
    e.rule_deploy = e.rule_deploy.model_copy(update={"enabled": False})
    return s


def _prod_env(**kw):
    e = {"ENVIRONMENT": "production", "APP_PASSWORD": "s3cret-very-long", "APP_SECRET": "x" * 64,
         "COOKIE_SECURE": "true", "AUDIT_LOG": "true"}
    e.update(kw)
    return e


# ------------------------------------------------------------------ G1 pseudonym key
def test_pseudonym_key_has_no_public_default(monkeypatch):
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.delenv("PRIVACY_SALT", raising=False)
    monkeypatch.setattr(privacy, "_random_salt", None)
    a = privacy._salt()
    assert a != b"wdt-privacy" and len(a) == 32 and privacy._salt() == a      # random, stable in the process
    assert privacy.salt_source() == "random"
    monkeypatch.setattr(privacy, "_random_salt", None)
    assert privacy._salt() != a                                                # a new process draws a new key
    monkeypatch.setenv("APP_SECRET", "app")
    assert privacy._salt() == b"app" and privacy.salt_source() == "APP_SECRET"
    monkeypatch.setenv("PRIVACY_SALT", "salt")
    assert privacy._salt() == b"salt" and privacy.salt_source() == "PRIVACY_SALT"


def test_pseudonym_is_64_bit_and_round_trips(monkeypatch):
    monkeypatch.setenv("PRIVACY_SALT", "k" * 32)
    m = privacy.Masker()
    out = m.mask("login by betul@example.com")
    tok = out.split("by ")[1]
    assert tok.startswith("<email:") and len(tok) == len("<email:>") + 16
    assert privacy.Masker.unmask(out) == "login by betul@example.com"
    monkeypatch.setenv("PRIVACY_SALT", "another-key" * 3)
    assert privacy.Masker().mask("login by betul@example.com") != out          # the key decides the token


def test_startup_reports_missing_or_short_pseudonym_key():
    s = _settings()
    s.environments[0].privacy = s.environments[0].privacy.model_copy(update={"mode": "mask"})
    _, w = security.validate(s, {"AUTH_DISABLED": "true"})
    assert any("PRIVACY_SALT" in x and "random" in x for x in w)
    _, w = security.validate(s, {"APP_SECRET": "short"})
    assert any("shorter than 16" in x for x in w)
    _, w = security.validate(s, {"PRIVACY_SALT": "x" * 40})
    assert not any("PRIVACY_SALT" in x for x in w)
    s.environments[0].privacy = s.environments[0].privacy.model_copy(update={"mode": "off"})
    _, w = security.validate(s, {})
    assert not any("PRIVACY_SALT" in x for x in w)


# ------------------------------------------------------------------ G2 cross-origin writes
def test_cross_origin_writes_are_refused(c):
    url = "/api/e/demo/liveness"
    assert c.post(url).status_code != 403                                            # no browser headers: a script
    assert c.post(url, headers={"Origin": "http://testserver"}).status_code != 403   # same origin
    assert c.post(url, headers={"Sec-Fetch-Site": "same-origin"}).status_code != 403
    for h in ({"Origin": "https://evil.example"},
              {"Origin": "https://other.testserver"},                                # sibling sub-domain
              {"Origin": "null"},
              {"Referer": "https://evil.example/page"},
              {"Sec-Fetch-Site": "cross-site"},
              {"Sec-Fetch-Site": "same-site", "Origin": "https://shop.testserver"}):
        r = c.post(url, headers=h)
        assert r.status_code == 403 and "cross-origin" in r.json()["error"], h
    assert c.get("/", headers={"Origin": "https://evil.example"}).status_code == 200   # reads are not affected
    r = c.post("/login", data={"password": "pw"}, headers={"Origin": "https://evil.example"},
               follow_redirects=False)
    assert r.status_code == 403                                                      # login CSRF


def test_origin_behind_a_proxy(c, monkeypatch):
    url = "/api/e/demo/liveness"
    h = {"Origin": "https://wdt.example.org", "X-Forwarded-Host": "wdt.example.org"}  # proxy rewrote Host
    assert c.post(url, headers=h).status_code != 403
    assert c.post(url, headers={"Origin": "https://wdt.example.org:8443"}).status_code == 403
    monkeypatch.setattr(web_auth, "TRUSTED_ORIGINS", {"https://wdt.example.org:8443"})
    assert c.post(url, headers={"Origin": "https://wdt.example.org:8443"}).status_code != 403
    assert web_auth._netloc("https://Host.Example:443/x") == "host.example"
    assert web_auth._netloc("host.example:8080") == "host.example:8080"


def test_mcp_is_exempt_from_the_origin_check(c):
    r = c.post("/mcp", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code in (401, 404)            # its own bearer token decides, not the origin


# ------------------------------------------------------------------ G3 permissions fail closed
def test_unmapped_write_route_needs_admin():
    assert web_auth.required_perm("POST", "/api/e/demo/brand-new-thing") == authz.ADMINISTER
    assert web_auth.required_perm("DELETE", "/api/e/demo/settings") == authz.ADMINISTER
    assert web_auth.required_perm("GET", "/api/e/demo/brand-new-thing") == authz.READ
    assert web_auth.required_perm("POST", "/logout") == authz.READ
    assert not authz.permitted("viewer", web_auth.required_perm("POST", "/api/e/demo/brand-new-thing"))


def test_every_write_route_has_an_explicit_permission():
    public = {"/login", "/lang", "/mcp"}
    missing = []
    for r in app.routes:
        methods = getattr(r, "methods", None) or set()
        path = getattr(r, "path", "")
        for m in methods - {"GET", "HEAD", "OPTIONS"}:
            if path not in public and web_auth.explicit_perm(m, path) is None:
                missing.append(f"{m} {path}")
    assert not missing, f"add these routes to web.auth.explicit_perm: {missing}"


# ------------------------------------------------------------------ G4 error texts
def test_public_error_hides_the_exception_text():
    e = IndexerError("indexer 400 POST /wazuh-alerts-*/_search: {\"error\":{\"reason\":\"secret-index-name\"}}")
    pub, ref = public_error(e)
    assert pub["kind"] == "bad_query" and pub["ref"] == ref and len(ref) == 8
    assert "secret-index-name" not in json.dumps(pub) and "_search" not in json.dumps(pub)
    assert classify(IndexerError("cannot reach indexer (https://10.1.2.3:9200): boom")) == "unreachable"
    assert classify(IndexerError("indexer query timed out after 30s (https://x)")) == "timeout"
    assert classify(IndexerError("indexer rejected the query (429, too many requests): x")) == "busy"
    assert classify(IndexerError("indexer authorization error 403 /x: no")) == "auth"
    assert classify(SourceError("404 /api/v1/x: nope")) == "not_found"
    assert classify(SourceError("cannot reach http://10.0.0.400:9090: x")) == "unreachable"
    assert classify(KeyError("x")) == "internal" and classify(httpx.ReadTimeout("x")) == "timeout"


async def test_tool_errors_do_not_leak_internals(caplog):
    env = _settings().environments[0]

    class Boom(FakeIndexer):
        async def search(self, index, body):
            raise IndexerError("cannot reach indexer (https://admin:hunter2@10.9.8.7:9200): refused")

    tb = ToolBox(env, Boom(), FakeAPI(), Repo(MemoryStore(), env.id), mode="mcp")
    with caplog.at_level(logging.WARNING, logger="wdt"):
        out = json.loads(await tb.call("search_alerts", {}))
    assert out["kind"] == "unreachable" and "10.9.8.7" not in json.dumps(out) and "hunter2" not in json.dumps(out)
    assert out["ref"] in caplog.text and "10.9.8.7" in caplog.text        # the operator still sees the cause


def test_policy_errors_stay_readable_for_the_model():
    assert issubclass(SourcePolicyError, SourceError)


# ------------------------------------------------------------------ G5 Lucene field allow-list
@pytest.mark.parametrize("q", [
    "data.srcip:192.0.2.10 AND rule.groups:sshd",
    'sshd AND "Failed password: for root"',
    "rule.level:[10 TO 15]",
    "timestamp:[2026-11-01T10:00:00 TO now]",
    "-rule.id:5710 +agent.name:web*",
    "(rule.id:5710 OR rule.id:5712) AND NOT data.srcuser:root",
    'data.url:"/a/b?c=d:e"',
    "full_log:/fail.*/",
    "_exists_:data.srcip",
    'data.srcip:"2001:db8::1"',
    "data.url:\\/api\\/v1",
    "error 2026-11-01T10:00:00",
])
def test_query_string_accepts_allow_listed_fields(q):
    assert query_string(q) == q


@pytest.mark.parametrize("q,why", [
    ("secret.field:x", "allow-listed"),
    ("rule.id:1 AND _id:5", "allow-listed"),
    ("(internal.token:abc)", "allow-listed"),
    ("_exists_:password", "allow-listed"),
    ("data.*:x", "pattern"),
    ("*admin", "leading"),
    ("rule.id:*710", "leading"),
    ("a* b* c* d* e* f* g* h* i*", "wildcards"),
    ("full_log:/a/ OR full_log:/b/ OR full_log:/c/", "regex"),
    ("full_log:/" + "a" * 100 + "/", "regex"),
])
def test_query_string_rejects(q, why):
    with pytest.raises(QueryError, match=why):
        query_string(q)


def test_extra_fields_and_subtrees():
    assert query_string("data.custom:1", ["data.custom"]) == "data.custom:1"
    assert field("data.win.system.eventID", ["data.win.*"]) == "data.win.system.eventID"
    with pytest.raises(QueryError):
        field("data.winx", ["data.win.*"])
    with pytest.raises(QueryError):
        field("anything", [".*"])


async def test_tool_query_is_guarded_and_bounded():
    env = _settings().environments[0]
    seen = {}

    class Spy(FakeIndexer):
        async def search(self, index, body):
            seen["body"] = body
            return await super().search(index, body)

    tb = ToolBox(env, Spy(), FakeAPI(), Repo(MemoryStore(), env.id), mode="tools")
    out = json.loads(await tb.call("search_alerts", {"query": "manager.secret:1"}))
    assert "allow-listed" in out["error"] and "body" not in seen                 # never reached the indexer
    await tb.call("search_alerts", {"query": "rule.groups:sshd"})
    qs = next(f["query_string"] for f in seen["body"]["query"]["bool"]["filter"] if "query_string" in f)
    assert qs["allow_leading_wildcard"] is False and qs["max_determinized_states"] <= 10000


async def test_indexer_search_has_a_server_side_timeout():
    env = _settings().environments[0]
    bodies = []

    def handler(req: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"timed_out": len(bodies) > 1, "hits": {"total": {"value": 0}, "hits": []}})

    ix = Indexer(env.indexer, transport=httpx.MockTransport(handler))
    try:
        await ix.search("wazuh-alerts-*", {"size": 0})
        assert bodies[0]["timeout"].endswith("s") and int(bodies[0]["timeout"][:-1]) >= 1
        with pytest.raises(IndexerError, match="timed out"):                       # partial answers are not used
            await ix.search("wazuh-alerts-*", {"size": 0})
    finally:
        await ix.close()


# ------------------------------------------------------------------ G6 SMTP
def _mail(**kw):
    s = _settings()
    base = {"host": "smtp.example.org", "sender": "wdt@example.org", "to": ["soc@example.org"]}
    s.notify = s.notify.model_copy(update={"email": notify.EmailCfg(**{**base, **kw})})
    return s


def test_production_checks_smtp():
    errors, warnings = security.validate(_mail(), _prod_env())
    assert not errors and not any("email" in w for w in warnings)
    errors, _ = security.validate(_mail(security="none", username="u", password="p"), _prod_env())
    assert any("clear text" in e for e in errors)
    errors, warnings = security.validate(_mail(security="none"), _prod_env())
    assert not errors and any("unencrypted" in w for w in warnings)
    _, warnings = security.validate(_mail(security="none"), _prod_env(WDT_ALLOW_INSECURE_SMTP="1"))
    assert not any("unencrypted" in w for w in warnings)
    errors, _ = security.validate(_mail(verify_tls=False), _prod_env())
    assert any("verify_tls" in e for e in errors)
    errors, _ = security.validate(_mail(verify_tls=False), _prod_env(WDT_ALLOW_INSECURE_TLS="1"))
    assert not errors
    errors, _ = security.validate(_mail(security="tls"), _prod_env())
    assert any("starttls, ssl or none" in e for e in errors)
    errors, _ = security.validate(_mail(security="none", username="u"), {})        # not production: no check
    assert not errors


def test_unknown_smtp_security_never_means_plain_text():
    cfg = notify.EmailCfg(host="127.0.0.1", port=1, sender="a@b.c", to=["d@e.f"], security="tls")
    with pytest.raises(RuntimeError, match="starttls, ssl, none"):
        notify._send_email(cfg, {"title": "t", "text": "x"})


# ------------------------------------------------------------------ G7 audit trail fails closed
def test_audit_strict_defaults():
    assert auditlog.strict({"ENVIRONMENT": "production"}) and not auditlog.strict({})
    assert not auditlog.strict({"ENVIRONMENT": "production", "AUDIT_STRICT": "false"})
    assert auditlog.strict({"AUDIT_STRICT": "true"})


def test_writes_are_refused_without_an_audit_trail(c, tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    before = auditlog.path()
    try:
        auditlog.configure(blocker / "audit.jsonl")            # parent is a file: cannot be written
        assert not auditlog.writable()
        monkeypatch.setenv("AUDIT_STRICT", "true")
        r = c.post("/api/e/demo/liveness")
        assert r.status_code == 503 and "audit" in r.json()["error"]
        assert c.get("/").status_code == 200                   # reading still works
        assert c.post("/lang", data={"lang": "en"}, follow_redirects=False).status_code == 303
        monkeypatch.setenv("AUDIT_STRICT", "false")
        assert c.post("/api/e/demo/liveness").status_code != 503
        assert auditlog.record("x") is None                    # lost, logged and counted — never raises
        monkeypatch.setenv("AUDIT_STRICT", "true")
        auditlog.configure(tmp_path / "ok" / "audit.jsonl")
        assert auditlog.available() and c.post("/api/e/demo/liveness").status_code != 503
    finally:
        auditlog.configure(before)


# ------------------------------------------------------------------ G8 credentials in logs
def test_scrub_removes_tokens_and_webhook_urls():
    tok = "123456:AAH-secret_token_value"
    assert tok not in scrub(f'HTTP Request: POST https://api.telegram.org/bot{tok}/sendMessage "HTTP/1.1 200 OK"')
    teams = ("https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke"
             "?api-version=2016-06-01&sig=SECRETSIG")
    out = scrub(f"POST {teams} failed")
    assert "SECRETSIG" not in out and "abc" not in out and "logic.azure.com" in out
    assert "B000/XXXX" not in scrub("https://hooks.slack.com/services/T000/B000/XXXX")
    assert "abcDEF" not in scrub("https://discord.com/api/webhooks/123/abcDEF")
    assert "s3cr3t" not in scrub("GET https://x.example/api?token=s3cr3t&page=2") and "page=2" in scrub(
        "GET https://x.example/api?token=s3cr3t&page=2")
    assert "abc.def" not in scrub("headers {'Authorization': 'Bearer abc.def'}")
    assert scrub("custom failure my-private-value here", "my-private-value") == "custom failure *** here"
    keep = "GET https://indexer:9200/wazuh-alerts-*/_search 200"
    assert scrub(keep) == keep


def test_log_filter_and_httpx_level():
    install_logging("INFO")
    assert logging.getLogger("httpx").level >= logging.WARNING
    assert logging.getLogger("httpcore").level >= logging.WARNING
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "POST %s", ("https://api.telegram.org/bot1:abcdefgh/x",),
                            None)
    ScrubFilter().filter(rec)
    assert "abcdefgh" not in rec.getMessage()


async def test_notification_errors_do_not_carry_the_webhook():
    url = "https://example.org/hooks/in/very-secret-path"

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {req.url}")

    cfg = notify.NotifyCfg(webhook=notify.WebhookCfg(url=url, token="tok-123456"),
                           telegram=notify.TelegramCfg(bot_token="999:ZZZsecretZZZ", chat_id="1"))
    res = await notify.send(cfg, notify.plain_message("t", ["l"]), transport=httpx.MockTransport(handler))
    assert set(res) == {"webhook", "telegram"}
    assert "very-secret-path" not in json.dumps(res) and "ZZZsecretZZZ" not in json.dumps(res)
