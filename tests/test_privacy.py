# SPDX-License-Identifier: AGPL-3.0-only
import asyncio

from app.config import Environment
from app.llm.base import LLMResponse, ToolCall
from app.privacy import Masker, MaskingLLM, be_nn_ok, card_ok, iban_ok, masker_for, nir_ok, scan, scan_alerts, tckn_ok
from app.redact import redact


def env(**kw):
    return Environment(id="t", name="T", indexer={"url": "https://x:9200"}, **kw)


def test_validators():
    assert tckn_ok("10000000146") and not tckn_ok("10000000147")
    assert iban_ok("TR33 0006 1005 1978 6457 8413 26") and not iban_ok("TR33 0006 1005 1978 6457 8413 27")
    assert card_ok("4539148803436467") and not card_ok("1730100000000")   # epoch ms is not a card
    assert be_nn_ok("85073003328") and nir_ok("269054958815780")


def test_run_ids_and_timestamps_untouched():
    t = "run rosca-20261028073001-712bbf at 2026-10-28T07:30:01.000+0000 ts=1730100000000 v4.14.8 port 55000"
    assert Masker().mask(t) == t
    assert redact(t) == t


def test_mask_roundtrip_and_stable_tokens():
    m = Masker()
    a = m.mask("login betul@example.com from 10.0.0.1; again betul@example.com")
    assert "betul@example.com" not in a and "10.0.0.1" in a
    toks = [w for w in a.replace(";", " ").split() if w.startswith("<email:")]
    assert len(set(toks)) == 1
    assert Masker.unmask(a) == "login betul@example.com from 10.0.0.1; again betul@example.com"
    s = m.mask('password=Hunter2 "token":"abc123" Authorization: Bearer abcdefgh.ijk')
    assert "Hunter2" not in s and "abc123" not in s and "abcdefgh" not in s
    assert "Hunter2" not in Masker.unmask(s)          # secrets are irreversible


def test_ips_public_mode_and_allow():
    m = Masker(ips="public", allow=[r"noreply@example\.com"])
    out = m.mask("10.1.1.1 8.8.8.8 noreply@example.com x@y.org")
    assert "10.1.1.1" in out and "8.8.8.8" not in out and "noreply@example.com" in out and "x@y.org" not in out


def test_privacy_config_alias():
    assert env(redact=True).privacy.mode == "mask"
    assert masker_for(env()) is None and masker_for(env(privacy={"mode": "mask"})) is not None


def test_masking_llm_boundary():
    seen = {}

    class Fake:
        name = "fake"

        async def complete(self, system, messages, tools, force_tool=None):
            seen["sys"], seen["msgs"] = system, messages
            tok = next(w for w in messages[0]["content"].split() if w.startswith("<email:"))
            return LLMResponse(text=f"user {tok}", tool_calls=[ToolCall("1", "search_alerts", {"q": tok})])

    llm = MaskingLLM(Fake(), Masker())
    r = asyncio.run(llm.complete("ctx admin@corp.example", [{"role": "user", "content": "who is a.b@corp.example ?"}], []))
    assert "a.b@corp.example" not in seen["msgs"][0]["content"] and "admin@corp.example" not in seen["sys"]
    assert r.text == "user a.b@corp.example" and r.tool_calls[0].input == {"q": "a.b@corp.example"}


def test_scan_alerts_groups_and_masks_examples():
    hits = [{"_source": {"full_log": "POST /login?user=ali&password=S3cret! tckn=10000000146",
                         "rule": {"id": "31101", "description": "web"}, "agent": {"name": "web1"},
                         "location": "/var/log/nginx/access.log"}},
            {"_source": {"full_log": "ok", "rule": {"id": "1"}, "agent": {"name": "a"}}}]
    r = scan_alerts(hits)
    assert r["affected_alerts"] == 1 and r["kinds"]["password"] == 1 and r["kinds"]["national_id_tr"] == 1
    ex = r["sources"][0]["example"]
    assert "S3cret" not in ex and "10000000146" not in ex
    assert scan("nothing here 12345") == {}


def test_personal_data_in_rule_description():
    r = scan_alerts([{"_source": {"full_log": "x", "rule": {"id": "300215", "description": "PII access - jane@corp.example"},
                                  "agent": {"name": "app"}, "location": "api"}}])
    assert r["sources"][0].get("in_rule_description") and "jane@corp.example" not in r["sources"][0]["example"]


def test_inbox_fuzzy_grouping():
    from app.review import ReviewMixin as ReviewOps
    a = {"label": "real_incident", "rule_ids": ["5712", "5763"], "agents": ["odooserver"], "title": "SSH brute force"}
    b = {"label": "investigate", "rule_ids": ["5763"], "agents": ["odooserver"], "title": "Kaba kuvvet SSH"}
    c = {"label": "investigate", "rule_ids": ["5763"], "agents": ["web1"], "title": "x"}
    d = {"label": "real_incident", "rule_ids": [], "agents": ["sfdsdb1"], "title": "sfdsdb1 /archives disk 100%"}
    e = {"label": "real_incident", "rule_ids": [], "agents": ["sfdsdb1"], "title": "/archives disk 100% on sfdsdb1"}
    assert ReviewOps.same_finding(a, b) and not ReviewOps.same_finding(a, c) and ReviewOps.same_finding(d, e)


def test_app_language_from_env(tmp_path, monkeypatch):
    from app.config import load_settings
    p = tmp_path / "e.yaml"
    p.write_text("environments:\n  - id: r\n    name: R\n    indexer: {url: 'https://x:9200'}\n")
    monkeypatch.setenv("APP_LANGUAGE", "tr")
    monkeypatch.setenv("TZ", "Europe/Istanbul")
    s = load_settings(p)
    assert s.app.language == "tr" and s.app.timezone == "Europe/Istanbul"


def test_yaml_bare_off(tmp_path):
    from app.config import load_settings
    p = tmp_path / "e.yaml"
    p.write_text("environments:\n  - id: r\n    name: R\n    indexer: {url: 'https://x:9200'}\n"
                 "    privacy: {mode: off, ips: public}\n  - id: s\n    name: S\n    indexer: {url: 'https://x:9200'}\n"
                 "    privacy: {mode: mask}\n")
    s = load_settings(p)
    assert s.environments[0].privacy.mode == "off" and s.environments[1].privacy.mode == "mask"
    assert load_settings("config/environments.example.yaml").environments


def test_kb_txt_and_csv_formats():
    from app.kbformats import parse_import, template
    items = parse_import("[karar] Jenkins açık kalsın\nkurallar: 100212, 100213\nKabul edilmiş risk.\n---\n"
                         "# yorum\n[gürültü] 31101 tarayıcılar\nNormal.\n---\nbozuk blok", "")
    assert items[0] == {"kind": "decision", "title": "Jenkins açık kalsın", "rule_ids": ["100212", "100213"],
                        "body": "Kabul edilmiş risk."}
    assert items[1]["kind"] == "baseline" and "_error" in items[2]
    csv_text = template("csv", "tr")[0]
    rows = parse_import(csv_text, "k.csv")
    assert rows[1]["kind"] == "baseline" and rows[1]["rule_ids"] == ["31101", "100211"]
    assert parse_import("- kind: Karar\n  title: x\n")[0]["kind"] == "decision"
