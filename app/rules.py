# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Rule drafts: extraction, safety analysis, manual commands and (opt-in) deployment.

Deployment is the ONLY write path towards Wazuh in this application. It is off unless an environment sets
`rule_deploy.enabled: true` with a separate API user, it writes to a single dedicated rules file, and every
change is validated by the manager before restart and rolled back automatically if anything fails.
"""
from __future__ import annotations

import asyncio
import re
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from .config import RuleDeployCfg
from .wazuh.api import WazuhAPI, WazuhAPIError

HEREDOC = "WDT_RULE_EOF"
POLL_FIRST, POLL_EVERY = 5.0, 4.0   # seconds; tests shorten these
_BLOCK = r"<!-- wdt:begin {kid} -->.*?<!-- wdt:end {kid} -->\n?"


# ----------------------------------------------------------------------------- extraction
def extract_xml(entry: dict) -> str:
    """The XML of a rule draft: the explicit `xml` field, else the <group>/<rule> elements inside the body."""
    if (entry.get("xml") or "").strip():
        return entry["xml"].strip()
    body = entry.get("body") or ""
    fenced = re.findall(r"```(?:xml)?\s*\n(.*?)```", body, re.S)
    for f in fenced:
        if "<rule" in f:
            return f.strip()
    m = re.search(r"<group\b.*</group>", body, re.S)
    if m:
        return m.group(0).strip()
    m = re.search(r"<rule\b.*</rule>", body, re.S)
    return m.group(0).strip() if m else ""


def _normalise(xml: str) -> str:
    """Rules must sit inside <group>; wrap bare <rule> elements."""
    if re.match(r"\s*<group\b", xml):
        return xml
    return f'<group name="wazuh-daily-triage,">\n{xml}\n</group>'


# ----------------------------------------------------------------------------- analysis
def parse(xml: str) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    rules: list[dict] = []
    if not xml.strip():
        return [], ["no rule XML found in this entry"]
    if "wdt:" in xml or HEREDOC in xml:
        errors.append("XML contains reserved markers (wdt: / heredoc terminator)")
    try:
        root = ET.fromstring(f"<root>{_normalise(xml)}</root>")
    except ET.ParseError as e:
        return [], [f"XML error: {e}"]
    for top in root:
        if top.tag != "group":
            errors.append(f"top-level <{top.tag}> is not allowed; only <group>")
    for r in root.iter("rule"):
        opts = [o.text.strip() for o in r.iter("options") if o.text]
        parents = [x.strip() for t in ("if_sid", "if_matched_sid") for el in r.iter(t)
                   for x in re.split(r"[,\s]+", el.text or "") if x.strip()]
        rules.append({"id": r.get("id"), "level": r.get("level"), "overwrite": r.get("overwrite") == "yes",
                      "options": opts, "parents": parents,
                      "if_group": [el.text for el in r.iter("if_group")] + [el.text for el in r.iter("if_matched_group")]})
    if not rules:
        errors.append("no <rule> element")
    return rules, errors


async def analyse(xml: str, cfg: RuleDeployCfg, api: WazuhAPI | None, high_level: int = 7) -> dict:
    """Errors block deployment; `risky` (silencing / level lowering) needs a second, typed confirmation."""
    rules, errors = parse(xml)
    risky: list[str] = []
    ids = [r["id"] for r in rules]
    for r in rules:
        rid, lvl = r["id"], r["level"]
        if not rid or not rid.isdigit():
            errors.append(f"rule without numeric id: {rid!r}")
            continue
        if not (cfg.id_min <= int(rid) <= cfg.id_max):
            errors.append(f"rule {rid}: id outside the allowed range {cfg.id_min}-{cfg.id_max}")
        if lvl is None or not lvl.isdigit():
            errors.append(f"rule {rid}: missing or invalid level")
            continue
        if int(lvl) == 0:
            risky.append(f"rule {rid}: level 0 — matching events will NOT raise alerts")
        if r["overwrite"]:
            risky.append(f"rule {rid}: overwrite=\"yes\" replaces an existing rule")
        for o in r["options"]:
            if o in ("no_log", "no_full_log", "no_email_alert", "no_ar"):
                risky.append(f"rule {rid}: <options>{o}</options>")
    if len(set(ids)) != len(ids):
        errors.append("duplicate rule ids in the draft")
    parents_info: dict[str, dict] = {}
    if api and not errors:
        want = sorted({p for r in rules for p in r["parents"]} | set(ids))
        try:
            for x in await api.rules(want):
                parents_info[str(x["id"])] = x
        except WazuhAPIError as e:
            errors.append(f"cannot check existing rules: {e}")
        for rid in ids:
            ex = parents_info.get(rid)
            if ex and ex.get("filename") != cfg.file:
                errors.append(f"rule {rid} already exists in {ex.get('filename')} (id collision)")
        for r in rules:
            for p in r["parents"]:
                pl = parents_info.get(p, {}).get("level")
                if pl is not None and r["level"] and r["level"].isdigit() and int(r["level"]) < int(pl):
                    risky.append(f"rule {r['id']}: lowers level {pl} → {r['level']} for child events of {p}")
                if p not in parents_info:
                    errors.append(f"rule {r['id']}: parent rule {p} does not exist")
                    continue
                pi = parents_info[p]
                # etc/rules files load alphabetically: a parent in a later file is not known yet
                if pi.get("relative_dirname") == "etc/rules" and pi.get("filename") != cfg.file \
                        and str(pi.get("filename", "")) > cfg.file:
                    errors.append(f"rule {r['id']}: parent {p} is in {pi.get('filename')}, which loads after "
                                  f"{cfg.file} (alphabetical) — rename rule_deploy.file, e.g. zz_{cfg.file}")
    return {"ok": not errors, "errors": errors, "risky": sorted(set(risky)), "ids": ids,
            "xml": _normalise(xml), "parents": {k: {"level": v.get("level"), "description": v.get("description"),
                                                    "filename": v.get("filename")} for k, v in parents_info.items()}}


# ----------------------------------------------------------------------------- file content
def block(kid: str, xml: str, title: str = "") -> str:
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%MZ")
    t = re.sub(r"-{2,}", "-", re.sub(r"[^\w .,:/()-]", "", title))[:120].rstrip("-")
    return f"<!-- wdt:begin {kid} -->\n<!-- {t} · {stamp} -->\n{_normalise(xml)}\n<!-- wdt:end {kid} -->\n"


def with_block(content: str | None, kid: str, xml: str, title: str = "") -> str:
    base = remove_block(content or "", kid)
    if not base.strip():
        base = "<!-- Managed by wazuh-daily-triage: approved rule drafts. Edit with care. -->\n"
    return base.rstrip("\n") + "\n\n" + block(kid, xml, title)


def remove_block(content: str, kid: str) -> str:
    return re.sub(_BLOCK.format(kid=re.escape(kid)), "", content, flags=re.S)


# ----------------------------------------------------------------------------- manual commands
def commands(kid: str, xml: str, cfg: RuleDeployCfg, title: str = "", ids: list[str] | None = None,
             tests: list[dict] | None = None) -> str:
    f = f"/var/ossec/etc/rules/{cfg.file}"
    first = (ids or ["?"])[0]
    lines = [
        f"# wazuh-daily-triage — {title}",
        "# Run as root on the Wazuh manager (the MASTER node in a cluster; workers receive rules from it).",
        "# Kubernetes/Docker: kubectl exec -it <master-pod> -- bash, then paste.",
        f'F={f}; B="$F.bak.$(date +%Y%m%d-%H%M%S)"',
        '[ -f "$F" ] && cp -a "$F" "$B" || { touch "$F"; B=; }',
        f"sed -i '/<!-- wdt:begin {kid} -->/,/<!-- wdt:end {kid} -->/d' \"$F\"   # previous version of this draft",
        f"cat >> \"$F\" <<'{HEREDOC}'",
        block(kid, xml, title).rstrip("\n"),
        HEREDOC,
        'chown wazuh:wazuh "$F" 2>/dev/null; chmod 660 "$F"',
        "# syntax/ruleset check — restores the backup and stops if it fails",
        'if ! /var/ossec/bin/wazuh-analysisd -t; then echo "INVALID - restoring"; '
        '[ -n "$B" ] && cp -a "$B" "$F" || rm -f "$F"; false; fi',
        "systemctl restart wazuh-manager 2>/dev/null || /var/ossec/bin/wazuh-control restart",
        f"grep -c 'id=\"{first}\"' \"$F\"   # 1 = in the file",
    ]
    if tests:
        lines.append("# logtest: paste each event into /var/ossec/bin/wazuh-logtest")
        for t in tests[:6]:
            lines.append(f"#   expect {t.get('expect', 'match')}: {str(t.get('event', ''))[:300]}")
    lines += [
        "# Roll back:",
        f"#   sed -i '/<!-- wdt:begin {kid} -->/,/<!-- wdt:end {kid} -->/d' {f} && systemctl restart wazuh-manager",
    ]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- deployment
class DeployError(RuntimeError):
    steps: list[dict] | None = None


async def _wait_back(api: WazuhAPI, ids: list[str], file: str, timeout: int, present: bool = True) -> str:
    """After a restart: wait for analysisd and (un)loaded rules. Returns a short status line."""
    deadline = time.monotonic() + timeout
    await asyncio.sleep(POLL_FIRST)
    last = ""
    while time.monotonic() < deadline:
        try:
            api.reset_token()
            st = await api.manager_status()
            if st.get("wazuh-analysisd") == "running":
                found = {str(r["id"]) for r in await api.rules(ids) if r.get("filename") == file} if ids else set()
                if (set(ids) <= found) if present else not found:
                    return "analysisd running, rules " + ("loaded" if present else "removed")
                last = f"rules loaded: {sorted(found)}"
            else:
                last = f"analysisd {st.get('wazuh-analysisd')}"
        except WazuhAPIError as e:
            last = str(e)[:160]
        await asyncio.sleep(POLL_EVERY)
    raise DeployError(f"manager did not come back as expected within {timeout}s ({last})")


async def _run_tests(api: WazuhAPI, ids: list[str], tests: list[dict]) -> list[dict]:
    out = []
    for t in tests[:6]:
        d = await api.logtest(t["event"], t.get("log_format", "syslog"), t.get("location", "daily-triage"))
        rid = str(((d.get("output") or {}).get("rule") or {}).get("id", ""))
        want = t.get("expect", "match") == "match"
        out.append({"expect": "match" if want else "no_match", "got_rule": rid, "ok": (rid in ids) == want})
    return out


async def apply(api: WazuhAPI, cfg: RuleDeployCfg, kid: str, xml: str, ids: list[str], title: str = "",
                tests: list[dict] | None = None, remove: bool = False) -> list[dict]:
    """Write (or remove) one draft's block, validate, restart, verify; roll back on any failure."""
    steps: list[dict] = []

    def step(name, ok=True, detail=""):
        steps.append({"step": name, "ok": ok, "detail": str(detail)[:500]})

    cluster = await api.cluster_running()
    step("cluster" if cluster else "standalone manager", True, "restart via /cluster/restart" if cluster else "")
    old = await api.rule_file_get(cfg.file)
    step("read " + cfg.file, True, "new file" if old is None else f"{len(old)} bytes")
    new = remove_block(old or "", kid) if remove else with_block(old, kid, xml, title)
    if remove and new == (old or ""):
        step("nothing to remove", True)
        return steps

    async def rollback(reason: str):
        step("rollback", True, reason)
        try:
            if old is not None:
                await api.rule_file_put(cfg.file, old)
            else:  # the file did not exist before: remove it (needs rules:delete), else leave an empty file
                try:
                    await api.rule_file_delete(cfg.file)
                except WazuhAPIError:
                    await api.rule_file_put(cfg.file, "<!-- Managed by wazuh-daily-triage. -->\n")
            v = await api.config_validation(cluster)
            if all(x.get("status") == "OK" for x in v):
                await api.restart(cluster)
                await _wait_back(api, [], cfg.file, cfg.restart_timeout)
            step("rollback done", True)
        except (WazuhAPIError, DeployError) as e:
            step("rollback FAILED — check the manager now", False, e)

    try:
        try:
            await api.rule_file_put(cfg.file, new)
        except WazuhAPIError as e:
            # nothing was written: no rollback, no restart
            hint = ""
            if "Permission denied" in str(e) or "4000" in str(e):
                hint = (f" — the deploy user needs rules:update on *:*:* and rules:delete on rule:file:{cfg.file}"
                        " (overwrite); see docs/rule-deployment.md")
            step("upload", False, f"{e}{hint}")
            step("nothing was changed", True, "the rule file and the manager are untouched")
            err = DeployError(f"upload refused{hint}")
            err.steps = steps
            raise err from e
        step("upload", True)
        val = await api.config_validation(cluster)
        bad = [x for x in val if x.get("status") != "OK"]
        if bad:
            step("validation", False, bad)
            await rollback("validation failed — restart skipped")
            raise DeployError("manager rejected the configuration")
        step("validation", True, "OK")
        await api.restart(cluster)
        step("restart requested", True)
        step("manager back", True, await _wait_back(api, ids, cfg.file, cfg.restart_timeout, present=not remove))
        if tests and not remove:
            res = await _run_tests(api, ids, tests)
            ok = all(r["ok"] for r in res)
            step("logtest", ok, "; ".join(f"{r['expect']} → {r['got_rule'] or '-'} {'✓' if r['ok'] else '✗'}" for r in res))
            if not ok:
                await rollback("logtest expectations not met")
                raise DeployError("logtest failed")
    except WazuhAPIError as e:
        step("error", False, e)
        await rollback(str(e)[:200])
        err = DeployError(str(e))
        err.steps = steps
        raise err from e
    except DeployError as e:
        if not any(s["step"] in ("rollback", "nothing was changed") for s in steps):
            step("error", False, e)
            await rollback("manager did not come back")
        e.steps = steps
        raise
    return steps
