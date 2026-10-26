# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Promotion package: turn a tested rule draft into a permanent rule in your own configuration management.

The application never touches your repository or the manager here. It generates, for the operator:
  * the rule block with a provenance comment, to append to your rules file,
  * a draft § for your alert catalogue (measurement, rule table, protected cases, risk acceptance, verification),
  * a script that backs the file up, appends the block, pre-tests it with `wazuh-analysisd -t` on a running
    manager, rolls it out (kubectl apply -k, or a manager restart on a host) and checks that it loaded.
If the draft is currently deployed by this application (rule_deploy.file), it must be removed there first —
the same rule ID in two files would be a duplicate; the script refuses to continue while it is still there.
"""
from __future__ import annotations

import re
import shlex
from datetime import UTC, datetime

from .config import Environment
from .i18n import t
from .rules import parse


def _ts(lang: str) -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def rule_table(xml: str) -> list[dict]:
    rules, _ = parse(xml)
    rows = []
    for r in rules:
        cond = "; ".join(r.get("conditions") or [])
        if r.get("frequency"):
            cond = (cond + "; " if cond else "") + f"frequency {r['frequency']} / {r.get('timeframe')} s"
        if r.get("ignore"):
            cond = (cond + "; " if cond else "") + f"ignore {r['ignore']} s"
        rows.append({"id": r["id"], "parents": ", ".join(r["parents"]) or ", ".join(x for x in r["if_group"] if x),
                     "level": r["level"], "condition": cond, "description": r.get("description", "")})
    return rows


def block(entry: dict, xml: str) -> str:
    title = re.sub(r"-{2,}", "-", entry.get("title", ""))[:150]
    return (f"<!-- {_ts('')} — {title}\n"
            f"     source: wazuh-daily-triage {entry.get('id')}; rationale, protected cases and risk acceptance:\n"
            f"     see the alert catalogue. -->\n{xml.strip()}\n")


def catalog_md(entry: dict, xml: str, analysis: dict, lang: str, actor: str = "") -> str:
    L = lang
    rows = rule_table(xml)
    out = [f"## § ? {entry.get('title', '')} — {_ts(L)}", "",
           f"**{t(L, 'pr.measure')}** {entry.get('body', '').strip() or '…'}", "",
           f"| ID | {t(L, 'pr.parent')} | {t(L, 'pr.level')} | {t(L, 'pr.condition')} | {t(L, 'pr.desc')} |",
           "|---|---|---|---|---|"]
    for r in rows:
        cond, desc = (r[k].replace("|", "\\|") for k in ("condition", "description"))
        out.append(f"| {r['id']} | {r['parents']} | {r['level']} | {cond} | {desc} |")
    out += ["", f"**{t(L, 'pr.protected')}** …", ""]
    risky = analysis.get("risky") or []
    out.append(f"**{t(L, 'pr.risk')}** " + ("; ".join(risky) + " — …" if risky else "…"))
    v = entry.get("verify") or {}
    dep = entry.get("deploy") or {}
    ver = []
    if dep.get("steps"):
        lt = next((s for s in dep["steps"] if str(s.get("step", "")).startswith("logtest")), None)
        if lt:
            ver.append(f"logtest: {lt.get('detail', '')}")
    if v.get("seen"):
        ver.append(t(L, "pr.verified", n=sum(x["n"] for x in v["seen"].values()), last=v.get("last") or ""))
    else:
        ver.append(t(L, "pr.not_verified"))
    out += ["", f"**{t(L, 'pr.verification')}** " + " · ".join(ver), "",
            t(L, "pr.approval", who=actor or "…", d=_ts(L))]
    return "\n".join(out) + "\n"


def script(env: Environment, entry: dict, xml: str, ids: list[str]) -> str:
    c = env.promote
    kid = entry.get("id", "")
    deploy_file = env.rule_deploy.file
    blk = block(entry, xml)
    first = ids[0] if ids else ""
    q = shlex.quote
    head = ["#!/usr/bin/env bash",
            f"# wazuh-daily-triage — promote {kid} ({', '.join(ids)}) into {c.rules_file}",
            "# Generated; read it before running. Re-running is safe: it stops if the rule is already there.",
            "set -euo pipefail",
            f"KID={q(kid)}; FIRST_ID={q(first)}",
            'STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT="${OUT:-wdt-promote-$KID-$STAMP.log}"',
            'exec > >(tee -a "$OUT") 2>&1',
            "BLOCK=$(cat <<'WDT_BLOCK_EOF'", blk.rstrip("\n"), "WDT_BLOCK_EOF", ")"]
    if c.mode == "kubernetes":
        body = [
            *( [f"export KUBECONFIG={q(c.kubeconfig)}"] if c.kubeconfig else []),
            f"cd {q(c.repo_dir or '.')}",
            f"F={q(c.rules_file)}; NS={q(c.namespace)}; POD={q(c.master_pod)}; KDIR={q(c.kustomize_dir or '.')}",
            f"DEPLOY_FILE=/var/ossec/etc/rules/{deploy_file}",
            'RF=/var/ossec/etc/rules/$(basename "$F")',
            'k(){ timeout -k 5 120 kubectl -n "$NS" "$@"; }',
            'echo "== 1. checks"',
            '[ -f "$F" ] || { echo "rules file $F not found"; exit 1; }',
            'if grep -q "id=\\"$FIRST_ID\\"" "$F"; then echo "rule $FIRST_ID is already in $F — nothing to do"; exit 0; fi',
            'if k exec "$POD" -- grep -q "wdt:begin $KID" "$DEPLOY_FILE" 2>/dev/null; then',
            '  echo "the draft is still deployed in $DEPLOY_FILE — press Remove in wazuh-daily-triage first"; exit 1; fi',
            'echo "== 2. backup + append"',
            'mkdir -p "${BACKUP_DIR:-.wdt-backup}"; cp -p "$F" "${BACKUP_DIR:-.wdt-backup}/$(basename "$F").before-$STAMP"',
            'printf "\\n%s\\n" "$BLOCK" >> "$F"',
            'echo "== 3. pre-test on the running manager (wazuh-analysisd -t), original restored afterwards"',
            'k exec "$POD" -- cp -p "$RF" "/tmp/wdt-orig.xml"',
            'k cp "$F" "$POD:$RF" >/dev/null',
            'set +e; T=$(k exec "$POD" -- /var/ossec/bin/wazuh-analysisd -t 2>&1); RC=$?; set -e',
            'k exec "$POD" -- sh -c "cat /tmp/wdt-orig.xml > $RF && rm -f /tmp/wdt-orig.xml"',
            'echo "$T" | grep -E "ERROR|CRITICAL|7617|7619|5107" || true',
            'if [ $RC -ne 0 ] || echo "$T" | grep -qE "CRITICAL|ERROR"; then',
            '  echo "pre-test FAILED — restoring $F"; cp -p "${BACKUP_DIR:-.wdt-backup}/$(basename "$F").before-$STAMP" "$F"; exit 1; fi',
            'echo "   pre-test OK"',
            'echo "== 4. kubectl apply -k $KDIR"',
            'kubectl kustomize "$KDIR" >/dev/null',
            'k apply -k "$KDIR"',
            'echo "== 5. waiting for the manager StatefulSets (no rollout status: it hangs behind some proxies)"',
            'for s in $(k get sts -o name | grep -i manager); do',
            '  for i in $(seq 1 90); do',
            '    J=$(k get "$s" -o jsonpath="{.spec.replicas} {.status.updatedReplicas} {.status.readyReplicas} {.status.currentRevision} {.status.updateRevision}")',
            '    set -- $J; if [ "${1:-x}" = "${2:-y}" ] && [ "${1:-x}" = "${3:-z}" ] && [ "${4:-a}" = "${5:-b}" ]; then echo "   $s ready"; break; fi',
            '    sleep 10; done; done',
            'echo "== 6. loaded?"',
            'k exec "$POD" -- grep -l "id=\\"$FIRST_ID\\"" /var/ossec/etc/rules/ -r',
            'k exec "$POD" -- sh -c "tail -n 300 /var/ossec/logs/ossec.log | grep -E \'CRITICAL|7617|7619|5107\' || echo \'   no rule errors in ossec.log\'"',
            'echo "done — log: $OUT. Next: add the catalogue §, then mark the draft as promoted in wazuh-daily-triage."',
        ]
    else:
        body = [
            "# run on the Wazuh manager as root",
            f"F={q(c.rules_file)}",
            f"DEPLOY_FILE=/var/ossec/etc/rules/{deploy_file}",
            'echo "== 1. checks"',
            '[ -f "$F" ] || { echo "rules file $F not found"; exit 1; }',
            'if grep -q "id=\\"$FIRST_ID\\"" "$F"; then echo "rule $FIRST_ID is already in $F — nothing to do"; exit 0; fi',
            'if grep -q "wdt:begin $KID" "$DEPLOY_FILE" 2>/dev/null; then',
            '  echo "the draft is still deployed in $DEPLOY_FILE — press Remove in wazuh-daily-triage first"; exit 1; fi',
            'echo "== 2. backup (outside etc/rules: every file there is loaded) + append"',
            'mkdir -p /var/ossec/backup; cp -p "$F" "/var/ossec/backup/$(basename "$F").before-$STAMP"',
            'printf "\\n%s\\n" "$BLOCK" >> "$F"',
            'echo "== 3. pre-test"',
            'set +e; T=$(/var/ossec/bin/wazuh-analysisd -t 2>&1); RC=$?; set -e',
            'echo "$T" | grep -E "ERROR|CRITICAL|7617|7619|5107" || true',
            'if [ $RC -ne 0 ] || echo "$T" | grep -qE "CRITICAL|ERROR"; then',
            '  echo "pre-test FAILED — restoring"; cp -p "/var/ossec/backup/$(basename "$F").before-$STAMP" "$F"; exit 1; fi',
            'echo "== 4. restart"',
            'systemctl restart wazuh-manager',
            'sleep 10; /var/ossec/bin/wazuh-control status | grep -E "analysisd|remoted"',
            'tail -n 200 /var/ossec/logs/ossec.log | grep -E "CRITICAL|7617|7619|5107" || echo "   no rule errors in ossec.log"',
            'echo "done — log: $OUT"',
        ]
    return "\n".join(head + body) + "\n"


def package(env: Environment, entry: dict, xml: str, analysis: dict, lang: str, actor: str = "") -> dict:
    ids = analysis.get("ids") or []
    deployed = (entry.get("deploy") or {}).get("state") == "deployed"
    c = env.promote
    steps = []
    if deployed:
        steps.append(t(lang, "pr.step_remove", file=env.rule_deploy.file, btn=t(lang, "rd.undeploy")))
    steps.append(t(lang, "pr.step_script_k8s" if c.mode == "kubernetes" else "pr.step_script_host",
                   file=c.rules_file))
    if c.catalog_file:
        steps.append(t(lang, "pr.step_catalog", file=c.catalog_file))
    steps.append(t(lang, "pr.step_mark"))
    return {"ids": ids, "mode": c.mode, "rules_file": c.rules_file, "catalog_file": c.catalog_file,
            "still_deployed": deployed, "steps": steps, "block": block(entry, xml),
            "catalog_md": catalog_md(entry, xml, analysis, lang, actor),
            "script": script(env, entry, xml, ids)}
