# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Evaluation: replay past windows and compare the AI's findings with what a human concluded.

    python -m app.eval cases.yaml                         # current model
    python -m app.eval cases.yaml --model deepseek-flash  # compare models / prompts
    kubectl exec -i deploy/wazuh-daily-triage -- python -m app.eval - --model deepseek-v4-pro < cases.yaml

Nothing is written: runs are not saved, AI proposals are discarded. Case format (YAML list):

  - name: Monday after the weekend
    env: prod
    from: 2026-10-23T08:30:00Z
    to:   2026-10-26T08:30:00Z
    expect:                       # each must appear among the findings
      - id: ssh-bruteforce
        rules: ["5712", "5763"]   # match by rule id …
        keywords: [odooserver]    # … and/or words in title/detail/agents (all must match when both given)
        labels: [real_incident, investigate]   # optional: acceptable labels
    forbid:                       # known noise: must NOT be reported as an incident / to investigate
      - id: wp-updates
        rules: ["100591", "100594"]
        labels_ok: [expected, baseline_increase, measurement, false_positive, correction]   # default

Limits: the knowledge base is today's (it may know things the past did not); tools that are not time-bound
(agent status, vulnerabilities) answer with today's state.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime

import yaml

from .agent.prompts import system_prompt, triage_user_message
from .agent.runner import run_agent
from .agent.tools import ToolBox
from .collector import Collector, _parse
from .config import load_settings
from .llm.base import make_llm
from .runtime import Runtime, _compact, demo_enabled, normalize_report

OK_LABELS = ["expected", "baseline_increase", "measurement", "false_positive", "correction"]


class _ReadOnlyRepo:
    """Reads go to the real repository; AI proposals are kept in memory only."""

    def __init__(self, repo):
        self._r = repo
        self.proposals: list[dict] = []

    def __getattr__(self, n):
        return getattr(self._r, n)

    async def add_knowledge(self, kind, title, body="", **kw):
        d = {"id": f"eval-{len(self.proposals) + 1}", "kind": kind, "title": title, "body": body, **kw}
        self.proposals.append(d)
        return d


def _when(v) -> datetime:
    """ISO-8601, a YAML datetime, `now` or `now-<n>[hd]`."""
    from datetime import UTC, timedelta
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    v = str(v)
    if v.startswith("now"):
        now = datetime.now(UTC)
        if v == "now":
            return now
        n, u = int(v[4:-1]), v[-1]
        return now - (timedelta(hours=n) if u == "h" else timedelta(days=n))
    return _parse(v)


def _text(f: dict) -> str:
    return " ".join([f.get("title", ""), f.get("detail", ""), " ".join(f.get("agents") or []),
                     " ".join(f.get("evidence") or [])]).lower()


def matches(f: dict, spec: dict) -> bool:
    rules = {str(r) for r in spec.get("rules") or []}
    kws = [k.lower() for k in spec.get("keywords") or []]
    r_ok = not rules or bool(rules & {str(x) for x in f.get("rule_ids") or []}) or any(r in _text(f) for r in rules)
    k_ok = not kws or all(k in _text(f) for k in kws)
    return (bool(rules) or bool(kws)) and r_ok and k_ok


def score(case: dict, findings: list[dict]) -> dict:
    hits, misses, bad = [], [], []
    for e in case.get("expect") or []:
        m = [f for f in findings if matches(f, e)]
        good = [f for f in m if not e.get("labels") or f.get("label") in e["labels"]]
        (hits if good else misses).append({"id": e.get("id"), "found_as": [f"{f.get('label')}: {f.get('title')}" for f in m]})
    for fb in case.get("forbid") or []:
        ok = fb.get("labels_ok") or OK_LABELS
        for f in findings:
            if matches(f, fb) and f.get("label") not in ok:
                bad.append({"id": fb.get("id"), "finding": f"{f.get('label')}: {f.get('title')}"})
    n = len(case.get("expect") or [])
    return {"recall": round(len(hits) / n, 2) if n else None, "hits": hits, "misses": misses,
            "noise_violations": bad, "findings": len(findings)}


async def run_case(rt: Runtime, case: dict, llm, llm_cfg) -> dict:
    er = rt.get(case["env"]) if case.get("env") else next(iter(rt.envs.values()))
    env, lang = er.env, rt.lang(er.env)
    frm, to = _when(case["from"]), _when(case["to"])
    t0 = time.time()
    collected = await Collector(env, er.ix, er.api, lang,
                                inventory=env.inventory_names(rt.settings.base_dir)).collect(frm, to)
    knowledge = await er.repo.list_knowledge(status=["active", "rejected"],
                                             kinds=["context", "baseline", "decision", "open_item", "lesson", "rule_draft"])
    sysmsg = system_prompt(env, env.context_text(rt.settings.base_dir), knowledge, rt.settings.app.timezone, lang)
    usr = triage_user_message(_compact(collected), [], [], [])
    usr += (f"\n\nNOTE: this is a replay of a past window ({collected['window']['from']} → {collected['window']['to']}). "
            "Always pass explicit `from`/`to` inside this window to the tools; 'now' is not the review time.")
    repo = _ReadOnlyRepo(er.repo)
    tb = ToolBox(env, er.ix, er.api, repo, mode="triage", run_id="eval", sources=er.sources)
    res = await run_agent(llm, sysmsg, [{"role": "user", "content": usr}], tb, llm_cfg.max_tool_steps,
                          stop_on="submit_report")
    rep = normalize_report(tb.submitted, res.text, lang) if tb.submitted else {"findings": [], "summary_md": res.text}
    sc = score(case, rep["findings"])
    return {"name": case.get("name") or f"{frm:%Y-%m-%d}", "env": env.id, "model": llm_cfg.model,
            "seconds": round(time.time() - t0), "steps": res.steps, "input_tokens": res.input_tokens,
            "output_tokens": res.output_tokens, "submitted": tb.submitted is not None, **sc,
            "summary": (rep.get("summary_md") or "")[:600],
            "all_findings": [f"[{f.get('label')}/{f.get('severity')}] {f.get('title')}" for f in rep["findings"]],
            "proposals": [p["title"] for p in repo.proposals]}


async def _main(a) -> int:
    cfg_path = os.environ.get("WDT_CONFIG") or ("config/demo.yaml" if demo_enabled() else "config/environments.yaml")
    settings = load_settings(cfg_path)
    rt = Runtime(settings, demo=demo_enabled())
    text = sys.stdin.read() if a.cases == "-" else open(a.cases, encoding="utf-8").read()
    cases = yaml.safe_load(text) or []
    out = []
    try:
        for case in cases:
            er = rt.get(case["env"]) if case.get("env") else next(iter(rt.envs.values()))
            llm_cfg = rt.llm_cfg(er.env).model_copy(update={k: v for k, v in (
                ("model", a.model), ("base_url", a.base_url), ("provider", a.provider)) if v})
            if a.max_steps:
                llm_cfg = llm_cfg.model_copy(update={"max_tool_steps": a.max_steps})
            llm = make_llm(llm_cfg)
            from .privacy import MaskingLLM, masker_for
            mk = masker_for(er.env)
            if mk:
                llm = MaskingLLM(llm, mk)
            for i in range(a.repeat):
                try:
                    r = await run_case(rt, case, llm, llm_cfg)
                except Exception as e:  # noqa: BLE001
                    r = {"name": case.get("name"), "error": f"{type(e).__name__}: {e}"}
                r["try"] = i + 1
                out.append(r)
                _print(r)
    finally:
        await rt.close()
    ok = [r for r in out if "error" not in r]
    if ok:
        rec = [r["recall"] for r in ok if r["recall"] is not None]
        print(f"\n== {len(ok)} run(s) · mean recall {sum(rec) / len(rec):.2f} · noise violations "
              f"{sum(len(r['noise_violations']) for r in ok)} · tokens in {sum(r['input_tokens'] for r in ok):,} "
              f"out {sum(r['output_tokens'] for r in ok):,}" if rec else "")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"at": datetime.now().isoformat(), "results": out}, f, ensure_ascii=False, indent=1)
    return 0 if all("error" not in r for r in out) else 1


def _print(r: dict):
    if "error" in r:
        print(f"✗ {r.get('name')}: {r['error']}")
        return
    print(f"\n### {r['name']} [{r['env']} · {r['model']} · try {r['try']}] recall {r['recall']} · "
          f"{r['findings']} findings · noise violations {len(r['noise_violations'])} · {r['seconds']} s · "
          f"{r['steps']} steps · tokens {r['input_tokens']:,}/{r['output_tokens']:,}")
    for h in r["hits"]:
        print(f"  ✓ {h['id']}: {'; '.join(h['found_as'])[:160]}")
    for m in r["misses"]:
        print(f"  ✗ {m['id']}" + (f" (found with another label: {'; '.join(m['found_as'])[:140]})" if m["found_as"] else ""))
    for b in r["noise_violations"]:
        print(f"  ! noise {b['id']}: {b['finding'][:160]}")


def main():
    p = argparse.ArgumentParser(prog="python -m app.eval", description="Replay past windows and score the findings")
    p.add_argument("cases", help="YAML file with cases, or - for stdin")
    p.add_argument("--model")
    p.add_argument("--base-url")
    p.add_argument("--provider")
    p.add_argument("--max-steps", type=int)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--out", help="write all results as JSON")
    sys.exit(asyncio.run(_main(p.parse_args())))


if __name__ == "__main__":
    main()
