# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Rule drafts: analysis, deployment, live verification and promotion."""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from . import rules as rulemod
from .collector import _parse, iso
from .config import Environment
from .store import now_iso
from .wazuh.api import WazuhAPI, WazuhAPIError

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt")


class RuleDeployMixin:
    def deploy_ready(self, env: Environment) -> bool:
        """Deployment is on, the environment has an API, and a separate deploy user is configured."""
        cfg = env.rule_deploy
        return bool(cfg.enabled and env.api and (self.demo or cfg.username))

    def _deploy_api(self, rt: EnvRuntime):
        """Write-enabled API client (separate user) — or the demo fake. None when deployment is off."""
        cfg = rt.env.rule_deploy
        if not self.deploy_ready(rt.env):
            return None
        if self.demo:
            return rt.api
        ep = rt.env.api.model_copy(update={"username": cfg.username, "password": cfg.password,
                                           "timeout": max(rt.env.api.timeout, 60)})
        return WazuhAPI(ep)

    async def _rule_entry(self, rt: EnvRuntime, kid: str) -> dict:
        d = await rt.store.get("knowledge", kid)
        if not d or d.get("env") != rt.env.id or d.get("kind") != "rule_draft":
            raise KeyError(kid)
        return d

    async def rule_view(self, env_id: str, kid: str) -> dict:
        rt = self.envs[env_id]
        d = await self._rule_entry(rt, kid)
        xml = rulemod.extract_xml(d)
        an = await rulemod.analyse(xml, rt.env.rule_deploy, rt.api, rt.env.high_level)
        return {"analysis": an, "deploy_enabled": self.deploy_ready(rt.env),
                "file": rt.env.rule_deploy.file, "deploy": d.get("deploy"),
                "commands": rulemod.commands(kid, xml, rt.env.rule_deploy, d.get("title", ""), an["ids"],
                                             d.get("tests"))}

    async def rule_deploy(self, env_id: str, kid: str, actor: str, confirm: str = "", remove: bool = False) -> dict:
        rt = self.envs[env_id]
        api = self._deploy_api(rt)
        if api is None:
            raise PermissionError("rule deployment is off for this environment "
                                  "(rule_deploy.enabled with a separate username/password)")
        if rt.deploy_lock.locked():
            raise RuntimeError("another deployment is in progress")
        async with rt.deploy_lock:
            d = await self._rule_entry(rt, kid)
            xml = rulemod.extract_xml(d)
            an = await rulemod.analyse(xml, rt.env.rule_deploy, rt.api, rt.env.high_level)
            ids = an["ids"]
            if not remove:
                if not an["ok"]:
                    raise ValueError("; ".join(an["errors"]))
                if an["risky"] and confirm.replace(" ", "") != ",".join(ids):
                    raise PermissionError("this draft silences or lowers alerts; type the rule id(s) to confirm: "
                                          + ",".join(ids))
                # fail closed: policy may require replayable samples before anything is written to the manager
                if rt.env.rule_deploy.require_tests and an.get("replayable", True) and not d.get("tests"):
                    raise ValueError("deployment policy requires logtest samples (rule_deploy.require_tests) — "
                                     "add two-way test events to the draft or provide the commands manually; "
                                     "see docs/rule-deployment.md")
            rec = {"state": "running", "action": "remove" if remove else "deploy", "at": now_iso(), "by": actor,
                   "file": rt.env.rule_deploy.file, "ids": ids, "risky": an["risky"]}
            try:
                rec["steps"] = await rulemod.apply(api, rt.env.rule_deploy, kid, xml, ids, d.get("title", ""),
                                                   d.get("tests"), remove=remove,
                                                   replayable=an.get("replayable", True))
                rec["state"] = "removed" if remove else "deployed"
                rec["rollback_state"] = "not_needed"
            except rulemod.DeployError as e:
                rec.update(state="failed", error=str(e)[:500], steps=getattr(e, "steps", None),
                           rollback_state=getattr(e, "rollback", "not_needed"))
                if rec["rollback_state"] == "failed":
                    log.critical("%s: rule %s could not be rolled back after a failed deployment — "
                                 "check the manager now", env_id, kid)
            except WazuhAPIError as e:  # e.g. wrong deploy credentials — nothing was written
                rec.update(state="failed", error=f"{e}"[:500], rollback_state="not_needed",
                           steps=[{"step": "connect as " + (rt.env.rule_deploy.username or "?"), "ok": False,
                                   "detail": "nothing was changed"}])
            finally:
                if api is not rt.api:
                    await api.close()
            async with self.run_lock(f"k:{kid}"):
                d = await self._rule_entry(rt, kid)
                hist = (d.get("deploy_history") or [])[-9:]
                if d.get("deploy"):
                    hist.append({k: v for k, v in d["deploy"].items() if k != "steps"})
                patch = {"deploy": rec, "deploy_history": hist, "updated_at": now_iso()}
                if rec["state"] == "deployed":
                    patch["status"] = "active"
                elif rec["state"] == "removed":
                    patch["status"] = "closed"
                d.update(patch)
                await rt.store.put("knowledge", kid, d)
            log.info("rule %s %s by %s: %s", kid, rec["action"], actor, rec["state"])
            await self._notify_rule(rt, d, rec, transport=self.notify_transport)
            return rec

    # ------------------------------------------------------------ live verification / promotion
    async def verify_rules(self, env_id: str, kid: str | None = None) -> list[dict]:
        """Has a deployed / approved / promoted rule draft fired on real events since then?"""
        rt = self.get(env_id)
        if kid:
            rows = [await self._rule_entry(rt, kid)]
        else:
            rows = await rt.repo.list_knowledge(kinds=["rule_draft"], status=["active", "closed"], size=500)
        now = datetime.now(UTC)
        out = []
        for d in rows:
            dep, prom = d.get("deploy") or {}, d.get("promoted") or {}
            if dep.get("state") == "deployed":
                since = dep.get("at")
            elif prom.get("at"):
                since = prom["at"]
            elif d.get("status") == "active":
                since = d.get("approved_at") or d.get("updated_at")
            else:
                continue
            if not since or (not kid and (now - _parse(since)).days > 60):
                continue  # verified long ago or too old to matter
            ids = [r["id"] for r in rulemod.parse(rulemod.extract_xml(d))[0] if r.get("id")] or d.get("rule_ids") or []
            if not ids:
                continue
            r = await rt.ix.search(rt.env.alerts_index, {
                "size": 0, "query": {"bool": {"filter": [{"terms": {"rule.id": ids}},
                                                         {"range": {"timestamp": {"gte": since}}}]}},
                "aggs": {"r": {"terms": {"field": "rule.id", "size": len(ids)},
                               "aggs": {"f": {"min": {"field": "timestamp"}}, "l": {"max": {"field": "timestamp"}},
                                        "a": {"terms": {"field": "agent.name", "size": 3}}}}}})
            seen = {b["key"]: {"n": b["doc_count"], "first": b["f"].get("value_as_string"),
                               "last": b["l"].get("value_as_string"), "agents": [a["key"] for a in b["a"]["buckets"]]}
                    for b in r["aggregations"]["r"]["buckets"]}
            v = {"checked_at": iso(now), "since": since, "ids": ids, "seen": seen,
                 "state": "seen" if seen else "waiting",
                 "last": max((x["last"] or "" for x in seen.values()), default=None),
                 "waiting_days": None if seen else (now - _parse(since)).days}
            if (d.get("verify") or {}).get("state") != v["state"] and seen:
                log.info("%s: rule draft %s confirmed on live events (%s)", env_id, d["id"], ", ".join(seen))
            await rt.repo.update_knowledge(d["id"], verify=v)
            out.append({"id": d["id"], **v})
        return out

    async def promote_view(self, env_id: str, kid: str, actor: str = "") -> dict:
        from . import promote
        rt = self.get(env_id)
        d = await self._rule_entry(rt, kid)
        xml = rulemod.extract_xml(d)
        an = await rulemod.analyse(xml, rt.env.rule_deploy.model_copy(update={"id_min": 0, "id_max": 10**7}),
                                   rt.api, rt.env.high_level)
        # existing ids are fine here when they are the ones this draft deployed (file == rule_deploy.file)
        errors = [e for e in an["errors"] if "already exists in " + rt.env.rule_deploy.file not in e]
        pkg = promote.package(rt.env, d, xml, an, self.lang(rt.env), actor)
        pkg["errors"] = errors
        return pkg

    async def mark_promoted(self, env_id: str, kid: str, actor: str) -> dict:
        rt = self.get(env_id)
        d = await self._rule_entry(rt, kid)
        if (d.get("deploy") or {}).get("state") == "deployed":
            raise ValueError("remove the draft from " + rt.env.rule_deploy.file + " first")
        ids = [r["id"] for r in rulemod.parse(rulemod.extract_xml(d))[0] if r.get("id")]
        rec = {"at": iso(datetime.now(UTC)), "by": actor, "file": rt.env.promote.rules_file, "ids": ids}
        return await rt.repo.update_knowledge(kid, promoted=rec, status="closed")
