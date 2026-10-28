# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Seed import and knowledge-base import/export."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import yaml

from .store import KNOWLEDGE_KINDS, now_iso

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt")


class KnowledgeIOMixin:
    async def ensure_seed(self, rt: EnvRuntime) -> int:
        """Import seed_file entries once per environment (guarded by a marker document)."""
        if rt.env.id in self._seeded:
            return 0
        self._seeded.add(rt.env.id)
        path = rt.env.resolve(self.settings.base_dir, rt.env.seed_file)
        if not path or not path.exists():
            return 0
        marker = f"_seed_{rt.env.id}"
        if await rt.store.get("knowledge", marker):
            return 0
        items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        if not isinstance(items, list):
            log.warning("%s: seed file %s is not a list of {kind, title, body} entries — not imported", rt.env.id,
                        path.name)
            return 0
        bad = 0
        for it in items:
            if not isinstance(it, dict) or it.get("kind") not in KNOWLEDGE_KINDS or not str(it.get("title", "")).strip():
                bad += 1
                continue
            await rt.repo.add_knowledge(it["kind"], it["title"], it.get("body", ""), status=it.get("status", "active"),
                                        created_by="seed", rule_ids=it.get("rule_ids"))
        if bad:
            log.warning("%s: skipped %d invalid seed entries in %s (kind/title missing or unknown kind)",
                        rt.env.id, bad, path.name)
        # marker doc: env "__meta__" keeps it out of every listing; deleted seed entries never come back
        await rt.store.put("knowledge", marker, {"id": marker, "env": "__meta__", "kind": "seed_marker",
                                                 "status": "closed", "title": path.name, "created_at": now_iso(),
                                                 "updated_at": now_iso()})
        log.info("%s: imported %d seed entries into the knowledge base (%s)", rt.env.id, len(items), path.name)
        return len(items)

    # ------------------------------------------------------------ knowledge import / export
    async def kb_import(self, env_id: str, items: list, update: bool = False, dry_run: bool = False,
                        created_by: str = "import") -> dict:
        """Import entries in seed format. Duplicates (same `key`, else same kind + title) are skipped,
        or updated in place with `update` (status is kept)."""
        rt = self.get(env_id)
        if not isinstance(items, list):
            raise ValueError("expected a YAML/JSON list of entries")
        existing = await rt.repo.list_knowledge(size=5000)
        by_key = {}
        for d in existing:
            by_key[d.get("import_key") or f"{d['kind']}|{d['title'].strip().lower()}"] = d
            by_key.setdefault(f"{d['kind']}|{d['title'].strip().lower()}", d)
        res = {"added": 0, "updated": 0, "skipped": 0, "errors": []}
        for n, it in enumerate(items, 1):
            if isinstance(it, dict) and it.get("_error"):
                res["errors"].append(f"#{n}: {it['_error']}")
                continue
            if not isinstance(it, dict) or not it.get("kind") or not str(it.get("title", "")).strip():
                res["errors"].append(f"#{n}: kind and title are required")
                continue
            kind, title = str(it["kind"]), str(it["title"]).strip()
            if kind not in KNOWLEDGE_KINDS:
                res["errors"].append(f"#{n}: unknown kind {kind!r}")
                continue
            key = str(it.get("key") or f"{kind}|{title.lower()}")
            body = str(it.get("body") or "")
            rule_ids = [str(x) for x in (it.get("rule_ids") or [])]
            old = by_key.get(key) or by_key.get(f"{kind}|{title.lower()}")
            if old:
                if update and (old.get("body") != body.strip() or old.get("title") != title[:300]
                               or old.get("rule_ids") != rule_ids):
                    if not dry_run:
                        await rt.repo.update_knowledge(old["id"], title=title[:300], body=body.strip(),
                                                       rule_ids=rule_ids, import_key=key)
                    res["updated"] += 1
                else:
                    res["skipped"] += 1
                continue
            if not dry_run:
                try:
                    d = await rt.repo.add_knowledge(kind, title, body, status=str(it.get("status") or "active"),
                                                    created_by=created_by, rule_ids=rule_ids,
                                                    extra={"import_key": key, **({"xml": it["xml"]} if it.get("xml") else {})})
                except ValueError as e:
                    res["errors"].append(f"#{n}: {e}")
                    continue
                by_key[key] = d
            res["added"] += 1
        res["dry_run"] = dry_run
        return res

    async def kb_export(self, env_id: str, kinds: list[str] | None = None, status: list[str] | None = None) -> list[dict]:
        rows = await self.get(env_id).repo.list_knowledge(kinds=kinds, status=status, size=5000)
        out = []
        for d in sorted(rows, key=lambda x: (x["kind"], x.get("created_at", ""))):
            e = {"kind": d["kind"], "title": d["title"]}
            for k in ("body", "rule_ids", "xml"):
                if d.get(k):
                    e[k] = d[k]
            if d.get("status") != "active":
                e["status"] = d["status"]
            if d.get("import_key"):
                e["key"] = d["import_key"]
            out.append(e)
        return out
