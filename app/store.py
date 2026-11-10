# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Persistence in the environment's own Wazuh Indexer, under `<prefix>-*` indices.

  <prefix>-runs       daily triage runs (report, findings, questions, collected summary)
  <prefix>-knowledge  baseline / decision / context / user request / answer / rule draft / lesson
  <prefix>-events     watch events (rule-based alerts between AI rounds) and the AI's verdict on each
  <prefix>-settings   what an administrator changes in the UI (watch, AI round, masking profile, backup)

These indices are the only copy of the knowledge base. A retention policy that matches them (an ISM policy
on ``*`` or on the prefix) deletes it without any error, so :meth:`IndexStore.ensure` never recreates a
missing index quietly: it records the loss, and the application raises a critical flag until an
administrator restores a backup or acknowledges the loss (see ``docs/backup.md``).

`dynamic: false` — only declared fields are indexed, everything else stays in _source,
so fields copied from alert data can never bloat the mapping.
"""
from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .wazuh.indexer import Indexer

KNOWLEDGE_KINDS = {
    "context": "Ortam bilgisi",
    "baseline": "Known noise (baseline)",
    "decision": "Karar",
    "open_item": "Open item",
    "request": "Request / note for next run",
    "answer": "Soruya cevap",
    "rule_draft": "Rule draft",
    "lesson": "Lesson learned",
}
KNOWLEDGE_STATUS = ("active", "proposed", "closed", "rejected")

_SETTINGS = {"index": {"number_of_shards": 1, "number_of_replicas": 0}}
MAPPINGS = {
    "runs": {"dynamic": False, "properties": {
        "env": {"type": "keyword"}, "run_id": {"type": "keyword"}, "status": {"type": "keyword"},
        "trigger": {"type": "keyword"}, "health": {"type": "keyword"},
        "started_at": {"type": "date"}, "finished_at": {"type": "date"},
        "window": {"properties": {"from": {"type": "date"}, "to": {"type": "date"}, "hours": {"type": "integer"}}},
        "summary_md": {"type": "text"},
        "findings": {"type": "object", "enabled": False},
        "questions": {"type": "object", "enabled": False},
        "collected": {"type": "object", "enabled": False},
        "metrics": {"properties": {"total": {"type": "long"}, "high": {"type": "long"}}},
    }},
    "knowledge": {"dynamic": False, "properties": {
        "env": {"type": "keyword"}, "kind": {"type": "keyword"}, "status": {"type": "keyword"},
        "title": {"type": "text", "fields": {"k": {"type": "keyword", "ignore_above": 256}}},
        "body": {"type": "text"}, "rule_ids": {"type": "keyword"},
        "created_at": {"type": "date"}, "updated_at": {"type": "date"},
        "created_by": {"type": "keyword"}, "source_run": {"type": "keyword"},
    }},
    "events": {"dynamic": False, "properties": {
        "env": {"type": "keyword"}, "id": {"type": "keyword"}, "key": {"type": "keyword"},
        "trigger": {"type": "keyword"}, "severity": {"type": "keyword"}, "status": {"type": "keyword"},
        "verdict": {"type": "keyword"}, "created_at": {"type": "date"}, "last_seen": {"type": "date"},
        "judged_at": {"type": "date"}, "count": {"type": "long"},
    }},
    "settings": {"dynamic": False, "properties": {
        "env": {"type": "keyword"}, "kind": {"type": "keyword"}, "updated_at": {"type": "date"},
    }},
}
LEGACY_KINDS = ("runs", "knowledge")     # existed before 0.10: when one is missing next to the other, it was deleted
MANIFEST_ID = "_manifest"


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id(prefix: str = "") -> str:
    return prefix + datetime.now(UTC).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]


class Store(Protocol):
    async def ensure(self) -> None: ...
    async def put(self, kind: str, doc_id: str, doc: dict) -> None: ...
    async def get(self, kind: str, doc_id: str) -> dict | None: ...
    async def delete(self, kind: str, doc_id: str) -> None: ...
    async def delete_before(self, kind: str, field: str, before: str, filters: dict | None = None) -> int: ...
    async def query(self, kind: str, filters: dict, sort: str, size: int, desc: bool = True,
                    exclude: list[str] | None = None) -> list[dict]: ...


class IndexStore:
    def __init__(self, ix: Indexer, prefix: str):
        self.ix = ix
        self.prefix = prefix
        self._ready = False
        self.health: dict = {}

    def _idx(self, kind: str) -> str:
        return f"{self.prefix}-{kind}"

    async def ensure(self):
        if self._ready:
            return
        await self.verify()

    async def _manifest(self, exists: dict[str, bool]) -> dict:
        """The record of which indices this installation created (kept twice: settings and knowledge)."""
        best: dict = {}
        for kind in ("settings", "knowledge"):
            if not exists.get(kind):
                continue
            try:
                d = await self.ix.get_doc(self._idx(kind), MANIFEST_ID)
            except Exception:  # noqa: BLE001 - an unreadable copy is the same as no copy
                d = None
            if d and len(d.get("created") or {}) >= len(best.get("created") or {}):
                best = d
        return best

    async def _save_manifest(self, m: dict) -> None:
        doc = {"id": MANIFEST_ID, "env": "__meta__", "kind": "manifest", "status": "closed", "title": self.prefix,
               "created_at": m.get("created_at") or now_iso(), "updated_at": now_iso(), **m}
        for kind in ("settings", "knowledge"):
            await self.ix.put_doc(self._idx(kind), MANIFEST_ID, doc)

    async def verify(self) -> dict:
        """Create what is missing — and say so. Returns the storage health (see :attr:`health`).

        * nothing exists → a new installation (or everything was deleted): indices are created and
          ``initialised`` is set, so the operator is told once;
        * an index is missing that this installation had created → **lost**: it is created again (the
          application needs it) but the loss stays recorded until it is acknowledged.
        """
        exists = {k: await self.ix.index_exists(self._idx(k)) for k in MAPPINGS}
        fresh = not any(exists.values())
        man = {} if fresh else await self._manifest(exists)
        created: dict[str, str] = dict(man.get("created") or {})
        lost: list[dict] = list(man.get("lost") or [])
        now = now_iso()
        for kind, mapping in MAPPINGS.items():
            if exists[kind]:
                created.setdefault(kind, man.get("created_at") or now)
                continue
            was_there = kind in created or (kind in LEGACY_KINDS and not fresh)
            await self.ix.create_index(self._idx(kind), {"settings": _SETTINGS, "mappings": mapping})
            created[kind] = now
            if was_there and not any(x["kind"] == kind and not x.get("acknowledged") for x in lost):
                lost.append({"kind": kind, "index": self._idx(kind), "detected_at": now, "acknowledged": None})
        new = {"created": created, "lost": lost[-50:], "created_at": man.get("created_at") or now,
               "initialised_at": now if fresh else man.get("initialised_at")}
        if new != {k: man.get(k) for k in new}:
            await self._save_manifest(new)
        self._ready = True
        self.health = {"fresh": fresh, "initialised_at": new["initialised_at"], "since": new["created_at"],
                       "checked_at": now,
                       "lost": [x for x in lost if not x.get("acknowledged")]}
        return self.health

    async def acknowledge_loss(self, by: str) -> int:
        """An administrator has restored a backup or accepts starting empty."""
        exists = {k: await self.ix.index_exists(self._idx(k)) for k in MAPPINGS}
        man = await self._manifest(exists)
        n = 0
        for x in man.get("lost") or []:
            if not x.get("acknowledged"):
                x["acknowledged"] = {"at": now_iso(), "by": by}
                n += 1
        if n:
            await self._save_manifest({k: man.get(k) for k in ("created", "lost", "created_at", "initialised_at")})
        self.health = {**getattr(self, "health", {}), "lost": []}
        return n

    async def put(self, kind, doc_id, doc):
        await self.ensure()
        await self.ix.put_doc(self._idx(kind), doc_id, doc)

    async def get(self, kind, doc_id):
        await self.ensure()
        return await self.ix.get_doc(self._idx(kind), doc_id)

    async def delete(self, kind, doc_id):
        await self.ensure()
        await self.ix.delete_doc(self._idx(kind), doc_id)

    async def delete_before(self, kind, field, before, filters=None):
        await self.ensure()
        must = [{"range": {field: {"lt": before}}}]
        must += [{"term": {k: v}} for k, v in (filters or {}).items() if v is not None]
        return await self.ix.delete_by_query(self._idx(kind), {"bool": {"filter": must}})

    async def query(self, kind, filters, sort, size, desc=True, exclude=None):
        await self.ensure()
        must = []
        for k, v in filters.items():
            if v is None:
                continue
            must.append({"terms" if isinstance(v, (list, tuple, set)) else "term": {k: list(v) if isinstance(v, (list, tuple, set)) else v}})
        r = await self.ix.search(self._idx(kind), {
            "size": size, "query": {"bool": {"filter": must}} if must else {"match_all": {}},
            "sort": [{sort: {"order": "desc" if desc else "asc", "unmapped_type": "date"}}],
            **({"_source": {"excludes": exclude}} if exclude else {}),
        })
        return [h["_source"] for h in r["hits"]["hits"]]


class MemoryStore:
    """For demo mode and tests."""

    def __init__(self):
        self.data: dict[str, dict[str, dict]] = {k: {} for k in MAPPINGS}
        self.prefix = "memory"
        self.health: dict = {"fresh": False, "lost": []}

    async def ensure(self):
        pass

    async def verify(self) -> dict:
        return self.health

    async def acknowledge_loss(self, by: str) -> int:
        n = len(self.health.get("lost") or [])
        self.health["lost"] = []
        return n

    async def put(self, kind, doc_id, doc):
        self.data[kind][doc_id] = deepcopy(doc)

    async def get(self, kind, doc_id):
        d = self.data[kind].get(doc_id)
        return deepcopy(d) if d else None

    async def delete(self, kind, doc_id):
        self.data[kind].pop(doc_id, None)

    async def delete_before(self, kind, field, before, filters=None):
        doomed = [doc_id for doc_id, d in self.data[kind].items()
                  if all(d.get(k) == v for k, v in (filters or {}).items() if v is not None)
                  and (_dig(d, field) or "") < before]
        for doc_id in doomed:
            self.data[kind].pop(doc_id, None)
        return len(doomed)

    async def query(self, kind, filters, sort, size, desc=True, exclude=None):
        def ok(d):
            for k, v in filters.items():
                if v is None:
                    continue
                dv = d.get(k)
                if isinstance(v, (list, tuple, set)):
                    if dv not in v:
                        return False
                elif dv != v:
                    return False
            return True
        rows = [deepcopy(d) for d in self.data[kind].values() if ok(d)]
        rows.sort(key=lambda d: _dig(d, sort) or "", reverse=desc)
        return rows[:size]


def _dig(d: dict, path: str) -> Any:
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


# ---------------------------------------------------------------------- servis
class Repo:
    """Domain operations on top of a Store."""

    def __init__(self, store: Store, env_id: str):
        self.s = store
        self.env = env_id

    # runs
    async def save_run(self, run: dict):
        await self.s.put("runs", run["run_id"], run)

    async def get_run(self, run_id: str) -> dict | None:
        r = await self.s.get("runs", run_id)
        return r if r and r.get("env") == self.env else None

    async def list_runs(self, size: int = 30, status: str | None = None, light: bool = False) -> list[dict]:
        ex = ["collected", "agent.trace"] if light else None
        return await self.s.query("runs", {"env": self.env, "status": status}, "started_at", size, exclude=ex)

    async def last_success(self) -> dict | None:
        r = await self.list_runs(1, status="done")
        return r[0] if r else None

    async def prune_runs(self, days: int) -> int:
        """Delete runs older than ``days``; knowledge stays forever (decisions are durable evidence)."""
        if days <= 0:
            return 0
        cutoff = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return await self.s.delete_before("runs", "started_at", cutoff, {"env": self.env})

    # knowledge base
    async def add_knowledge(self, kind: str, title: str, body: str = "", status: str = "active",
                            created_by: str = "user", rule_ids: list[str] | None = None,
                            source_run: str | None = None, extra: dict | None = None) -> dict:
        if kind not in KNOWLEDGE_KINDS:
            raise ValueError(f"unknown kind: {kind}")
        if status not in KNOWLEDGE_STATUS:
            raise ValueError(f"bilinmeyen durum: {status}")
        doc = {"id": new_id("k"), "env": self.env, "kind": kind, "status": status, "title": title.strip()[:300],
               "body": body.strip(), "rule_ids": [str(x) for x in (rule_ids or [])], "created_at": now_iso(),
               "updated_at": now_iso(), "created_by": created_by, "source_run": source_run}
        if extra:
            doc.update(extra)
        await self.s.put("knowledge", doc["id"], doc)
        return doc

    async def update_knowledge(self, kid: str, **patch) -> dict | None:
        d = await self.s.get("knowledge", kid)
        if not d or d.get("env") != self.env:
            return None
        if patch.get("status") is not None and patch["status"] not in KNOWLEDGE_STATUS:
            raise ValueError("invalid status")
        d.update({k: v for k, v in patch.items() if v is not None})
        d["updated_at"] = now_iso()
        await self.s.put("knowledge", kid, d)
        return d

    async def delete_knowledge(self, kid: str):
        d = await self.s.get("knowledge", kid)
        if d and d.get("env") == self.env:
            await self.s.delete("knowledge", kid)

    async def list_knowledge(self, kinds: list[str] | None = None, status: list[str] | str | None = None,
                             size: int = 300) -> list[dict]:
        return await self.s.query("knowledge", {"env": self.env, "kind": kinds, "status": status},
                                  "updated_at", size)

    # watch events
    async def save_event(self, ev: dict):
        await self.s.put("events", ev["id"], ev)

    async def get_event(self, eid: str) -> dict | None:
        d = await self.s.get("events", eid)
        return d if d and d.get("env") == self.env else None

    async def list_events(self, size: int = 100, status: list[str] | str | None = None) -> list[dict]:
        return await self.s.query("events", {"env": self.env, "status": status}, "created_at", size)

    async def prune_events(self, days: int) -> int:
        if days <= 0:
            return 0
        cutoff = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return await self.s.delete_before("events", "created_at", cutoff, {"env": self.env})

    # settings and small state documents (ids are namespaced by environment)
    async def get_state(self, name: str) -> dict | None:
        return await self.s.get("settings", f"{self.env}:{name}")

    async def put_state(self, name: str, doc: dict):
        await self.s.put("settings", f"{self.env}:{name}",
                         {**doc, "env": self.env, "kind": name, "updated_at": now_iso()})
