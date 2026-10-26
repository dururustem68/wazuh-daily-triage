# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Persistence in the environment's own Wazuh Indexer, under `<prefix>-*` indices.

  <prefix>-runs       daily triage runs (report, findings, questions, collected summary)
  <prefix>-knowledge  baseline / decision / context / user request / answer / rule draft / lesson
  <prefix>-chat       chat messages

`dynamic: false` — only declared fields are indexed, everything else stays in _source,
so fields copied from alert data can never bloat the mapping.
"""
from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime
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
    "chat": {"dynamic": False, "properties": {
        "env": {"type": "keyword"}, "session": {"type": "keyword"}, "role": {"type": "keyword"},
        "ts": {"type": "date"}, "content": {"type": "text"},
    }},
}


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_id(prefix: str = "") -> str:
    return prefix + datetime.now(UTC).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]


class Store(Protocol):
    async def ensure(self) -> None: ...
    async def put(self, kind: str, doc_id: str, doc: dict) -> None: ...
    async def get(self, kind: str, doc_id: str) -> dict | None: ...
    async def delete(self, kind: str, doc_id: str) -> None: ...
    async def query(self, kind: str, filters: dict, sort: str, size: int, desc: bool = True,
                    exclude: list[str] | None = None) -> list[dict]: ...


class IndexStore:
    def __init__(self, ix: Indexer, prefix: str):
        self.ix = ix
        self.prefix = prefix
        self._ready = False

    def _idx(self, kind: str) -> str:
        return f"{self.prefix}-{kind}"

    async def ensure(self):
        if self._ready:
            return
        for kind, mapping in MAPPINGS.items():
            if not await self.ix.index_exists(self._idx(kind)):
                await self.ix.create_index(self._idx(kind), {"settings": _SETTINGS, "mappings": mapping})
        self._ready = True

    async def put(self, kind, doc_id, doc):
        await self.ensure()
        await self.ix.put_doc(self._idx(kind), doc_id, doc)

    async def get(self, kind, doc_id):
        await self.ensure()
        return await self.ix.get_doc(self._idx(kind), doc_id)

    async def delete(self, kind, doc_id):
        await self.ensure()
        await self.ix.delete_doc(self._idx(kind), doc_id)

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

    async def ensure(self):
        pass

    async def put(self, kind, doc_id, doc):
        self.data[kind][doc_id] = deepcopy(doc)

    async def get(self, kind, doc_id):
        d = self.data[kind].get(doc_id)
        return deepcopy(d) if d else None

    async def delete(self, kind, doc_id):
        self.data[kind].pop(doc_id, None)

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

    # sohbet
    async def chat_add(self, session: str, role: str, content: str, trace: list | None = None):
        doc = {"id": new_id("c"), "env": self.env, "session": session, "role": role,
               "content": content, "ts": now_iso(), "trace": trace or []}
        await self.s.put("chat", doc["id"], doc)
        return doc

    async def chat_history(self, session: str, size: int = 40) -> list[dict]:
        rows = await self.s.query("chat", {"env": self.env, "session": session}, "ts", size)
        return list(reversed(rows))

    async def chat_sessions(self, size: int = 200) -> list[dict]:
        rows = await self.s.query("chat", {"env": self.env, "role": "user"}, "ts", size)
        seen: dict[str, dict] = {}
        for r in rows:
            seen.setdefault(r["session"], {"session": r["session"], "ts": r["ts"], "title": r["content"][:80]})
        return list(seen.values())
