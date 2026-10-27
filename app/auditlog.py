# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Operational audit trail — append-only JSON Lines, hash-chained.

This is deliberately **not** the monthly ISMS report in :mod:`app.audit` (which is built from the index
and the stored runs). Here every state-changing operation is recorded with the actor, role, environment,
action, target, result and time, in a file that sits outside the application log stream:

* one JSON object per line, never rewritten in place (append only),
* ``prev`` + ``hash`` chain: changing or deleting a line breaks the chain, so tampering is detectable
  (verify with :func:`verify`),
* no secrets, tokens, passwords or raw log contents are written — only identifiers,
* size-based rotation (``.1`` … ``.3``) keeps the current file bounded; each generation is a complete
  hash chain of its own, so ship and verify every file (see ``docs/permissions.md``).

Set ``AUDIT_LOG_FILE`` to move the file (e.g. a read-only mount or a log shipper path). An unwritable
path never breaks a request: the failure is logged and the application continues.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("wdt.audit")
MAX_BYTES = 20 * 1024 * 1024
KEEP = 3
_lock = threading.Lock()
_path: Path | None = None
_last_hash: str | None = None
_warned = False


def configure(path: str | os.PathLike | None = None) -> Path:
    """Point the audit log at a file (called once at startup)."""
    global _path, _last_hash
    env = str(path or os.environ.get("AUDIT_LOG_FILE") or "logs/audit.jsonl")
    _path = Path(env)
    _last_hash = _tail_hash(_path)
    return _path


def path() -> Path | None:
    return _path


def enabled() -> bool:
    return os.environ.get("AUDIT_LOG", "true").strip().lower() not in ("0", "false", "no", "off")


def _tail_hash(p: Path) -> str | None:
    try:
        with p.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 8192))
            lines = f.read().decode("utf-8", "replace").strip().splitlines()
        return json.loads(lines[-1]).get("hash") if lines else None
    except (OSError, ValueError):
        return None


def _rotate(p: Path) -> bool:
    """Move the current file to `.1` (shifting `.1`→`.2` …) when it exceeds MAX_BYTES.

    A rotation starts a new hash chain: each generation is verified on its own. Returns True when the
    file was rotated, so the caller can reset the chain head instead of linking across files.
    """
    try:
        if not p.exists() or p.stat().st_size < MAX_BYTES:
            return False
        for i in range(KEEP - 1, 0, -1):
            src = p.with_suffix(p.suffix + f".{i}")
            dst = p.with_suffix(p.suffix + f".{i + 1}")
            if src.exists():
                dst.unlink(missing_ok=True)
                src.rename(dst)
        p.rename(p.with_suffix(p.suffix + ".1"))
        return True
    except OSError:
        return False


def record(action: str, *, actor: str = "", role: str = "", env: str = "", target: str = "",
           result: str = "", request_id: str = "", method: str = "", path_: str = "",
           detail: dict | None = None) -> dict | None:
    """Append one audit line. Never raises."""
    global _last_hash, _warned
    if not enabled():
        return None
    p = _path
    if p is None:
        p = configure()
    rec = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), "action": action, "actor": actor or "unknown",
           "role": role or "unknown", "env": env, "target": target, "result": result,
           "request_id": request_id, "method": method, "path": path_}
    if detail:
        rec["detail"] = {k: v for k, v in detail.items() if v not in (None, "", [], {})}
    try:
        with _lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            if _rotate(p):
                _last_hash = None          # a new generation starts a new chain
            if _last_hash is None:
                _last_hash = _tail_hash(p)
            body = json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            h = hashlib.sha256(((_last_hash or "") + body).encode()).hexdigest()
            rec["prev"], rec["hash"] = _last_hash, h
            with p.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            _last_hash = h
        return rec
    except OSError as e:
        if not _warned:
            _warned = True
            log.warning("audit log is not writable (%s): %s", p, e)
        return None


def verify(p: str | os.PathLike | None = None) -> dict:
    """Check the hash chain of a log file; returns counts plus the first broken line."""
    f = Path(p or _path or os.environ.get("AUDIT_LOG_FILE") or "logs/audit.jsonl")
    prev, n, broken = None, 0, None
    try:
        lines = f.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return {"ok": False, "error": str(e), "lines": 0}
    for i, line in enumerate(lines, 1):
        try:
            rec = json.loads(line)
        except ValueError:
            broken = broken or {"line": i, "reason": "not JSON"}
            continue
        h = rec.pop("hash", None)
        got_prev = rec.pop("prev", None)
        body = json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        want = hashlib.sha256(((got_prev or "") + body).encode()).hexdigest()
        if got_prev != prev or h != want:
            broken = broken or {"line": i, "reason": "hash chain broken"}
        prev, n = h, n + 1
    return {"ok": broken is None, "lines": n, "broken": broken, "file": str(f)}
