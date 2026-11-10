# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Sample state for the demo, so every page has something to show right after `docker compose up`.

The synthetic alerts in :mod:`app.demo` cover 18 days. On top of that, at startup the demo gets:

* a few extra alerts the watch reacts to (a successful SSH login after failed attempts, an Active
  Response block),
* the watch switched on, with the events of the last 24 hours already recorded and "announced",
* one finished AI round (the mock model) that judged those events and left tuning suggestions,
* a masking profile with one custom detector, so the settings page shows how it looks.

Only in demo mode, and only when the store is empty (the demo store lives in memory). ``WDT_DEMO_SEED=false``
starts the demo empty.
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

from .demo import AGENTS, RULES, _ev
from .store import now_iso
from .watch import Scanner

log = logging.getLogger("wdt")


def enabled() -> bool:
    return os.environ.get("WDT_DEMO_SEED", "true").strip().lower() not in ("0", "false", "no", "off")


def extra_alerts(now: datetime) -> list[dict]:
    """Alerts that make the watch's local rules fire (the base data is about noise and slow attacks)."""
    db, web = AGENTS[1], AGENTS[0]
    ip = "198.51.100.66"
    out = [_ev(now - timedelta(minutes=55 - i), "5710", db, srcip=ip, srcuser=u,
               full_log=f"sshd[3301]: Invalid user {u} from {ip} port 5{i:04d}")
           for i, u in enumerate(["admin", "oracle", "test", "ubuntu", "deploy", "git", "backup", "postgres",
                                  "jenkins", "support", "guest", "ftp"])]
    out.append(_ev(now - timedelta(minutes=40), "5715", db, srcip=ip, dstuser="deploy",
                   full_log=f"sshd[3302]: Accepted password for deploy from {ip} port 50999 ssh2"))
    ar = _ev(now - timedelta(minutes=30), "5715", web, srcip="203.0.113.10",
             full_log="active-response/bin/firewall-drop: add -  203.0.113.10")
    ar["rule"] = {"id": "651", "level": 3, "description": "Host Blocked by firewall-drop Active Response",
                  "groups": ["ossec", "active_response"]}
    out.append(ar)
    return out


async def seed_demo(rt) -> dict:
    """Fill the demo with sample watch events, one AI round and a masking profile. Returns a summary."""
    out: dict = {}
    for env_id, er in rt.envs.items():
        if await er.repo.list_runs(1):
            continue
        now = datetime.now(UTC)
        er.ix.alerts.extend(extra_alerts(now))
        await rt.save_settings(env_id, {
            "watch": {"enabled": True, "rules": ["100213"]},
            "mask": {"custom": [{"name": "x_order_no", "pattern": r"ORD-\d{6}",
                                 "description": "demo: order numbers in web logs"}],
                     "allow": [r"noreply@example\.com"], "disabled": []},
        }, "demo")
        st = await rt.env_settings(er, fresh=True)
        frm = now - timedelta(hours=24)
        events, disconnected = await Scanner(er.env, er.ix, er.api, st.watch, rt.lang(er.env)).scan(frm, now, set())
        stamp = now_iso()
        for e in events:
            e["status"], e["notified_at"] = "notified", stamp
            await er.repo.save_event(e)
        await er.repo.put_state("watch", {
            "cursor": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "disconnected": sorted(disconnected or []),
            "last_scan": {"at": stamp, "from": frm.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "found": len(events),
                          "new": len(events), "sent": len(events), "quiet": False, "errors": [], "gap": None}})
        run = await rt.run_triage(er, f"{env_id}-demo-seed", trigger="schedule")
        out[env_id] = {"events": len(events), "run": run.get("status"),
                       "judged": (run.get("watch") or {}).get("judged", 0)}
        log.info("demo: sample data for %s — %d watch event(s), AI round %s", env_id, len(events), run.get("status"))
    return out


assert "651" not in RULES        # the Active Response sample uses its own rule id
