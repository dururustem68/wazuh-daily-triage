# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The watch: rule-based alerts between AI rounds.

Every few minutes the alerts of the last interval are checked against **local rules** — no model is
involved, so an urgent situation is announced within minutes and costs nothing:

1. ``level``            any alert at or above ``critical_level``
2. ``rules``/``groups`` the environment's watched rule ids; watched groups at or above ``group_min_level``
3. ``active_response``  Wazuh took an automatic action
4. ``brute_force``      a successful login from a source that failed ``brute_failures`` times before it
5. ``spike``            the alert volume is ``spike_factor`` × the 24 h average
6. ``agents``           agents that stopped reporting

Events are then *sorted out* (muted keys, known noise from the knowledge base, the repeat window),
*announced* at once on the selected channels as "rule-based alert — not reviewed by AI" (held back
during quiet hours unless critical) and *kept* in ``<prefix>-events``. The next scheduled AI round gets
all of them in one call and returns a verdict per event plus tuning suggestions, which an administrator
can accept in the settings page — that is the only way the model influences the watch.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from .collector import TS, _b, _parse, iso, rng
from .config import DAYS
from .i18n import t
from .notify import NotifyCfg, plain_message
from .notify import send as notify_send
from .observability import metrics
from .settingsdoc import CHANNELS, TUNABLE, WatchSettings
from .store import new_id, now_iso

if TYPE_CHECKING:
    from .services import EnvRuntime

log = logging.getLogger("wdt.watch")

FIELDS = [TS, "agent.name", "rule.id", "rule.level", "rule.description", "rule.groups", "data.srcip",
          "data.srcuser", "data.dstuser", "location", "full_log"]
AUTH_FAIL = ["authentication_failed", "authentication_failures"]
AUTH_OK = ["authentication_success"]
MAX_HITS = 500
MAX_WINDOW_MINUTES = 120          # after downtime the watch does not replay more than this
PENDING = ("new", "notified", "held", "muted")
VERDICTS = ("real_incident", "investigate", "expected", "noise")


def _get(d: dict, path: str) -> Any:
    cur: Any = d
    for p in path.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _groups(src: dict) -> list[str]:
    g = _get(src, "rule.groups") or []
    return [g] if isinstance(g, str) else [str(x) for x in g]


def _level(src: dict) -> int:
    try:
        return int(_get(src, "rule.level") or 0)
    except (TypeError, ValueError):
        return 0


def classify(src: dict, cfg: WatchSettings, rules: set[str], groups: set[str]) -> tuple[str, str] | None:
    """``(trigger, severity)`` for one alert, most specific trigger first; ``None`` when nothing applies."""
    g = set(_groups(src))
    lvl = _level(src)
    if cfg.on("active_response") and "active_response" in g:
        return "active_response", "high"
    if cfg.on("level") and lvl >= cfg.critical_level:
        return "level", "critical" if lvl >= max(cfg.critical_level, 15) else "high"
    if cfg.on("rules") and str(_get(src, "rule.id")) in rules:
        return "rules", "high"
    if cfg.on("groups") and g & groups and lvl >= cfg.group_min_level:
        return "groups", "high"
    return None


def _event(env_id: str, key: str, trigger: str, severity: str, **kw) -> dict:
    now = now_iso()
    return {"id": new_id("w"), "env": env_id, "key": key, "trigger": trigger, "severity": severity,
            "status": "new", "verdict": None, "created_at": now, "last_seen": now, "count": 1, **kw}


class Scanner:
    """The local rules. Stateless except for what the caller passes in; never writes anything."""

    def __init__(self, env, ix, api, cfg: WatchSettings, lang: str = "en"):
        self.env, self.ix, self.api, self.cfg, self.lang = env, ix, api, cfg, lang
        self.rules = {str(x) for x in (cfg.rules if cfg.rules is not None else env.watch_rules)}
        self.groups = {str(x) for x in (cfg.groups if cfg.groups is not None else env.watch_groups)}
        self.errors: list[str] = []

    async def _safe(self, name: str, coro, default):
        try:
            return await coro
        except Exception as e:  # noqa: BLE001 - one broken trigger must not blind the others
            self.errors.append(f"{name}: {type(e).__name__}")
            log.warning("%s: watch trigger %s failed: %s", self.env.id, name, e)
            return default

    async def scan(self, frm: datetime, to: datetime, known_disconnected: set[str] | None) -> tuple[list[dict], set[str] | None]:
        a, b, c, d = await asyncio.gather(
            self._safe("alerts", self.alerts(frm, to), []),
            self._safe("brute_force", self.brute_force(frm, to), []),
            self._safe("spike", self.spike(frm, to), []),
            self._safe("agents", self.agents(to, known_disconnected), ([], known_disconnected)))
        return a + b + c + d[0], d[1]

    # -------------------------------------------------------- level / rules / groups / active response
    async def alerts(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        should: list[dict] = []
        if cfg.on("level"):
            should.append({"range": {"rule.level": {"gte": cfg.critical_level}}})
        if cfg.on("rules") and self.rules:
            should.append({"terms": {"rule.id": sorted(self.rules)}})
        if cfg.on("groups") and self.groups:
            should.append({"bool": {"filter": [{"terms": {"rule.groups": sorted(self.groups)}},
                                               {"range": {"rule.level": {"gte": cfg.group_min_level}}}]}})
        if cfg.on("active_response"):
            should.append({"term": {"rule.groups": "active_response"}})
        if not should:
            return []
        r = await self.ix.search(self.env.alerts_index, {
            "size": MAX_HITS, "sort": [{TS: "desc"}], "_source": FIELDS,
            "query": {"bool": {"filter": [rng(frm, to)], "should": should, "minimum_should_match": 1}}})
        by_key: dict[str, dict] = {}
        for h in r["hits"]["hits"]:
            src = h["_source"]
            cl = classify(src, cfg, self.rules, self.groups)
            if not cl:
                continue
            trig, sev = cl
            rid, agent = str(_get(src, "rule.id") or ""), str(_get(src, "agent.name") or "")
            key = f"{trig}:{rid}:{agent}"
            ev = by_key.get(key)
            if ev is None:
                ev = by_key[key] = _event(
                    self.env.id, key, trig, sev, rule_ids=[rid], agents=[agent] if agent else [],
                    level=_level(src), title=str(_get(src, "rule.description") or "")[:200], srcips=[],
                    first_seen=src.get(TS), last_seen=src.get(TS), count=0,
                    sample=str(src.get("full_log") or "")[:400])
            ev["count"] += 1
            ev["first_seen"] = src.get(TS) or ev["first_seen"]          # hits are newest first
            ip = _get(src, "data.srcip")
            if ip and ip not in ev["srcips"] and len(ev["srcips"]) < 5:
                ev["srcips"].append(ip)
            if sev == "critical":
                ev["severity"] = "critical"
        total = r["hits"]["total"]["value"]
        out = list(by_key.values())
        if total > MAX_HITS and out:
            out[0]["truncated"] = total
        return out

    # -------------------------------------------------------- failed logins, then a success
    async def brute_force(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        if not cfg.on("brute_force"):
            return []
        ok = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"terms": {"rule.groups": AUTH_OK}},
                                                     {"exists": {"field": "data.srcip"}}]}},
            "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 200},
                            "aggs": {"last": {"max": {"field": TS}},
                                     "agent": {"terms": {"field": "agent.name", "size": 3}},
                                     "user": {"terms": {"field": "data.dstuser", "size": 3}}}}}})
        winners = {str(x["key"]): x for x in _b(ok["aggregations"]["ip"])}
        if not winners:
            return []
        start = frm - timedelta(minutes=cfg.brute_window_minutes)
        fails = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(start, to), {"terms": {"rule.groups": AUTH_FAIL}},
                                                     {"terms": {"data.srcip": sorted(winners)}}]}},
            "aggs": {"ip": {"terms": {"field": "data.srcip", "size": 200},
                            "aggs": {"first": {"min": {"field": TS}}}}}})
        out = []
        for bk in _b(fails["aggregations"]["ip"]):
            ip, n = str(bk["key"]), int(bk["doc_count"])
            if n < cfg.brute_failures:
                continue
            w = winners[ip]
            first, last = _agg_ts(bk.get("first")), _agg_ts(w.get("last"))
            if first and last and first >= last:      # the failures came after the success: not this pattern
                continue
            agents = [str(x["key"]) for x in _b(w.get("agent") or {})]
            users = [str(x["key"]) for x in _b(w.get("user") or {})]
            out.append(_event(self.env.id, f"brute_force:{ip}", "brute_force", "critical", rule_ids=[],
                              agents=agents, srcips=[ip], users=users, count=n, successes=int(w["doc_count"]),
                              first_seen=iso(first) if first else None, last_seen=iso(last) if last else None,
                              title=t(self.lang, "watch.ev.brute_force", ip=ip, n=n,
                                      m=cfg.brute_window_minutes, agents=", ".join(agents) or "?")))
        return out

    # -------------------------------------------------------- volume
    async def spike(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        if not cfg.on("spike"):
            return []
        span = (to - frm).total_seconds()
        if span <= 0:
            return []
        cur = await self.ix.count(self.env.alerts_index, {"bool": {"filter": [rng(frm, to)]}})
        if cur < cfg.spike_min:
            return []
        day = await self.ix.count(self.env.alerts_index, {"bool": {"filter": [rng(frm - timedelta(hours=24), frm)]}})
        avg = day * span / 86400
        if avg <= 0 or cur < cfg.spike_factor * avg:
            return []
        return [_event(self.env.id, "spike:total", "spike", "high", rule_ids=[], agents=[], srcips=[], count=cur,
                       first_seen=iso(frm), last_seen=iso(to), baseline=round(avg, 1),
                       factor=round(cur / avg, 1),
                       title=t(self.lang, "watch.ev.spike", n=f"{cur:,}", m=round(span / 60),
                               x=round(cur / avg, 1), avg=f"{round(avg):,}"))]

    # -------------------------------------------------------- agents
    async def agents(self, now: datetime, known: set[str] | None) -> tuple[list[dict], set[str] | None]:
        cfg = self.cfg
        if not cfg.on("agents") or not self.api:
            return [], known
        rows = await self.api.agents(status="disconnected", limit=500)
        lost: dict[str, str] = {}
        for a in rows or []:
            name = str(a.get("name") or a.get("id") or "")
            if not name or any(fnmatch.fnmatch(name, p) for p in self.env.ignore_agents):
                continue
            try:
                since = _parse(str(a.get("lastKeepAlive") or ""))
            except ValueError:
                continue
            if (now - since).total_seconds() >= cfg.agent_minutes * 60:
                lost[name] = iso(since)
        current = set(lost)
        if known is None:                      # first scan after a start: learn the state, announce nothing
            return [], current
        new = sorted(current - known)
        if not new:
            return [], current
        many = len(new) >= 5
        ev = _event(self.env.id, "agents:" + ",".join(new)[:150], "agents", "critical" if many else "high",
                    rule_ids=[], agents=new[:50], srcips=[], count=len(new), first_seen=min(lost[n] for n in new),
                    last_seen=iso(now), title=t(self.lang, "watch.ev.agents", n=len(new),
                                                names=", ".join(new[:8]) + ("…" if len(new) > 8 else ""),
                                                m=cfg.agent_minutes))
        return [ev], current


def _agg_ts(agg: dict | None) -> datetime | None:
    if not agg:
        return None
    v = agg.get("value_as_string") or agg.get("value")
    if v is None:
        return None
    try:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v / 1000, UTC)
        return _parse(str(v))
    except (ValueError, OSError):
        return None


# ------------------------------------------------------------------ sorting out
def muted(ev: dict, mute: list[str]) -> bool:
    """A mute entry is an event key, a key prefix ending in ``*`` or ``rule:<id>``."""
    for m in mute:
        if m == ev["key"] or (m.endswith("*") and ev["key"].startswith(m[:-1])):
            return True
        if m.startswith("rule:") and m[5:] in (ev.get("rule_ids") or []):
            return True
    return False


def known_noise(ev: dict, baseline_rules: set[str]) -> bool:
    """Alert-based events whose rule a human already filed as known noise (knowledge base ``baseline``)."""
    return ev["trigger"] in ("rules", "groups", "level") and ev["severity"] != "critical" \
        and bool(ev.get("rule_ids")) and set(ev["rule_ids"]) <= baseline_rules


def channels_for(cfg: NotifyCfg, selected: list[str]) -> NotifyCfg:
    """The notification config limited to the channels chosen in the settings page (empty = all)."""
    if not selected:
        return cfg
    out = cfg.model_copy(deep=True)
    for name in CHANNELS:
        if name not in selected:
            setattr(out, name, type(getattr(out, name))())
    return out


def quiet_now(cfg: WatchSettings, now_local: datetime) -> bool:
    day = DAYS[now_local.weekday()]
    prev = DAYS[(now_local.weekday() - 1) % 7]
    return cfg.quiet.active(now_local.strftime("%H:%M"), day, prev)


def event_line(ev: dict, lang: str) -> str:
    mark = "🔴" if ev["severity"] == "critical" else "🟠"
    where = ", ".join((ev.get("agents") or [])[:3])
    bits = [t(lang, "watch.trigger." + ev["trigger"])]
    if ev.get("rule_ids") and ev["rule_ids"][0]:
        bits.append(f"{ev['rule_ids'][0]} (L{ev.get('level', '?')})")
    head = f"{mark} [{' · '.join(bits)}] {ev.get('title') or ev['key']}"
    tail = [f"×{ev['count']}"] if ev.get("count", 1) > 1 and ev["trigger"] in ("level", "rules", "groups",
                                                                                "active_response") else []
    if where and ev["trigger"] != "agents":
        tail.append(where)
    if ev.get("srcips") and ev["trigger"] != "brute_force":
        tail.append(", ".join(ev["srcips"][:3]))
    return head + (" — " + " · ".join(tail) if tail else "")


def compact_for_ai(ev: dict) -> dict:
    """What the AI round sees of one event (ids and numbers; the sample goes through the masker like all text)."""
    keep = ("id", "trigger", "severity", "title", "rule_ids", "level", "agents", "srcips", "users", "count",
            "first_seen", "last_seen", "baseline", "factor", "successes", "status", "sample")
    return {k: ev[k] for k in keep if ev.get(k) not in (None, "", [])}


def normalize_verdicts(raw, known_ids: set[str]) -> list[dict]:
    """Model output → verdicts for events that exist; a malformed entry is dropped, never fatal."""
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for v in raw:
        if not isinstance(v, dict) or str(v.get("event_id")) not in known_ids:
            continue
        verdict = str(v.get("verdict") or "")
        if verdict not in VERDICTS:
            verdict = "investigate"
        sug = None
        s = v.get("suggestion")
        if isinstance(s, dict):
            if s.get("mute") is True:
                sug = {"type": "mute"}
            elif s.get("param") in TUNABLE:
                try:
                    val = float(s.get("value"))
                except (TypeError, ValueError):
                    val = None
                lo, hi = TUNABLE[s["param"]]
                if val is not None and lo <= val <= hi:
                    sug = {"type": "param", "param": s["param"], "value": val}
            if sug:
                sug["why"] = str(s.get("why") or "")[:300]
        out.append({"event_id": str(v["event_id"]), "verdict": verdict, "reason": str(v.get("reason") or "")[:600],
                    "suggestion": sug})
    return out


# ------------------------------------------------------------------ runtime side
class WatchMixin:
    """Scheduler tick, persistence, notification and the hand-over to the AI round."""

    async def watch_state(self, rt: EnvRuntime) -> dict:
        return await rt.repo.get_state("watch") or {}

    async def watch_scan(self, env_id: str, transport=None, now: datetime | None = None) -> dict:
        """One scan. Returns a summary; safe to call by hand ("scan now")."""
        rt = self.get(env_id)
        st = await self.env_settings(rt)
        cfg = st.watch
        if not cfg.enabled:
            return {"enabled": False}
        lang = self.lang(rt.env)
        now = now or datetime.now(UTC)
        state = await self.watch_state(rt)
        try:
            frm = _parse(state["cursor"])
        except (KeyError, ValueError):
            frm = now - timedelta(minutes=cfg.interval_minutes)
        gap = None
        if (now - frm).total_seconds() > MAX_WINDOW_MINUTES * 60:
            gap = {"from": iso(frm), "to": iso(now - timedelta(minutes=MAX_WINDOW_MINUTES))}
            frm = now - timedelta(minutes=MAX_WINDOW_MINUTES)
        if frm >= now:
            return {"enabled": True, "events": 0, "skipped": "clock"}
        known = set(state["disconnected"]) if isinstance(state.get("disconnected"), list) else None
        sc = Scanner(rt.env, rt.ix, rt.api, cfg, lang)
        found, disconnected = await sc.scan(frm, now, known)

        baseline = {str(r) for k in await rt.repo.list_knowledge(kinds=["baseline"], status="active")
                    for r in k.get("rule_ids") or []}
        recent = {e["key"]: e for e in reversed(await rt.repo.list_events(300))}
        cutoff = now - timedelta(hours=cfg.repeat_hours)
        fresh: list[dict] = []
        for ev in found:
            old = recent.get(ev["key"])
            if old and _parse(old["created_at"]) >= cutoff:        # same thing again: count it, stay silent
                old["count"] = int(old.get("count") or 1) + int(ev.get("count") or 1)
                old["last_seen"] = ev.get("last_seen") or now_iso()
                old["repeats"] = int(old.get("repeats") or 0) + 1
                await rt.repo.save_event(old)
                continue
            if muted(ev, cfg.mute):
                ev["status"], ev["why_silent"] = "muted", "mute"
            elif known_noise(ev, baseline):
                ev["status"], ev["why_silent"] = "muted", "baseline"
            fresh.append(ev)

        quiet = quiet_now(cfg, now.astimezone(self.tz))
        to_send = [e for e in fresh if e["status"] == "new"
                   and not (quiet and not (cfg.quiet.allow_critical and e["severity"] == "critical"))]
        for e in fresh:
            if e["status"] == "new" and e not in to_send:
                e["status"] = "held"
        held_before = [] if quiet else await rt.repo.list_events(100, status="held")
        result = None
        if to_send or held_before:
            result = await self._watch_notify(rt, to_send, held_before, lang, transport)
            stamp = now_iso()
            for e in to_send + held_before:
                e["status"], e["notified_at"], e["notify_result"] = "notified", stamp, result
        for e in fresh + held_before:
            await rt.repo.save_event(e)
        new_state = {"cursor": iso(now), "disconnected": sorted(disconnected) if disconnected is not None else None,
                     "last_scan": {"at": iso(now), "from": iso(frm), "found": len(found), "new": len(fresh),
                                   "sent": len(to_send) + len(held_before), "quiet": quiet,
                                   "errors": sc.errors, "gap": gap}}
        await rt.repo.put_state("watch", new_state)
        metrics.inc("wdt_watch_scans_total", env=env_id)
        if fresh:
            metrics.inc("wdt_watch_events_total", float(len(fresh)), env=env_id)
            log.info("%s watch: %d new event(s), %d announced%s", env_id, len(fresh), len(to_send),
                     " (quiet hours)" if quiet else "")
        return {"enabled": True, "events": len(fresh), "sent": len(to_send) + len(held_before), "quiet": quiet,
                "errors": sc.errors, "notify": result}

    async def _watch_notify(self, rt: EnvRuntime, events: list[dict], held: list[dict], lang: str, transport) -> dict:
        st = await self.env_settings(rt)
        ncfg = channels_for(self.settings.notify_for(rt.env), st.watch.channels)
        if not ncfg.enabled or not ncfg.channels:
            return {}
        sev = {"critical": 0, "high": 1}
        events = sorted(events, key=lambda e: sev.get(e["severity"], 2))
        lines = [event_line(e, lang) for e in events[:20]]
        if len(events) > 20:
            lines.append(t(lang, "watch.more", n=len(events) - 20))
        if held:
            lines.append(t(lang, "watch.held", n=len(held)))
            lines += [event_line(e, lang) for e in held[:15]]
        lines.append(t(lang, "watch.not_ai"))
        crit = any(e["severity"] == "critical" for e in events + held)
        link = f"{ncfg.ui_url.rstrip('/')}/e/{rt.env.id}/watch" if ncfg.ui_url else ""
        msg = plain_message(t(lang, "watch.title_critical" if crit else "watch.title", env=rt.env.name), lines, link)
        msg["link_title"] = t(lang, "watch.open")
        try:
            return await notify_send(ncfg, msg, transport=transport)
        except Exception:  # noqa: BLE001 - a notification problem must never stop the watch
            log.exception("%s: watch notification failed", rt.env.id)
            return {}

    async def _watch_tick(self):
        loop_now = asyncio.get_running_loop().time()
        for env_id, rt in self.envs.items():
            if env_id in self._watch_busy:
                continue
            try:
                cfg = (await self.env_settings(rt)).watch
            except Exception as e:  # noqa: BLE001 - the indexer may be down; liveness reports that
                log.debug("%s: settings unavailable for the watch: %s", env_id, e)
                continue
            if not cfg.enabled or loop_now - self._watch_last.get(env_id, -1e9) < cfg.interval_minutes * 60:
                continue
            self._watch_last[env_id] = loop_now
            self._watch_busy.add(env_id)

            async def go(eid=env_id):
                try:
                    await self.watch_scan(eid, transport=self.notify_transport)
                except Exception:  # noqa: BLE001
                    log.exception("watch scan failed: %s", eid)
                finally:
                    self._watch_busy.discard(eid)
            task = asyncio.create_task(go())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # -------------------------------------------------------- AI round hand-over
    async def watch_pending(self, rt: EnvRuntime, limit: int = 60) -> list[dict]:
        """Events without a verdict, most severe first — handed to the next AI round in one go."""
        rows = [e for e in await rt.repo.list_events(400, status=list(PENDING)) if not e.get("verdict")]
        sev = {"critical": 0, "high": 1}
        rows.sort(key=lambda e: (sev.get(e["severity"], 2), e["status"] == "muted", e["created_at"]))
        return rows[:limit]

    async def watch_apply_verdicts(self, rt: EnvRuntime, verdicts: list[dict], run_id: str) -> int:
        n = 0
        for v in verdicts:
            ev = await rt.repo.get_event(v["event_id"])
            if not ev:
                continue
            ev.update(verdict=v["verdict"], reason=v["reason"], status="judged", judged_at=now_iso(),
                      judged_run=run_id)
            if v.get("suggestion"):
                ev["suggestion"] = {**v["suggestion"], "state": "open"}
            await rt.repo.save_event(ev)
            n += 1
        return n

    async def watch_suggestion(self, env_id: str, event_id: str, action: str, by: str) -> dict:
        """An administrator accepts or dismisses the model's tuning suggestion. Nothing is applied without this."""
        rt = self.get(env_id)
        ev = await rt.repo.get_event(event_id)
        sug = (ev or {}).get("suggestion")
        if not ev or not sug or sug.get("state") != "open":
            raise ValueError("no open suggestion on this event")
        if action == "apply":
            st = await self.env_settings(rt)
            watch = st.watch.model_dump()
            if sug["type"] == "mute":
                watch["mute"] = sorted(set(watch["mute"]) | {ev["key"]})
            else:
                kind = type(watch[sug["param"]])
                watch[sug["param"]] = kind(sug["value"])
            await self.save_settings(env_id, {"watch": watch}, by)
        elif action != "dismiss":
            raise ValueError("action must be apply or dismiss")
        sug.update(state="applied" if action == "apply" else "dismissed", by=by, at=now_iso())
        await rt.repo.save_event(ev)
        return ev
