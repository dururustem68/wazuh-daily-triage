# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Notifications for critical situations: e-mail (SMTP), Telegram, Microsoft Teams (Workflows webhook).

Only the essentials leave the system: environment, severity, finding titles and a link to the report.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import httpx
from pydantic import BaseModel, Field, field_validator

from .i18n import t

log = logging.getLogger("wdt.notify")


class EmailCfg(BaseModel):
    host: str = ""
    port: int = 587
    security: str = "starttls"   # starttls | ssl | none
    username: str = ""
    password: str = ""
    sender: str = ""
    to: list[str] = Field(default_factory=list)
    verify_tls: bool = True

    @field_validator("to", mode="before")
    @classmethod
    def _to(cls, v):
        if isinstance(v, str):
            v = [v]
        return [a.strip() for x in (v or []) for a in str(x).split(",") if a.strip()]

    @property
    def enabled(self) -> bool:
        return bool(self.host and self.sender and self.to)


class TelegramCfg(BaseModel):
    bot_token: str = ""
    chat_id: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)


class TeamsCfg(BaseModel):
    webhook_url: str = ""        # Teams "Workflows" → "Post to a channel when a webhook request is received"

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)


class NotifyCfg(BaseModel):
    enabled: bool = True
    on_critical_flags: bool = True      # SIEM silent, indexer red, daemons down, disk >= 90 %
    on_real_incident: bool = True       # findings labelled real_incident
    on_critical_findings: bool = True   # findings with severity critical
    on_run_error: bool = False          # the triage run itself failed
    on_run_summary: bool = False        # a short summary after EVERY run (health, counts, waiting recommendations)
    on_rule_deploy: bool = True         # a rule draft was deployed, failed (rolled back) or removed
    repeat_hours: int = 24              # do not repeat the same item within this period
    ui_url: str = ""                    # base URL used for links, e.g. http://127.0.0.1:18080
    email: EmailCfg = Field(default_factory=EmailCfg)
    telegram: TelegramCfg = Field(default_factory=TelegramCfg)
    teams: TeamsCfg = Field(default_factory=TeamsCfg)

    @property
    def channels(self) -> list[str]:
        return [n for n, c in (("email", self.email), ("telegram", self.telegram), ("teams", self.teams)) if c.enabled]


# ----------------------------------------------------------------------------- selection
def critical_items(run: dict, cfg: NotifyCfg, finding_key) -> list[dict]:
    """[{key, kind, text}] that deserve a notification for this run."""
    items: list[dict] = []
    if run.get("status") == "error":
        if cfg.on_run_error:
            items.append({"key": "run_error", "kind": "error", "text": run.get("error", "")[:300]})
        return items
    if cfg.on_critical_flags:
        for f in run.get("flags") or []:
            if f.get("severity") == "critical":
                items.append({"key": f"flag:{f.get('code')}", "kind": "flag", "text": f.get("message", "")})
    for f in run.get("findings") or []:
        if f.get("user_status", "new") != "new":
            continue
        if (cfg.on_real_incident and f.get("label") == "real_incident") or \
           (cfg.on_critical_findings and f.get("severity") == "critical"):
            items.append({"key": "finding:" + finding_key(f), "kind": "finding", "text": f.get("title", ""),
                          "fid": f.get("id")})
    return items


def recently_notified(previous_runs: list[dict], hours: int) -> set[str]:
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    keys: set[str] = set()
    for r in previous_runs:
        for n in r.get("notified") or []:
            try:
                ts = datetime.fromisoformat(n["ts"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            if ts >= cutoff:
                keys.add(n["key"])
    return keys


# ----------------------------------------------------------------------------- message
def build_message(env_name: str, run: dict, items: list[dict], cfg: NotifyCfg, lang: str, env_id: str) -> dict:
    link = f"{cfg.ui_url.rstrip('/')}/e/{env_id}/r/{run['run_id']}" if cfg.ui_url else ""
    title = t(lang, "notify.title", env=env_name)
    lines = [t(lang, "notify.kind." + i["kind"]) + ": " + i["text"] for i in items]
    return {"title": title, "lines": lines, "link": link,
            "text": "\n".join([title, ""] + [f"• {x}" for x in lines] + ([f"\n{link}"] if link else []))}


def summary_lines(run: dict, lang: str, inbox_waiting: int | None, label_name) -> list[str]:
    m = run.get("metrics") or {}
    lvl = ((run.get("collected") or {}).get("env") or {}).get("high_level", "")
    out = [t(lang, "notify.sum_counts", total=f"{m.get('total', 0):,}", high=f"{m.get('high', 0):,}", lvl=lvl)]
    counts: dict[str, int] = {}
    for f in run.get("findings") or []:
        counts[f.get("label", "")] = counts.get(f.get("label", ""), 0) + 1
    if counts:
        out.append(t(lang, "notify.sum_findings", n=sum(counts.values()),
                     labels=", ".join(f"{n} {label_name(k)}" for k, n in sorted(counts.items(), key=lambda x: -x[1]))))
    if inbox_waiting:
        out.append(t(lang, "notify.sum_inbox", n=inbox_waiting))
    if run.get("ai_error"):
        out.append(t(lang, "notify.sum_ai_error"))
    return out


def plain_message(title: str, lines: list[str], link: str = "") -> dict:
    return {"title": title, "lines": lines, "link": link,
            "text": "\n".join([title, ""] + [f"• {x}" for x in lines] + ([f"\n{link}"] if link else []))}


# ----------------------------------------------------------------------------- channels
def _send_email(cfg: EmailCfg, msg: dict):
    m = EmailMessage()
    m["Subject"] = msg["title"]
    m["From"] = cfg.sender
    m["To"] = ", ".join(cfg.to)
    m.set_content(msg["text"])
    ctx = ssl.create_default_context()
    if not cfg.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cfg.security == "ssl":
        s = smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx, timeout=20)
    else:
        s = smtplib.SMTP(cfg.host, cfg.port, timeout=20)
        if cfg.security == "starttls":
            s.starttls(context=ctx)
    try:
        if cfg.username:
            s.login(cfg.username, cfg.password)
        s.send_message(m)
    finally:
        s.quit()


async def _send_telegram(cfg: TelegramCfg, msg: dict, client: httpx.AsyncClient):
    r = await client.post(f"https://api.telegram.org/bot{cfg.bot_token}/sendMessage",
                          json={"chat_id": cfg.chat_id, "text": msg["text"][:4000], "disable_web_page_preview": True})
    if r.status_code >= 400:
        raise RuntimeError(f"Telegram {r.status_code}: {r.text[:200]}")


async def _send_teams(cfg: TeamsCfg, msg: dict, client: httpx.AsyncClient):
    body = [{"type": "TextBlock", "text": msg["title"], "weight": "Bolder", "size": "Medium", "color": "Attention",
             "wrap": True}]
    body += [{"type": "TextBlock", "text": f"• {x}", "wrap": True} for x in msg["lines"][:20]]
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "body": body}
    if msg["link"]:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Report", "url": msg["link"]}]
    payload = {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}
    r = await client.post(cfg.webhook_url, json=payload)
    if r.status_code >= 400:
        raise RuntimeError(f"Teams {r.status_code}: {r.text[:200]}")


async def send(cfg: NotifyCfg, msg: dict, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, str]:
    """Send to every configured channel; returns {channel: "ok" | error}."""
    res: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=20, transport=transport) as client:
        for name in cfg.channels:
            try:
                if name == "email":
                    await asyncio.to_thread(_send_email, cfg.email, msg)
                elif name == "telegram":
                    await _send_telegram(cfg.telegram, msg, client)
                elif name == "teams":
                    await _send_teams(cfg.teams, msg, client)
                res[name] = "ok"
            except Exception as e:  # noqa: BLE001
                log.warning("notification via %s failed: %s", name, e)
                res[name] = f"{type(e).__name__}: {e}"[:300]
    return res
