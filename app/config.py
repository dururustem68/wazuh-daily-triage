# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Configuration: config/environments.yaml (multi-environment) or plain environment
variables (single environment).

``${VAR}`` and ``${VAR:-default}`` inside the YAML are expanded from the process
environment so secrets can live in ``.env`` rather than in the file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, Field, field_validator

from .notify import NotifyCfg

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
LANGUAGES = ("en", "tr", "es", "de")


def _expand(value):
    if isinstance(value, str):
        # like the shell's ${VAR:-default}: an empty variable also falls back to the default
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


class Endpoint(BaseModel):
    url: str
    username: str = ""
    password: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    # optional mutual TLS (client certificate authentication)
    client_cert: str | None = None
    client_key: str | None = None
    timeout: float = 30.0

    @property
    def verify(self):
        if self.ca_file:
            return self.ca_file
        return self.verify_tls

    @property
    def cert(self):
        if self.client_cert:
            return (self.client_cert, self.client_key) if self.client_key else self.client_cert
        return None


DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class LivenessCfg(BaseModel):
    """Quick health check every few minutes, without the LLM: notifies when Wazuh breaks and when it recovers."""
    enabled: bool = True
    interval_minutes: int = Field(10, ge=2, le=120)
    silence_minutes: int | None = None    # default: the environment's max_silence_minutes
    repeat_hours: float = 2               # remind while a problem persists
    notify_recovery: bool = True


class QueryLimitsCfg(BaseModel):
    """Hard limits for every query the AI (or an MCP client) can trigger.

    The model can only narrow or widen a window inside these bounds; field names are checked against an
    allow-list, so a prompt-injected instruction cannot turn into an expensive or arbitrary query.
    """
    max_range_hours: int = Field(24 * 14, ge=1, le=24 * 366)   # widest window per tool call
    max_buckets: int = Field(200, ge=10, le=10_000)            # date_histogram buckets per query
    max_terms_size: int = Field(50, ge=1, le=10_000)           # terms aggregation bucket count
    max_size: int = Field(25, ge=1, le=1_000)                  # documents returned
    min_interval: str = "1m"                                   # smallest histogram interval
    max_concurrent: int = Field(8, ge=1, le=64)                # parallel queries per environment
    request_timeout: float | None = Field(None, gt=0, le=600)  # overrides indexer.timeout when set
    extra_fields: list[str] = Field(default_factory=list)      # allow-listed fields on top of the built-ins

    @field_validator("min_interval")
    @classmethod
    def _interval(cls, v):
        if not re.fullmatch(r"\d+[smhdw]", v):
            raise ValueError("min_interval must look like 30s, 1m, 1h")
        return v


class MailCfg(BaseModel):
    """The manager's e-mail limits (ossec.conf <global>). When set, each run shows the hours in which the alert mail
    channel was saturated and the alerts that may never have been mailed in those hours."""
    alert_level: int = 7          # email_alert_level
    max_per_hour: int = 12        # email_maxperhour (Wazuh default 12)


class VulnSlaCfg(BaseModel):
    """Days an active vulnerability may stay open, per severity (0 = not tracked)."""
    critical: int = 15
    high: int = 30
    medium: int = 90
    low: int = 0

    def days(self) -> dict[str, int]:
        return {k.capitalize(): v for k, v in self.model_dump().items() if v}


class PromoteCfg(BaseModel):
    """How a tested rule draft becomes a permanent rule in your own configuration management ("promotion package").

    mode `host`: the rules file lives on the manager host. mode `kubernetes`: the file is in a kustomize repo
    (e.g. wazuh-kubernetes) and is rolled out with `kubectl apply -k`.
    """
    mode: Literal["host", "kubernetes"] = "host"
    repo_dir: str = ""                    # kubernetes: repository root on the operator's machine
    rules_file: str = "/var/ossec/etc/rules/local_rules.xml"   # host: absolute; kubernetes: relative to repo_dir
    catalog_file: str = ""                # optional markdown alert catalogue (relative to repo_dir) — a § draft is generated
    kubeconfig: str = ""
    namespace: str = "wazuh"
    master_pod: str = "wazuh-manager-master-0"
    kustomize_dir: str = ""               # relative to repo_dir, e.g. k8s/wazuh
    manager_label: str = "app=wazuh-manager"   # pods that must become Ready again after the rollout


class SourceEndpoint(BaseModel):
    url: str = ""
    username: str = ""
    password: str = ""
    bearer_token: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    timeout: float = 30.0
    org_id: str = ""                      # Loki multi-tenancy (X-Scope-OrgID)

    @property
    def verify(self):
        return self.ca_file or self.verify_tls


class KubernetesSource(BaseModel):
    """Read-only Kubernetes API (pods, nodes, events, workloads, pod logs; never secrets or configmaps)."""
    enabled: bool = False
    in_cluster: bool = True               # use the pod's service account (needs the rbac-readonly component)
    api_url: str = ""                     # when not in cluster
    token: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    namespaces: list[str] = Field(default_factory=list)   # optional allow-list; empty = all
    pod_logs: bool = True


class SourcesCfg(BaseModel):
    """Extra read-only data sources the AI can query next to Wazuh."""
    prometheus: SourceEndpoint | None = None
    loki: SourceEndpoint | None = None
    kubernetes: KubernetesSource = Field(default_factory=KubernetesSource)

    @field_validator("prometheus", "loki", mode="before")
    @classmethod
    def _empty(cls, v):
        return None if isinstance(v, dict) and not v.get("url") else v


class ZammadCfg(BaseModel):
    url: str = ""
    token: str = ""
    group: str = "Users"
    customer: str = ""                    # e-mail of the ticket customer
    verify_tls: bool = True


class JiraCfg(BaseModel):
    url: str = ""                         # https://<site>.atlassian.net (or a self-hosted base URL)
    email: str = ""                       # the account e-mail (basic auth user)
    token: str = ""                       # Jira Cloud API token / personal access token
    project: str = ""                     # project key, e.g. SEC
    issue_type: str = "Task"              # issue type name, e.g. Task / Incident
    verify_tls: bool = True


class IncidentCfg(BaseModel):
    """Incident record drafts from findings (e.g. ISO 27001 / ISMS-18 records)."""
    id_prefix: str = "INC-"
    template_file: str | None = None      # markdown skeleton the AI fills; default: built-in
    template: str | None = None           # … or the skeleton inline ({id} {title} {by} are filled in)
    zammad: ZammadCfg | None = None       # optional: open the draft as an internal Zammad ticket
    jira: JiraCfg | None = None           # optional: open the draft as a Jira issue

    @field_validator("zammad", "jira", mode="before")
    @classmethod
    def _z(cls, v):
        return None if isinstance(v, dict) and not v.get("url") else v


class RuleDeployCfg(BaseModel):
    """Optional: let "Approve and deploy" write approved rule drafts to the manager.

    Off by default. Uses a SEPARATE Wazuh API user whose only write rights are uploading custom rules files and
    manager/cluster restart (docs/rule-deployment.md); the application writes only the file below.
    """
    enabled: bool = False
    username: str = ""
    password: str = ""
    file: str = "wdt_rules.xml"          # in etc/rules on the manager (master node in a cluster)
    id_min: int = 100000                 # drafts outside this ID range are refused
    id_max: int = 119999
    restart_timeout: int = 180           # seconds to wait for the manager to come back
    # deployment gate (fail closed): a draft without logtest samples, or with a sample that cannot be
    # reproduced, is not deployed automatically. Set require_tests: true to enforce samples for every draft.
    require_tests: bool = False
    allow_inconclusive: bool = False     # true = an unreproducible sample is still deployed (with a warning)

    @field_validator("file")
    @classmethod
    def _file(cls, v):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}\.xml", v):
            raise ValueError("rule_deploy.file must be a plain file name ending in .xml")
        return v


_HM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


class Schedule(BaseModel):
    enabled: bool = True
    time: str = "07:30"  # HH:MM in app.timezone (single run per day)
    times: list[str] = Field(default_factory=list)  # several runs per day, e.g. ["07:50", "19:50"]; overrides `time`
    days: list[str] = Field(default_factory=lambda: list(DAYS))

    @property
    def all_times(self) -> list[str]:
        return sorted(set(self.times)) if self.times else [self.time]

    @field_validator("times")
    @classmethod
    def _times(cls, v):
        bad = [x for x in v if not _HM.fullmatch(x)]
        if bad:
            raise ValueError(f"times must be HH:MM: {bad}")
        return v

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        v = [d.lower()[:3] for d in v]
        bad = [d for d in v if d not in DAYS]
        if bad:
            raise ValueError(f"invalid day(s): {bad}")
        return v

    @field_validator("time")
    @classmethod
    def _time(cls, v):
        if not _HM.fullmatch(v):
            raise ValueError("time must be HH:MM")
        return v


class LLMConfig(BaseModel):
    provider: Literal["anthropic", "openai", "mock"] = "anthropic"
    model: str = ""
    base_url: str | None = None
    api_key: str = ""
    max_tokens: int = 4096
    temperature: float | None = 0.2   # leave empty for reasoning models that only accept the default
    # OpenAI-compatible: newer models want max_completion_tokens
    token_param: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    extra_body: dict = Field(default_factory=dict)  # passed through to the provider verbatim
    max_tool_steps: int = 14
    max_retries: int = 4              # retries on 429/5xx/overload with backoff (honours Retry-After)
    timeout: float = 180.0

    @field_validator("temperature", mode="before")
    @classmethod
    def _temp(cls, v):
        return None if v in ("", None) else v


class Environment(BaseModel):
    id: str
    name: str
    description: str = ""
    indexer: Endpoint
    api: Endpoint | None = None
    alerts_index: str = "wazuh-alerts-4.x-*"
    vuln_index: str = "wazuh-states-vulnerabilities-*"
    storage_prefix: str = "daily-triage"
    schedule: Schedule = Field(default_factory=Schedule)
    # Window: since the last successful run; min = fallback without a report, max = cap
    window_min_hours: int = 24
    window_max_hours: int = 96
    high_level: int = 7
    max_silence_minutes: int = 60
    disk_warn_percent: int = 75
    required_daemons: list[str] = Field(default_factory=lambda: [
        "wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd", "wazuh-apid"])
    watch_rules: list[str] = Field(default_factory=list)
    watch_groups: list[str] = Field(default_factory=list)
    context_file: str | None = None
    seed_file: str | None = None      # imported into the knowledge base once, on first use
    redact: bool = False
    language: str | None = None       # report language override (en|tr)
    llm: LLMConfig | None = None      # per-environment model override (e.g. local model for regulated data)
    notify: NotifyCfg | None = None   # per-environment notification override
    rule_deploy: RuleDeployCfg = Field(default_factory=RuleDeployCfg)
    liveness: LivenessCfg = Field(default_factory=LivenessCfg)
    query: QueryLimitsCfg = Field(default_factory=QueryLimitsCfg)
    mail: MailCfg | None = None          # set to analyse e-mail channel saturation
    vuln_sla: VulnSlaCfg = Field(default_factory=VulnSlaCfg)
    promote: PromoteCfg = Field(default_factory=PromoteCfg)
    inventory: list[str] = Field(default_factory=list)   # expected agent names (coverage reconciliation)
    inventory_file: str | None = None    # one agent name per line (# comments allowed)
    sources: SourcesCfg = Field(default_factory=SourcesCfg)
    incident: IncidentCfg = Field(default_factory=IncidentCfg)
    anomaly: bool = True                  # deterministic rule×agent anomalies against a 14-day baseline
    run_retention_days: int = Field(default=0, ge=0)   # 0 = keep runs forever; knowledge is never pruned

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,40}", v):
            raise ValueError("id must be lowercase letters/digits/-/_")
        return v

    @field_validator("watch_rules", mode="before")
    @classmethod
    def _rules(cls, v):
        return [str(x) for x in (v or [])]

    @field_validator("api", mode="before")
    @classmethod
    def _api(cls, v):
        if isinstance(v, dict) and not v.get("url"):
            return None
        return v

    def resolve(self, base: Path, rel: str | None) -> Path | None:
        if not rel:
            return None
        p = Path(rel)
        return p if p.is_absolute() else base / p

    def inventory_names(self, base: Path) -> list[str]:
        names = list(self.inventory)
        p = self.resolve(base, self.inventory_file)
        if p:
            try:
                names += [ln.split("#", 1)[0].strip() for ln in p.read_text(encoding="utf-8").splitlines()]
            except OSError:
                pass
        return sorted({n for n in names if n})

    def context_text(self, base: Path) -> str:
        p = self.resolve(base, self.context_file)
        try:
            return p.read_text(encoding="utf-8") if p else ""
        except OSError:
            return ""


class AppConfig(BaseModel):
    timezone: str = "UTC"
    language: str = "en"
    title: str = "Wazuh Daily Triage"

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise ValueError(f"unknown timezone {v!r}; install the tzdata package") from e
        return v

    @field_validator("language")
    @classmethod
    def _lang(cls, v):
        if v not in LANGUAGES:
            raise ValueError(f"language must be one of {LANGUAGES}")
        return v


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    notify: NotifyCfg = Field(default_factory=NotifyCfg)
    environments: list[Environment]
    base_dir: Path = Path(".")

    def env(self, env_id: str) -> Environment:
        for e in self.environments:
            if e.id == env_id:
                return e
        raise KeyError(env_id)

    def llm_for(self, env: Environment) -> LLMConfig:
        return env.llm or self.llm

    def notify_for(self, env: Environment) -> NotifyCfg:
        return env.notify or self.notify

    def lang_for(self, env: Environment) -> str:
        return env.language if env.language in LANGUAGES else self.app.language


def llm_from_env() -> dict:
    """LLM settings from LLM_* variables (single-environment mode)."""
    E = os.environ.get
    llm: dict = {"provider": E("LLM_PROVIDER", "anthropic"), "model": E("LLM_MODEL", ""),
                 "api_key": E("LLM_API_KEY", ""), "base_url": E("LLM_BASE_URL") or None}
    if E("LLM_MAX_TOKENS"):
        llm["max_tokens"] = int(E("LLM_MAX_TOKENS"))
    temp = E("LLM_TEMPERATURE")
    if temp is not None and temp.strip() != "":
        llm["temperature"] = None if temp.strip().lower() in ("none", "default", "off") else float(temp)
    if E("LLM_TOKEN_PARAM"):
        llm["token_param"] = E("LLM_TOKEN_PARAM")
    extra: dict = {}
    if E("LLM_REASONING_EFFORT"):
        extra["reasoning_effort"] = E("LLM_REASONING_EFFORT")
    if E("LLM_EXTRA_BODY"):
        import json
        extra.update(json.loads(E("LLM_EXTRA_BODY")))
    if extra:
        llm["extra_body"] = extra
    if E("LLM_MAX_RETRIES"):
        llm["max_retries"] = int(E("LLM_MAX_RETRIES"))
    if E("LLM_MAX_TOOL_STEPS"):
        llm["max_tool_steps"] = int(E("LLM_MAX_TOOL_STEPS"))
    return llm


def _env(name: str, default: str | None = None) -> str | None:
    """Environment variable; an empty value counts as unset."""
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def notify_from_env() -> dict:
    """NOTIFY_* / SMTP_* / TELEGRAM_* / TEAMS_* variables (also used when the YAML has no notify block)."""
    E = _env
    return {
        "enabled": _bool(E("NOTIFY_ENABLED"), True),
        "on_run_error": _bool(E("NOTIFY_ON_RUN_ERROR"), False),
        "on_run_summary": _bool(E("NOTIFY_ON_RUN_SUMMARY"), False),
        "on_rule_deploy": _bool(E("NOTIFY_ON_RULE_DEPLOY"), True),
        "on_liveness": _bool(E("NOTIFY_ON_LIVENESS"), True),
        "repeat_hours": int(E("NOTIFY_REPEAT_HOURS", "24")),
        "ui_url": E("NOTIFY_UI_URL", ""),
        "email": {"host": E("SMTP_HOST", ""), "port": int(E("SMTP_PORT", "587")), "security": E("SMTP_SECURITY", "starttls"),
                  "username": E("SMTP_USER", ""), "password": E("SMTP_PASSWORD", ""), "sender": E("SMTP_FROM", ""),
                  "to": [x.strip() for x in E("SMTP_TO", "").split(",") if x.strip()],
                  "verify_tls": _bool(E("SMTP_VERIFY_TLS"), True)},
        "telegram": {"bot_token": E("TELEGRAM_BOT_TOKEN", ""), "chat_id": E("TELEGRAM_CHAT_ID", "")},
        "teams": {"webhook_url": E("TEAMS_WEBHOOK_URL", "")},
        "slack": {"webhook_url": E("SLACK_WEBHOOK_URL", "")},
        "discord": {"webhook_url": E("DISCORD_WEBHOOK_URL", "")},
        "webhook": {"url": E("WEBHOOK_URL", ""), "token": E("WEBHOOK_TOKEN", "")},
        "ntfy": {"topic": E("NTFY_TOPIC", ""), "token": E("NTFY_TOKEN", "")},
    }


def settings_from_env() -> dict:
    """Single-environment configuration from plain environment variables (no YAML needed)."""
    E = os.environ.get
    if not E("WAZUH_INDEXER_URL"):
        raise FileNotFoundError("no config file and WAZUH_INDEXER_URL is not set")
    verify = _bool(E("WAZUH_VERIFY_TLS"), True)
    env: dict = {
        "id": E("WAZUH_ENV_ID", "default"), "name": E("WAZUH_ENV_NAME", "Wazuh"),
        "indexer": {"url": E("WAZUH_INDEXER_URL"), "username": E("WAZUH_INDEXER_USER", ""),
                    "password": E("WAZUH_INDEXER_PASSWORD", ""), "verify_tls": verify, "ca_file": E("WAZUH_CA_FILE") or None},
        "schedule": {"enabled": _bool(E("SCHEDULE_ENABLED"), True), "time": E("SCHEDULE_TIME", "07:30").split(",")[0],
                     "times": [x.strip() for x in E("SCHEDULE_TIME", "").split(",") if x.strip()] if "," in E("SCHEDULE_TIME", "") else [],
                     "days": [d for d in E("SCHEDULE_DAYS", "mon,tue,wed,thu,fri").split(",") if d]},
        "high_level": int(E("HIGH_LEVEL", "7")),
        "window_min_hours": int(E("WINDOW_MIN_HOURS", "24")),
        "redact": _bool(E("REDACT"), False),
    }
    if E("WAZUH_API_URL"):
        env["api"] = {"url": E("WAZUH_API_URL"), "username": E("WAZUH_API_USER", ""),
                      "password": E("WAZUH_API_PASSWORD", ""), "verify_tls": verify, "ca_file": E("WAZUH_CA_FILE") or None}
    if E("WAZUH_ALERTS_INDEX"):
        env["alerts_index"] = E("WAZUH_ALERTS_INDEX")
    if E("LIVENESS_INTERVAL_MINUTES") or E("LIVENESS_ENABLED"):
        env["liveness"] = {"enabled": _bool(E("LIVENESS_ENABLED"), True),
                           "interval_minutes": int(E("LIVENESS_INTERVAL_MINUTES") or 10)}
    if E("MAIL_MAX_PER_HOUR"):
        env["mail"] = {"alert_level": int(E("MAIL_ALERT_LEVEL") or 7), "max_per_hour": int(E("MAIL_MAX_PER_HOUR"))}
    if E("INVENTORY"):
        env["inventory"] = [x.strip() for x in E("INVENTORY", "").split(",") if x.strip()]
    if _bool(E("RULE_DEPLOY_ENABLED"), False):
        env["rule_deploy"] = {"enabled": True, "username": E("WAZUH_DEPLOY_USER", ""),
                              "password": E("WAZUH_DEPLOY_PASSWORD", ""),
                              "file": E("RULE_DEPLOY_FILE") or "wdt_rules.xml",
                              "id_min": int(E("RULE_DEPLOY_ID_MIN") or 100000),
                              "id_max": int(E("RULE_DEPLOY_ID_MAX") or 119999),
                              "require_tests": _bool(E("RULE_DEPLOY_REQUIRE_TESTS"), False),
                              "allow_inconclusive": _bool(E("RULE_DEPLOY_ALLOW_INCONCLUSIVE"), False)}
    return {
        "app": {"timezone": E("TZ", "UTC"), "language": E("APP_LANGUAGE", "en")},
        "llm": llm_from_env(),
        "notify": notify_from_env(),
        "environments": [env],
    }


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    path = Path(path or os.environ.get("WDT_CONFIG", "config/environments.yaml"))
    if path.exists():
        raw = _expand(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        if "llm" not in raw:  # no llm block → LLM_* variables
            raw["llm"] = llm_from_env()
        if "notify" not in raw:  # no notify block → NOTIFY_*/SMTP_*/TELEGRAM_*/TEAMS_*
            raw["notify"] = notify_from_env()
        base = path.parent
    else:
        raw = settings_from_env()
        base = path.parent if path.parent.exists() else Path(".")
    s = Settings(**raw, base_dir=base)
    ids = [e.id for e in s.environments]
    if len(ids) != len(set(ids)):
        raise ValueError("environment ids must be unique")
    if not ids:
        raise ValueError("no environments configured")
    return s
