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

import yaml
from pydantic import BaseModel, Field, field_validator

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
LANGUAGES = ("en", "tr")


def _expand(value):
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
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


class Schedule(BaseModel):
    enabled: bool = True
    time: str = "07:30"  # HH:MM in app.timezone
    days: list[str] = Field(default_factory=lambda: list(DAYS))

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
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
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
    # Window: since the last successful run, clamped to [min, max] hours
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

    @field_validator("language")
    @classmethod
    def _lang(cls, v):
        if v not in LANGUAGES:
            raise ValueError(f"language must be one of {LANGUAGES}")
        return v


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    environments: list[Environment]
    base_dir: Path = Path(".")

    def env(self, env_id: str) -> Environment:
        for e in self.environments:
            if e.id == env_id:
                return e
        raise KeyError(env_id)

    def llm_for(self, env: Environment) -> LLMConfig:
        return env.llm or self.llm

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
    if E("LLM_MAX_TOOL_STEPS"):
        llm["max_tool_steps"] = int(E("LLM_MAX_TOOL_STEPS"))
    return llm


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
        "schedule": {"enabled": _bool(E("SCHEDULE_ENABLED"), True), "time": E("SCHEDULE_TIME", "07:30"),
                     "days": [d for d in E("SCHEDULE_DAYS", "mon,tue,wed,thu,fri").split(",") if d]},
        "high_level": int(E("HIGH_LEVEL", "7")),
        "redact": _bool(E("REDACT"), False),
    }
    if E("WAZUH_API_URL"):
        env["api"] = {"url": E("WAZUH_API_URL"), "username": E("WAZUH_API_USER", ""),
                      "password": E("WAZUH_API_PASSWORD", ""), "verify_tls": verify, "ca_file": E("WAZUH_CA_FILE") or None}
    if E("WAZUH_ALERTS_INDEX"):
        env["alerts_index"] = E("WAZUH_ALERTS_INDEX")
    return {
        "app": {"timezone": E("TZ", "UTC"), "language": E("APP_LANGUAGE", "en")},
        "llm": llm_from_env(),
        "environments": [env],
    }


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    path = Path(path or os.environ.get("WDT_CONFIG", "config/environments.yaml"))
    if path.exists():
        raw = _expand(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        raw.setdefault("llm", llm_from_env())  # no llm block → LLM_* variables
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
