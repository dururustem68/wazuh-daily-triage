# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.2] — 2026-10-26

### Fixed
- LLM calls are retried with backoff on overload / rate-limit / gateway errors (429, 5xx, 529), honouring
  `Retry-After` (`max_retries`, `LLM_MAX_RETRIES`, default 4).
- If the AI provider is still unavailable, the run is saved with the deterministic health flags and data
  instead of failing; open requests are kept for the next run.

## [0.1.1] — 2026-10-26

### Added
- Kubernetes manifests: hardened Kustomize base (single-replica Deployment, Service, optional NetworkPolicy)
  and an example overlay (`deploy/kubernetes`).

## [0.1.0] — 2026-10-25

### Added
- Scheduled and on-demand daily triage per Wazuh environment with deterministic health flags.
- AI diagnosis with read-only tools; Anthropic and OpenAI-compatible providers, per-environment override.
- Reports, knowledge base and chat stored in the environment's own Wazuh Indexer (`daily-triage-*`).
- Questions to the user, finding feedback, AI knowledge proposals with approval.
- Rule draft validation (XML, OS_Regex pitfalls, ID collisions) and logtest.
- Web UI in English and Turkish; connection test in the UI and `python -m app.check`.
- Single-environment configuration from environment variables; mutual TLS; redaction option.
- Demo mode with synthetic data.
- Provider guide for Claude, OpenAI, Gemini, DeepSeek, Azure and local models; `LLM_TEMPERATURE`,
  `LLM_TOKEN_PARAM`, `LLM_REASONING_EFFORT`, `LLM_EXTRA_BODY` variables.
