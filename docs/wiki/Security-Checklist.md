# Security checklist before production

**For:** the person who signs off the installation. Work through it once before go-live and again after every
change of exposure (new ingress, SSO, rule deployment switched on). Each item says how to check it.

## Secrets and accounts

- [ ] `APP_PASSWORD` is strong and used nowhere else; `APP_SECRET` is random (`openssl rand -hex 32`).
- [ ] No demo or example value is left: the installation was started from `.env.example`, not `.env.demo`,
      and `WDT_DEMO` is not set.
- [ ] `ENVIRONMENT=production` is set, so the startup checks are enforced. The container log shows no
      security warning at start.
- [ ] `VIEWER_PASSWORD`, if used, differs from the admin password.
- [ ] `MCP_TOKEN` and `METRICS_TOKEN`, if used, are long random values kept in a secret store.
- [ ] `PRIVACY_SALT` or `APP_SECRET` is set, so pseudonyms stay stable across restarts.

## Wazuh access

- [ ] The Indexer user is the dedicated `daily-triage` account: read on the alert and vulnerability indices,
      full rights only on `<storage_prefix>-*`. Not `admin`.
- [ ] The Wazuh API user is the dedicated read-only `daily-triage` account. Not `wazuh` or `wazuh-wui`.
- [ ] Both were checked with **Test connections** or `python -m app.check`.
- [ ] `storage_prefix` does not start with `wazuh-` (**Settings → Storage safety** shows this).

## TLS

- [ ] `verify_tls` is on for the Indexer and the API, and `ca_file` points at your CA.
      `WDT_ALLOW_INSECURE_TLS` is not set.
- [ ] The UI is reached through HTTPS only, `COOKIE_SECURE=true`, and the container port is not published on
      a public interface (Compose publishes on `127.0.0.1`).
- [ ] `FORWARDED_ALLOW_IPS` is the proxy's address or range as the container sees it. Never `*`.

## Rule deployment

- [ ] Not needed: `rule_deploy.enabled` is `false` (the default) and no deploy credentials exist.
- [ ] Needed: it uses a **separate** API user (`daily-triage-deploy`) with only the permissions in
      [docs/rule-deployment.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/rule-deployment.md),
      the ID range (`id_min`–`id_max`) is one you reserved for it, and `require_tests: true` is set.
- [ ] The people who may press **Approve and deploy** know that it restarts the manager.

## Access to the UI

- [ ] `AUTH_DISABLED=true` is used **only** behind an SSO proxy that authenticates every request, and the
      application cannot be reached around the proxy (NetworkPolicy or firewall). `TRUSTED_PROXIES` or
      `PROXY_SECRET` is set. See [SSO proxy authentication](SSO-Proxy-Auth).
- [ ] With SSO: `SSO_ADMIN_GROUPS` names the few people who may decide and deploy, everyone else is a viewer or
      refused (`SSO_VIEWER_GROUPS`), and `SSO_DEFAULT_ROLE` is not `admin`. The proxy strips client-supplied group
      headers.
- [ ] With several environments in one installation, `ADMIN_ENVS`, `VIEWER_ENVS` and `MCP_ENVS` are set where
      roles must not see everything.

## Data leaving your network

- [ ] You know which model provider each environment uses and under which terms. Regulated environments use
      a local model or a provider under a data-processing agreement.
- [ ] `privacy.mode` is `mask` (the default since 0.10.1). You pasted a typical log line into
      **Settings → Personal data masking → Preview** and the result is what you expect.
- [ ] You decided on IP addresses: `ips: keep` (default), `public` or `all`.
- [ ] Everyone who receives notifications is allowed to see host names, IP addresses and finding titles.
      Notifications are not masked.
- [ ] MCP: every client that holds the token is one you trust with masked alert data.

## Logs, audit and retention

- [ ] The audit trail is written (`AUDIT_LOG` is not `false`), on a volume that survives a restart, and is
      shipped to central storage. On Kubernetes the default `emptyDir` does not survive the pod.
- [ ] Who may read the audit trail, the container log and the `<storage_prefix>-*` indices is decided. They
      contain real host names, IPs and report content.
- [ ] Retention is decided: `run_retention_days` for reports, your policy for the shipped audit files.
- [ ] No index retention policy deletes the application's indices (**Settings → Storage safety**), and a first
      backup exists. See [Backup](Backup).

## Operations

- [ ] The image is pinned to a version or digest, not `:latest`.
- [ ] One replica only, or `WDT_SCHEDULER=false` on the others.
- [ ] At least one notification channel is configured and **Test notifications** succeeded, so an outage of
      the SIEM reaches a person.
- [ ] Someone is named as owner of the recommendations inbox.

Background for every item: [Security model](Security-Model) ·
[docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md)

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Security-Checklist) · [Türkçe](Security-Checklist-TR)
