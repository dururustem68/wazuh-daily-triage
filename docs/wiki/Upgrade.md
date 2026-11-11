# Upgrade and rollback

**For:** operators. The steps below are the **recommended operating procedure**. The application has no
built-in upgrade or downgrade command: an upgrade is a new image with the same configuration and the same data.

## What an upgrade touches

| | Where it lives | Changed by an upgrade? |
|---|---|---|
| The application | the container image | yes: that is the upgrade |
| Configuration | `.env`, `config/environments.yaml`, or Helm values | only if the release notes say a key changed |
| Reports, knowledge base, watch events, settings | `<storage_prefix>-*` indices in your Wazuh Indexer | no migration step; a new version may add an index |
| Audit trail | the `audit` volume or your log shipping | no |

Because the state is in the Indexer, replacing the container loses nothing. The risk in an upgrade is a changed
default or a new requirement, which is why the release notes come first.

## Before you upgrade

1. Read [CHANGELOG.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CHANGELOG.md) from your
   version to the target, including the version notes below.
2. Note the running version (the **About** page) and the image tag or digest in use.
3. Take a backup: **Settings → Backup → Create and download**, and store the passphrase where you will find it.
   The backup is your way back if a new version writes something an old one cannot read. See [Backup](Backup).
4. Make sure no run is active.

## Upgrade

Pin versions. With `:latest` you cannot say what you are running or go back to it.

```sh
# Docker Compose: set the image tag in docker-compose.yml, then
docker compose pull
docker compose up -d
docker compose exec triage python -m app.check
```

```sh
# Helm
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --version <chart version> -f my-values.yaml
```

For Kustomize, change the `?ref=` of the remote base and the image tag in your overlay, then `kubectl apply -k .`.

## After the upgrade

- The container log shows the environments and the schedule, and no new security warning.
- `python -m app.check` passes.
- **Settings → Storage safety** is OK.
- Start one run and open the report.
- The older reports and the knowledge base are still there.

## Rollback

Deploy the previous image tag or digest with the previous configuration:

```sh
# Helm
helm -n wazuh-daily-triage history wazuh-daily-triage
helm -n wazuh-daily-triage rollback wazuh-daily-triage <revision>
```

With Compose, set the previous tag and run `docker compose up -d`.

**Limits of a rollback.** The project does not test downgrades. Documents written by the newer version stay in
the indices, and an older version may ignore fields it does not know. Settings that exist only in the newer
version have no effect after a rollback. If the older version misbehaves on the newer data, import the backup
you took before the upgrade.

## Version notes

### 0.11.0

- **SSO roles (action needed behind an SSO proxy).** Before 0.11 every SSO user was an administrator. Now the
  role comes from the proxy's group header: set `SSO_ADMIN_GROUPS` (and optionally `SSO_VIEWER_GROUPS`) and make
  the proxy forward the groups (`X-authentik-groups`, `X-Auth-Request-Groups`). Without it every SSO user is a
  read-only viewer. `SSO_DEFAULT_ROLE=admin` keeps the old behaviour for a transition; startup warns about it.
  Details: [SSO proxy authentication](SSO-Proxy-Auth).
- **New interface.** Sidebar navigation, a dashboard with charts and an ATT&CK page. No configuration needed;
  bookmarks keep working. The dashboard takes `?env=` and `?period=24h|7d|30d`.
- **ATT&CK tags on findings.** New runs store `mitre` and `mitre_tactics` on findings; older reports simply show
  no tags.
- Two more aggregation queries per environment when the dashboard is opened (cached for a minute). The Indexer
  role needs no new permission.

### 0.10.1

- **Personal-data masking is on by default.** An installation without a `privacy:` block now masks. To keep the
  earlier behaviour set `privacy.mode: off` explicitly.
- Docker Compose: the audit trail is in the named volume `audit` (before: `./logs`). Move an existing
  `./logs/audit.jsonl` into the volume if you want to keep it.
- The demo has its own `.env.demo`; `.env.example` no longer sets `WDT_DEMO`.

### 0.10.0

- Two new indices are created at the first start: `<prefix>-events` and `<prefix>-settings`. An Indexer role on
  `<prefix>-*` covers them; a role that names `-runs` and `-knowledge` does not.
- Behaviour does not change until the watch is switched on in **Settings**.
- SSO mode (`AUTH_DISABLED=true`): requests without a user header are answered with `401`. The proxy must
  forward one of the `USER_HEADER` headers.
- Helm: `networkPolicy.enabled` is now `true`; set `networkPolicy.ingressNamespace`.
- A missing storage index is no longer recreated silently; see [Backup](Backup).
- Take a first backup; the reminder counts from the upgrade.

### 0.9.2

- Buttons answer `403` "cross-origin request refused" when the browser's origin is not the host the application
  sees: set `WDT_TRUSTED_ORIGINS`.
- In production mode, state-changing requests answer `503` while the audit trail cannot be written.

Older versions: the changelog.

See also: [Backup](Backup) · [Compatibility](Compatibility) · [Troubleshooting](Troubleshooting)

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Upgrade) · [Türkçe](Upgrade-TR)
