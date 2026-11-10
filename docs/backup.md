# Backup, restore and index retention

Everything the application knows — knowledge base, decisions, reports, watch events, settings — lives in
`<storage_prefix>-*` indices of **your** Wazuh indexer. There is no other database. That keeps the
installation simple, and it means an index retention rule can delete the application's memory without any error.

## Is my data safe from the cluster's retention rules?

**Settings → Storage safety** checks this on every installation, read-only:

1. **Prefix.** A `storage_prefix` that starts with `wazuh-` falls under Wazuh's own index patterns
   (`wazuh-*`); retention rules written for Wazuh indices then apply to the application's data. The default
   `daily-triage` is safe. A warning is also logged at startup.
2. **Policy.** For each index: is an Index State Management policy attached, does it contain a `delete`
   action, and on which date would that happen. A policy with the index pattern `*` catches these indices
   too. If the indexer user may not read ISM (`cluster:admin/opendistro/ism/*`), the result is
   *could not be checked* — never "no policy".
3. **Loss.** A missing index is **not** recreated quietly. The application creates it (it needs it to
   work), records the loss, raises the critical flag `storage_lost`, shows a banner on every page and sends
   a notification. The banner stays until an administrator restores a backup or acknowledges the loss.
   On a brand-new installation one notification says that the indices were created.
4. **Reminder.** When the last export is older than `remind_days` (default 30; counted from installation
   when there never was one), each run carries an informational flag and a notification is sent at most
   once a week.

To exclude the indices from a catch-all policy, give that policy a narrower `ism_template.index_patterns`
(for example `wazuh-alerts-*`, `wazuh-archives-*`) or remove the policy from the application's indices:

```
POST _plugins/_ism/remove/daily-triage-*
```

## Export

**Settings → Backup → Create and download.** You choose a passphrase (at least 12 characters); the
archive (`wdt-<env>-<time>.wdtbak`) is compressed and encrypted with scrypt + AES-256-GCM. Without the
passphrase it cannot be opened, and a damaged or modified file is refused. The archive contains no
credentials. The route needs the `admin` permission and every export is written to the audit trail.

### S3

Define a bucket in the configuration (never in the UI) and the export form offers "also send to S3":

| Variable | Meaning |
|---|---|
| `BACKUP_S3_ENDPOINT` | `https://s3.eu-central-1.amazonaws.com`, a MinIO/Ceph/Hetzner endpoint … |
| `BACKUP_S3_BUCKET`, `BACKUP_S3_REGION` | bucket and region (`us-east-1` when the provider has none) |
| `BACKUP_S3_ACCESS_KEY`, `BACKUP_S3_SECRET_KEY` | a key that may only `PutObject` into that bucket |
| `BACKUP_S3_PREFIX` | key prefix, default `wazuh-daily-triage` |
| `BACKUP_S3_PATH_STYLE` | `true` (default) for `https://host/bucket/key`, `false` for `https://bucket.host/key` |
| `BACKUP_PASSPHRASE` | needed only for **automatic** backups |

Automatic backups run when S3 **and** `BACKUP_PASSPHRASE` are configured **and** the switch in Settings →
Backup is on (default every 7 days). Without S3 there are no automatic backups: an archive next to the
data it protects is not a backup.

## Import

Upload the archive, enter the passphrase, **preview**. The preview lists per kind what would be added,
changed or left alone. Then:

- **add what is missing** — existing entries are never touched;
- **overwrite** — entries with the same id are replaced and the settings from the archive are applied.

Imported rule drafts lose their approved/deployed state and must be approved again; an archive is never a
way to put a rule on a manager. An archive of another environment can be imported (the preview says so).
