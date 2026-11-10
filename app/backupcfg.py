# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Backup configuration (YAML ``backup:`` block or ``BACKUP_*`` variables). Credentials stay out of the UI."""
from __future__ import annotations

import os

from pydantic import BaseModel


class S3Cfg(BaseModel):
    """An S3-compatible bucket (AWS, MinIO, Hetzner, Ceph …). Configured in YAML / environment only."""
    endpoint: str = ""            # https://s3.eu-central-1.amazonaws.com or https://fsn1.your-objectstorage.com
    bucket: str = ""
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    prefix: str = "wazuh-daily-triage"
    path_style: bool = True
    verify_tls: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.endpoint and self.bucket and self.access_key and self.secret_key)


class BackupCfg(BaseModel):
    passphrase: str = ""          # BACKUP_PASSPHRASE — needed for automatic backups only
    s3: S3Cfg = S3Cfg()
    keep_events_days: int = 180   # watch events older than this are pruned (0 = keep)


def backup_from_env(env=os.environ) -> dict:
    E = env.get
    return {"passphrase": E("BACKUP_PASSPHRASE", ""),
            "s3": {"endpoint": E("BACKUP_S3_ENDPOINT", ""), "bucket": E("BACKUP_S3_BUCKET", ""),
                   "region": E("BACKUP_S3_REGION", "us-east-1"), "access_key": E("BACKUP_S3_ACCESS_KEY", ""),
                   "secret_key": E("BACKUP_S3_SECRET_KEY", ""), "prefix": E("BACKUP_S3_PREFIX", "wazuh-daily-triage"),
                   "path_style": (E("BACKUP_S3_PATH_STYLE", "true").lower() != "false"),
                   "verify_tls": (E("BACKUP_S3_VERIFY_TLS", "true").lower() != "false")}}
