# Environment context — example

This file is given to the AI on every run. Keep it short and durable; things that change day to day
belong in the knowledge base (managed from the UI). Any language is fine.

- Architecture: one manager + one indexer, 25 agents (Ubuntu 24.04 servers, 3 Windows workstations).
- Internet-facing services: web01 (nginx behind a CDN), jenkins (customer-triggered builds, accepted risk).
- Team egress / VPN range: 100.64.0.0/10.
- Automatic updates: unattended-upgrades ~06:00 UTC — dpkg events and post-kernel-update vulnerability bursts are normal.
- No notification channel is configured (do not suggest one).
- Active Response is disabled — detection only.
