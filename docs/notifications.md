# Notifications

By default only critical situations are sent — the daily detail stays in the UI. Turn on `on_run_summary` for
a short message after every run.

| Trigger | Setting (default) |
|---|---|
| Critical health flag: SIEM silent, indexer red, manager daemon down, indexer disk ≥ 90 % | `on_critical_flags: true` |
| Finding labelled *real incident* | `on_real_incident: true` |
| Finding with severity *critical* | `on_critical_findings: true` |
| The triage run itself failed | `on_run_error: false` |
| Summary after **every** run: health, alert counts, findings by label, recommendations waiting | `on_run_summary: false` |
| A rule draft was deployed, failed and rolled back, or removed | `on_rule_deploy: true` |
| **Liveness check** (every `liveness.interval_minutes`, default 10): indexer unreachable or red, API unreachable, required daemon down, no alerts for `max_silence_minutes`, indexer disk ≥ 90 %, cluster not running — sent when it starts, repeated every `liveness.repeat_hours` (2) while it lasts, and a "recovered" message at the end | `on_liveness: true` |

The liveness check needs no AI and costs a few small queries. While it is on, the daily runs do not send the same
health flags again. Configure it per environment:

```yaml
    liveness: {enabled: true, interval_minutes: 5, repeat_hours: 2, notify_recovery: true}
    max_silence_minutes: 60        # "SIEM silent" threshold (liveness.silence_minutes overrides it)
```

The same item is not sent again within `repeat_hours` (default 24), so a twice-daily schedule does not repeat
an unresolved problem every 12 hours. Findings you already decided on (inbox) are never sent.

Messages contain the environment name, the flag/finding titles and a link to the report (`ui_url`). Titles can
include host names and IP addresses — choose channels accordingly.

## Configuration

`config/environments.yaml` (global, or per environment under `environments[].notify`):

```yaml
notify:
  ui_url: https://triage.example.internal      # link target in messages
  repeat_hours: 24
  on_run_error: false
  on_run_summary: false       # true: one short message after every run
  on_rule_deploy: true
  email:
    host: smtp.example.org
    port: 587
    security: starttls        # starttls | ssl | none
    username: ${SMTP_USER}
    password: ${SMTP_PASSWORD}
    sender: wazuh-triage@example.org
    to: [secops@example.org]
  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: ${TELEGRAM_CHAT_ID}
  teams:
    webhook_url: ${TEAMS_WEBHOOK_URL}
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
  discord:
    webhook_url: ${DISCORD_WEBHOOK_URL}
  webhook:                    # generic JSON webhook (Zapier, Make, a SOAR/SIEM endpoint…)
    url: ${WEBHOOK_URL}
    token: ${WEBHOOK_TOKEN}   # optional: Authorization: Bearer <token>
    headers: {}               # optional extra headers
  ntfy:
    topic: wazuh-triage       # or a full URL https://ntfy.sh/wazuh-triage
    token: ${NTFY_TOKEN}      # optional
```

Without a `notify:` block the same settings are read from environment variables:
`NOTIFY_UI_URL`, `NOTIFY_REPEAT_HOURS`, `NOTIFY_ON_RUN_ERROR`, `NOTIFY_ON_RUN_SUMMARY`, `NOTIFY_ON_RULE_DEPLOY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`,
`SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` (comma separated), `TELEGRAM_BOT_TOKEN`,
`TELEGRAM_CHAT_ID`, `TEAMS_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, `WEBHOOK_URL`,
`WEBHOOK_TOKEN`, `NTFY_TOPIC`, `NTFY_TOKEN`. A channel is active when its required fields are set.

Use **Test notifications** on the environment page to check every configured channel.

## Channel setup

- **Telegram:** talk to `@BotFather` → `/newbot` → token. Add the bot to a group (or message it), send
  `/start@<your_bot>`, then read the chat id from `https://api.telegram.org/bot<token>/getUpdates` (`chat.id`,
  negative for groups). If the group is quiet, BotFather → `/setprivacy` → Disable and re-add the bot. If you
  already send Wazuh alerts through the Dashboard's *Notifications* plugin, the channel's webhook URL contains the
  token and the monitor's message body contains the chat id.
- **Microsoft Teams:** in the channel → *Workflows* → template **"Post to a channel when a webhook request is
  received"** → copy the URL. (The old Office 365 "Incoming Webhook" connectors are retired.) Messages are sent as
  Adaptive Cards.
- **Slack:** *Your Apps* → create an app → *Incoming Webhooks* → add to a channel → copy the Webhook URL. Messages
  are sent as block-kit sections with a header and a link to the report.
- **Discord:** channel → *Edit* → *Integrations* → *Webhooks* → *New Webhook* → *Copy Webhook URL*. The message body
  is plain text (Discord webhooks do not render markdown links from an arbitrary URL).
- **Generic webhook:** any HTTP(S) endpoint that accepts a JSON body. It receives
  `{"title", "lines", "link", "text"}`; set `token` for a `Bearer` header or `headers` for anything else. Point it at
  Zapier/Make to fan out to services without a dedicated channel.
- **ntfy:** [ntfy.sh](https://ntfy.sh) (self-hostable) push notifications. Set `topic` to a full URL or just the
  topic name; the message title becomes the notification title and `link` becomes the tap action. Add `token` for a
  protected topic.
- **E-mail:** any SMTP relay. Port 587 + `starttls`, or 465 + `ssl`; `security: none` only on a trusted internal
  relay.
