# Watch: urgent alerts without the AI

*Since 0.10.0.* Two loops with different jobs:

| | The watch | The AI round |
|---|---|---|
| When | every few minutes (default 5) | once or twice a day, at the times you set |
| How it decides | local rules — **no model is called** | the model reviews the whole period |
| What it does | notifies at once: "rule-based alert — not reviewed by AI" | one verdict per watch event, findings, tuning suggestions |
| Cost | none | one model call per round |

The watch is **off** until an administrator switches it on in **Settings → Watch** (`/e/<env>/settings`).

## What counts as urgent

| Trigger | Fires when | Tune with |
|---|---|---|
| Critical level | an alert at or above `critical_level` (default 12; level 15+ is *critical*) | level |
| Watched rule | any alert of a rule in the list (default: the environment's `watch_rules`) | list |
| Watched group | an alert of a watched group at or above `group_min_level` (default 10) | list, level |
| Active Response | Wazuh executed an automatic action (`rule.groups: active_response`) | — |
| Login after failed attempts | a successful login from a source address with ≥ `brute_failures` failed logins in the `brute_window_minutes` before it — always *critical* | count, window |
| Sudden increase | the alerts of one interval are ≥ `spike_factor` × the 24 h average and ≥ `spike_min` | factor, minimum |
| Agents lost | an agent disconnected for more than `agent_minutes` (`ignore_agents` are skipped; 5 or more at once is *critical*). The first scan after a start only learns the current state | minutes |

## Sorting out

Before anything is sent, an event is dropped from the notification (it is still recorded and still judged
by the AI) when

- its key is in the **mute** list (an exact key, a prefix ending in `*`, or `rule:<id>`),
- its rule is an active **baseline** entry in the knowledge base (never for critical events),
- the same key was announced within `repeat_hours` (default 6) — the count on the existing event goes up.

## Channels and quiet hours

The watch uses the channels you tick, **among those defined in the configuration file**; addresses, tokens
and webhook URLs are never entered in the UI. During quiet hours nothing is sent except — if you leave that
option on — critical events; everything held back goes out as one message when the quiet period ends.

## The AI round

The scheduled run gets every event without a verdict in one request and answers with `event_verdicts`:
`real_incident`, `investigate`, `expected` or `noise`, each with a reason. It may add a suggestion — mute this
event key, or change one threshold. **A suggestion changes nothing**: it appears in Settings → "AI suggestions
for the watch", where an administrator accepts or dismisses it. Accepting is written to the audit trail.

Set the round times in **Settings → AI round** (one or two a day). Empty means: use `schedule` from the
configuration file. Manual runs ("Run now") and incident drafts are not limited.

## Where things are stored

`<prefix>-events` holds the events and verdicts, `<prefix>-settings` the settings document and small state
(scan cursor, known disconnected agents). Events older than 180 days are pruned (`backup.keep_events_days`).

## Trying it out

Switch the watch on with the defaults, leave quiet hours off for a week, and read the verdicts on the Watch
page after each AI round. Accept the mute suggestions that are right; raise a threshold when a trigger fires
daily for something you already know.

See also: [Backup](Backup) · [Configuration](Configuration) · [Features](Features)

---

[English](Watch) · [Türkçe](Watch-TR)
