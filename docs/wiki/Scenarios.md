# Example scenarios

**For:** new users who want to see how the pieces work together. All data here is invented: host names are
made up and IP addresses come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). Thresholds are the defaults; yours may differ.

## 1. SSH brute force followed by a successful login

**What happens.** `web01` receives failed SSH logins from `203.0.113.45`, then one login from the same address
succeeds.

**The watch** (if switched on) sees a successful login from an address with at least `brute_failures` failed
attempts in the preceding `brute_window_minutes`. This trigger is always critical, so it is sent even in quiet
hours, as "rule-based alert — not reviewed by AI".

**The next AI round** correlates the events, profiles the source address, gives the watch event a verdict and
usually asks: *was this login yours?*

**You** answer the question. "Yes, the new VPN exit" becomes a knowledge-base entry and the same pattern from
that address is context next time. "No" makes it a real incident: create an incident record from the finding.

## 2. An agent stops reporting

**What happens.** The agent on `db02` disconnects at night.

**The watch** announces it after `agent_minutes`; five or more at once is critical. **The daily report** lists
inactive agents and, with an inventory list, expected agents that are missing.

**You** check the server. If the machine was decommissioned, remove the agent in Wazuh or add its name to
`ignore_agents`, so it stops counting against coverage.

## 3. The indexer disk fills up

**What happens.** Disk usage on the indexer node passes the warning threshold.

**The daily report** raises a health flag from `disk_warn_percent` (default 75). **The liveness check**, which
runs every few minutes without the model, notifies at 90 percent, reminds while it lasts and reports recovery.

**You** act before alerts stop being indexed: retention, storage, or the noisiest rules ([noise
map](User-Guide)). The outage, if it comes to one, appears in the monthly audit report.

## 4. A rule ID nobody has seen before

**What happens.** After an agent update, a rule fires that did not fire in the last 14 days.

**The report** lists it under *New rules (first in 14 days)*, and the anomaly check marks rule and agent pairs
that are new. The model looks at it first, because new is where both attacks and misconfigurations show up.

**You** decide: expected after the update (status *Known noise (baseline)*, with what would make it abnormal),
or something to investigate.

## 5. Alert volume jumps

**What happens.** A scanner finds your public web server; alerts multiply.

**The watch** fires the *sudden increase* trigger when an interval has at least `spike_factor` times the
24-hour average and at least `spike_min` alerts. **The report** compares with the previous window and shows
which rules and agents carry the increase.

**You** read the verdict after the AI round. If it is the usual scanner noise, accept the suggestion to mute
that event key or raise the threshold. A suggestion changes nothing until you accept it.

## 6. Teaching it a false positive

**What happens.** Every night a backup job triggers a "multiple authentication failures" rule on `backup01`.
The model reports it as *Investigate*.

**You** open the finding in **Recommendations**, set *Known noise (baseline)* and write: "nightly backup job,
02:00–02:30, service account svc-backup; abnormal if outside that window or from another host".

**Next runs** receive that entry as context. The model no longer reports the nightly burst, and the note tells
it what would still be worth reporting. The watch stops notifying for that rule, except for critical events.

## 7. A rule draft, tested and then proven live

**What happens.** The model proposes a child rule that lowers the nightly backup failures from level 10 to
level 4, limited to `backup01` and the service account.

1. **What would it do?** shows that in 14 days it would have taken over 420 alerts, all from `backup01`, and no
   high-level alert from another host.
2. Because the draft lowers a level, **Approve and deploy** asks you to type the rule ID.
3. The application writes the rule, validates, restarts the manager and runs the two samples: the backup
   failure must match the new rule, a failure from another host must not.
4. A day later **Check live** shows *confirmed live 14×*. Had it shown *not seen*, the rule would be loaded but
   not matching, and the replay numbers would tell you it should have.
5. **Make permanent** gives you the package for your own rules repository.

The full procedure and what happens on failure: [Rule lifecycle](Rule-Lifecycle).

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Scenarios) · [Türkçe](Scenarios-TR)
