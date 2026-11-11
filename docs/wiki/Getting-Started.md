# Getting started: from the demo to your first real report

**For:** anyone installing the tool for the first time. **Goal:** a report from your own Wazuh that you have
checked field by field. Allow 10 minutes for the demo and 30–60 minutes for the real connection.

Do the demo first. It shows every page with synthetic data, so later you know what a healthy installation looks
like before your own Wazuh, certificates and accounts are involved.

## Requirements

| What | Demo | Real Wazuh |
|---|---|---|
| Docker with Compose | yes | yes (or Kubernetes: [Kubernetes](Kubernetes)) |
| Wazuh Indexer reachable on 9200 | – | yes |
| Wazuh server API reachable on 55000 | – | optional; without it there is no agent/daemon health, rule info or logtest |
| A model with tool (function) calling | – (`mock`) | yes: hosted or local |
| The Wazuh root CA file | – | yes, unless the certificates are publicly trusted |

## Step 1 — Start the demo

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git
cd wazuh-daily-triage
cp .env.demo .env
docker compose up -d --build
```

**Expected:** `docker compose ps` lists `wazuh-daily-triage` as running, and after about half a minute as
healthy. `curl -fsS http://127.0.0.1:8080/healthz` answers with HTTP 200.

**If not:** `docker compose logs triage` shows the reason. The usual one is a `.env` copied from `.env.example`
with `WDT_DEMO=true` added above another `WDT_DEMO=` line; the last line wins. Use `.env.demo` as it is.

## Step 2 — Sign in

Open <http://127.0.0.1:8080> and sign in with `demo-password-change-me` (the `APP_PASSWORD` in `.env.demo`).

**Expected:** the **Watch board** dashboard: key figures with trend lines, the alert volume chart, the ATT&CK
tactic strip and the work queue with a finished report, open questions and waiting
recommendations.

**If not:** a login that returns to the login page means `COOKIE_SECURE=true` over plain HTTP. `.env.demo` sets
it to `false`; check that you did not change it.

## Step 3 — Start a run on the demo data

Press **Run check now** on the dashboard (top right) or on the environment's **Reports** page in the sidebar.

**Expected:** the button shows *Running…*, then *Done — open report*. The demo uses the `mock` provider: it
writes a placeholder report without calling a model, so the run takes seconds and costs nothing.

## Step 4 — Read the report and the inbox

1. Open the report. Top to bottom: summary, infrastructure, findings, questions from the assistant, then the
   **Data** section marked *deterministic queries — independent of the AI*.
2. Open **Recommendations**. Decide one finding, answer one question.
3. Open **Knowledge base** and confirm that your answer is stored there.

Each of these pages is explained in the [User guide](User-Guide). To see a real model on the same synthetic
data, set the `LLM_*` variables in `.env` and run `docker compose up -d` again.

## Step 5 — Create the read-only Wazuh accounts

Do not use admin credentials. Create the two accounts with the commands in
[docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md):

| Account | Where | May |
|---|---|---|
| `daily-triage` | Indexer | read `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`; everything on `daily-triage-*` (its own data) |
| `daily-triage` | Wazuh API (optional) | read agents, manager status, cluster status, rule files; run logtest |

**Expected:** the verification at the end of the Indexer block returns a count:

```sh
curl -sS --cacert root-ca.pem -u 'daily-triage:PASSWORD' "https://<indexer>:9200/wazuh-alerts-*/_count"
```

**If not:** `401` is a wrong password or a missing role mapping. `403` is a missing index permission. On
wazuh-docker and wazuh-kubernetes, users created through the REST API can be overwritten when `securityadmin`
reloads the YAML files; add them there as well (the permissions document explains how).

## Step 6 — Point the installation at your Wazuh and test the connections

Stop the demo configuration and start from the example file:

```sh
cp .env.example .env
openssl rand -hex 32          # use the output as APP_SECRET
mkdir -p config/certs
cp /path/to/root-ca.pem config/certs/root-ca.pem
vi .env
```

The minimal `.env` for one environment is in [Installation](Installation) (section A2); every variable is in
[Configuration](Configuration). Then:

```sh
docker compose up -d
docker compose exec triage python -m app.check
```

`python -m app.check` tests the Indexer (alerts, vulnerabilities, the application's own indices), the Wazuh API,
any extra sources and the model, without starting a run. `--no-llm` skips the model call. The same test is the
**Test connections** button on the environment's **Reports** page.

**Expected:** every check passes. Fix what does not before you continue: a run on a half-working connection
produces a report with blind spots.

**If not:** see [Troubleshooting](Troubleshooting). The frequent causes are the CA file (path inside the
container is `/app/config/certs/…`), an API password that does not meet the Wazuh password policy, and a
container that refuses to start in production mode. The log line names the variable.

## Step 7 — First real run

Press **Run check now**. With no earlier report the window is the configured minimum (`window_min_hours`);
from the second run on it is "since the last successful run".

**Expected:** a report within a few minutes. The duration depends on the model and on `max_tool_steps`.

## Step 8 — Check the report before you trust it

| Look at | It should show | If it does not |
|---|---|---|
| Window | the period you expected | a failed earlier run does not move the window; the next one starts from the last successful run |
| Infrastructure | indexer status, disk, agents, daemons | empty agent and daemon fields mean the Wazuh API is not configured or not permitted |
| Level distribution, most frequent rules | numbers that match your Wazuh dashboard for the same period | check `alerts_index` and the timezone (`TZ`) |
| Collection errors (blind spots) | absent | each entry is a query that failed; the section it belongs to is empty, not "all clear" |
| Findings | each with evidence and a label | a report that only lists health flags means the model failed; the summary says so |
| AI tool calls | a number above zero | zero calls usually means the model does not support tool calling |

Then do the same three things as in the demo: decide a finding, answer a question, and find both in the
knowledge base. The next run reads them.

## Next

- Before it goes to production: [Security checklist](Security-Checklist).
- What is sent to the model, and what is not: [Privacy](Privacy), [Security model](Security-Model).
- Urgent alerts between AI rounds: [Watch](Watch).
- More than one Wazuh: [Installation](Installation) (A3) and [Configuration](Configuration).

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Getting-Started) · [Türkçe](Getting-Started-TR)
