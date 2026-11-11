# Development and contributing

**For:** contributors. The binding rules are in
[CONTRIBUTING.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CONTRIBUTING.md); the module map
and request flow are in
[docs/architecture.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/architecture.md).

## Ground rules

- **Read-only towards Wazuh.** A feature that changes Wazuh belongs in a separate, explicitly privileged
  component. Open an issue first.
- **Never commit real data.** Use the documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`) and invented host names in tests, demo data, examples and screenshots.
- **Deterministic first.** What a query can compute belongs in the collector. The model interprets; it does not
  count.
- **Few dependencies.** No provider SDKs, no front-end build step.

## Local setup

```sh
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. The demo mode needs no Wazuh and no model. The application does not read `.env`
by itself; export variables in the shell. Python 3.11 or newer.

## Tests and checks

What CI runs on every push, for Python 3.11, 3.12, 3.13 and 3.15:

```sh
ruff check .
pytest -q --cov=app --cov-report=term-missing
mypy
```

CI also audits the dependencies (`pip-audit`), lints and renders the Helm chart, and installs it into a kind
cluster. A pull request should pass the three commands above locally first.

## How the demo engine is used

`app/demo.py` contains a small OpenSearch query engine, a fake Wazuh API and a mock model, with synthetic
alerts. The test suite and the demo both run on it, so neither needs a cluster. If your change uses a query
feature the demo engine does not support, extend the engine and add a test. `app/demo_seed.py` provides the
sample report, watch events and settings the demo starts with.

## Evaluating a prompt or model change

Tests show that the code works; they do not show that the diagnosis is good. For changes to prompts, tools or
model handling, run the evaluation on cases with known answers:

```sh
python -m app.eval config/eval/demo.yaml
python -m app.eval cases.yaml --repeat 3 --out results.json
```

It reports recall, missed items, noise reported as incidents, tool steps, tokens and time per case
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)). CI does not run it:
it needs a model and your data.

## Adding things

| To add | Where |
|---|---|
| A tool for the model | a handler and a spec in `app/agent/tools.py`; new fields go to the allow-list in `app/query_guard.py`. MCP exposes it automatically. It must be read-only |
| A data source | a client in `app/sources.py`, registered on the environment runtime, exposed through a tool |
| A notification channel | configuration and a sender in `app/notify.py` ([docs/notifications.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/notifications.md)) |
| A model provider | most providers work through the OpenAI-compatible client; a different wire format is a new client in `app/llm/` |
| A watch trigger | `app/watch.py`; it must decide locally, without a model call |

### A new UI language

UI strings are dictionaries in `app/i18n.py` and `app/i18n_v10.py`. Add a dictionary with exactly the same keys
(a test enforces this), register it in `CATALOG`, `LANG_NAMES` and `OUTPUT_LANGUAGE`, and add the code to
`LANGUAGES` in `app/config.py`. The report language follows the environment's `language`.

## Pull requests

- One topic per pull request, with tests.
- New source files start with the SPDX header:
  ```
  # SPDX-License-Identifier: AGPL-3.0-only
  # Copyright (C) 2026 <your name>
  ```
- Sign off your commits (`git commit -s`). Contributions are licensed under AGPL-3.0-only.
- Security problems are reported privately, not as an issue or pull request.

## Documentation

- The wiki source is `docs/wiki/` in the main repository; the wiki repository is a copy. Edit there and sync
  ([docs/wiki/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/wiki/README.md)).
- Every page has an English and a Turkish version and is listed in `_Sidebar.md`.
- A page states who it is for, gives commands that were run against the stated version, and ends with the
  version and review date.
- Write "tested", "expected" and "not supported" with the meanings on the [Compatibility](Compatibility) page.
- Dangerous operations state their effect, prerequisite, confirmation and rollback.
- Screenshots come from the demo, never from a real environment.

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](Development) · [Türkçe](Development-TR)
