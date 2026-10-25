# Contributing

Thanks for helping! Issues and pull requests are welcome.

## Ground rules

- **Read-only towards Wazuh.** Features that change Wazuh (active response, rule deployment, agent commands)
  belong in a separate, explicitly privileged component — please open an issue to discuss first.
- **Never commit real data.** Use documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
  2001:db8::/32) and invented host names in tests, demo data and examples.
- **Deterministic first.** If something can be computed with a query, do it in `collector.py`; the LLM should
  interpret, not count.
- Keep dependencies minimal (no provider SDKs, no front-end build step).

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
ruff check .
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

`app/demo.py` provides synthetic alerts and a small OpenSearch query engine. If you add a query feature the
demo engine does not support, extend it and add a test.

## Translations

UI strings live in `app/i18n.py`. Add a new dictionary with exactly the same keys (a test enforces this), add
it to `CATALOG`, `LANG_NAMES` and `OUTPUT_LANGUAGE`, and add the code to `LANGUAGES` in `app/config.py`.

## Pull requests

- One topic per PR, with tests.
- New source files start with:
  ```
  # SPDX-License-Identifier: AGPL-3.0-only
  # Copyright (C) 2026 <your name>
  ```
- By contributing you agree that your contribution is licensed under AGPL-3.0-only. Sign off your commits
  (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
