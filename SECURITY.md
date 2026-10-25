# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository.

Include the affected version, a description, reproduction steps and the impact. You should receive an answer
within 7 days. Please allow a reasonable time for a fix before public disclosure.

## Supported versions

Only the latest release receives security fixes.

## Scope notes

- The application is designed to be **read-only** towards Wazuh. Any way to make it change Wazuh state, read
  indices outside its configured patterns, or exfiltrate credentials is in scope.
- Prompt injection through alert content that leads to an action beyond adding a *proposal* to the knowledge
  base is in scope.
- The UI is meant to run behind TLS on an internal network. Findings that require an attacker to already hold
  the UI password or the `.env` file are generally out of scope.
