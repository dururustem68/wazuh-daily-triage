# Personal data (GDPR / KVKK)

Two independent features, configured per environment under `privacy:`.

```yaml
environments:
  - id: prod
    privacy:
      mode: mask          # off (default) | mask
      ips: keep           # keep (default) | public | all
      kinds: []           # empty = all detectors; or e.g. [email, password, national_id_tr, iban, card]
      allow: ['noreply@example\.com', 'svc-.*@example\.com']   # never masked / reported
      detect: true        # default
      detect_sample: 1000 # alerts scanned per run (0 = off), max 5000
```

Variable-only deployments: `PRIVACY_MODE=mask`, `PRIVACY_IPS=public`, `PRIVACY_DETECT=false`. The old
`redact: true` / `REDACT=true` still work and mean `mode: mask`.

## 1. Masking at the LLM boundary (`mode: mask`)

Everything the model receives passes through one masker: the system prompt (context, knowledge base), the
collected summary of the window and every tool result. Before the request leaves the application:

| Kind | Example in | Sent to the model | Check |
|---|---|---|---|
| `email` | `betul@example.com` | `<email:3f9a1c2b>` | — |
| `phone` | `+90 532 123 45 67`, `0532 123 45 67` | `<phone:…>` | 10–15 digits |
| `national_id_tr` | TCKN | `<national_id_tr:…>` | both check digits |
| `national_id_be` | `85.07.30-033.28` | `<national_id_be:…>` | mod 97 |
| `national_id_fr` | NIR | `<national_id_fr:…>` | key = 97 − n mod 97 |
| `iban` | `TR33 0006 …` | `<iban:…>` | mod 97 |
| `card` | `4539 1488 0343 6467` | `<card:…>` | Luhn + issuer prefix |
| `ip` (only with `ips: public/all`) | `203.0.113.7` | `<ip:…>` | `public` keeps private ranges |
| `password`, `bearer`, `jwt`, `aws_key`, `private_key` | `password=…`, `Bearer …` | `<password>` … | removed, **irreversible** |

- **Pseudonyms are stable**: the same value always gets the same token (HMAC with `APP_SECRET`), so the model can
  still see that the same person logged in from five countries — without seeing who.
- **They are reversible inside the application only.** When the model calls a tool with a pseudonym
  (`search_alerts user=<email:3f9a1c2b>`), the application substitutes the real value before querying Wazuh, and
  the model's answer is mapped back before it is stored. Reports, the inbox and incident drafts show real values
  to the reviewer; the model never received them.
- **MCP**: an external assistant is an LLM too. MCP results are masked the same way, and pseudonyms passed back as
  arguments resolve (within the life of the process).
- IP addresses are personal data under GDPR, but most of the analysis is about them; the default keeps them. Use
  `ips: public` to pseudonymise public addresses while keeping internal ones readable.
- Run ids, timestamps, epoch values, versions and ports are not touched: numbers glued to identifiers are skipped
  and every number kind needs a valid check digit.

What it is **not**: a DLP product. Free-text names ("Betül Eser") and usernames that are not e-mail addresses
are not detected. Combine it with a provider under a data-processing agreement, or a local model, for regulated
data.

## 2. Detection in the logs (`detect: true`)

Every run scans a sample of the window's alerts — the newest `detect_sample` plus five from each of the 40
busiest log locations — for the same kinds (validated) in `full_log`, `data.*` and `rule.description`. Only
counts and fully masked examples are kept.

- The flag `personal_data` (warning for secrets, national IDs, IBANs and cards; info for e-mail/phone) names the
  top sources.
- The report section `personal_data` lists rule × agent × location, the kinds found and a masked example.
  `in_rule_description: true` marks rules whose `<description>` copies the value (`$(field)`), so it lands in
  every index, mail and dashboard.
- The model is instructed to turn real leaks into a finding with the fix at the source (mask in the application,
  drop the field in the shipper, a decoder/rule change, retention of what is already indexed), citing GDPR
  Art. 5(1)(c) and 32 / KVKK Art. 12. E-mail addresses in authentication logs are usually legitimate and are
  reported only when they appear where they should not (URLs, query strings, payloads).

Tune false positives with `allow` (regex on the value) or `kinds`.
