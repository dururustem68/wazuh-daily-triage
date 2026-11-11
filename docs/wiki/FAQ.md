# FAQ, glossary and known limitations

## Frequently asked questions

**Does it replace Wazuh, or the Wazuh dashboard?**
No. Wazuh collects, decodes and alerts. This tool reads what Wazuh produced, checks that the SIEM itself is
alive, and prepares the daily review for a person. You keep the dashboard for searching.

**Is it a SOAR? Does it respond automatically?**
No. It does not block addresses, isolate hosts or run commands on agents. The only change it can make in Wazuh
is deploying a rule draft that an administrator approved, and that is off by default.

**Can the AI change something in Wazuh on its own?**
No. The model's tools only read. What it suggests is a proposal that waits for a person.

**What is sent to the model provider?**
Your environment description, the knowledge base, the collected summary of the period (counts, groups, sample
log lines) and the results of the model's queries. Personal data and secrets in it are masked first, by default.
IP addresses are kept unless you choose otherwise. See [Privacy](Privacy) and [Security model](Security-Model).

**Can I keep everything inside my network?**
Yes, with a local model behind an OpenAI-compatible endpoint (Ollama, vLLM, LM Studio). The quality of the
report follows the model.

**Does it need its own database?**
No. Reports, the knowledge base, watch events and settings are documents in your Wazuh Indexer. That also means
an index retention rule can delete them: see [Backup](Backup).

**Does it work without the Wazuh API?**
Yes, for alert analysis. Agent and daemon health, rule definitions, logtest and rule deployment need the API.

**How do I keep the model cost under control?**
One or two AI rounds a day, a limit on tool steps per run (`max_tool_steps`), and a model that fits your volume.
The watch, the liveness check, the noise map and the audit report never call the model.

**Which model should I use?**
One with reliable tool calling. Beyond that, measure on your own reviewed days with `python -m app.eval` rather
than trusting a general ranking.

**Can several Wazuh installations share one instance?**
Yes. Each environment has its own connection, schedule, knowledge base, model setting and pseudonyms.

**Can I give colleagues read-only access?**
Yes: with the viewer password, or behind SSO by putting them into a group of `SSO_VIEWER_GROUPS`
([Viewer mode](Viewer-Mode)).

**Can I run two replicas for availability?**
Only with the scheduler disabled on all but one. Otherwise every check runs twice.

**Is it ISO 27001 compliant or certified?**
No such claim is made. The monthly audit report can support an ISMS review as evidence of monitoring activity;
conformity is a property of your organisation's management system, not of a tool.

**Is this project part of Wazuh?**
No. It is independent and not affiliated with Wazuh, Inc. The licence is AGPL-3.0: if you run a modified version
for users over a network, you must offer them its source.

**Where do I ask for help or report a bug?**
[GitHub issues](https://github.com/dururustem68/wazuh-daily-triage/issues). Security problems go privately
through [security advisories](https://github.com/dururustem68/wazuh-daily-triage/security/advisories/new).

## Glossary

| Term | Meaning |
|---|---|
| Environment | one Wazuh installation (Indexer plus optional API) with its own settings |
| Run | one pass of collection and diagnosis for an environment; the result is a report |
| Window | the period a run covers; by default from the end of the last successful run |
| AI round | a scheduled run; it also judges the watch events since the previous round |
| Watch | local rules that check for urgent situations every few minutes without calling a model |
| Liveness check | a check every few minutes that Wazuh itself works: indexer, API, daemons, incoming alerts |
| Health flag | a deterministic finding about the SIEM: silence, indexer state, disk, daemon down, and so on |
| Finding | one issue in a report, with a label, severity, evidence and recommendation |
| Label | the model's classification: real incident, investigate, detection gap, false positive, baseline increase, measurement, expected, correction |
| Verdict | the AI round's judgement of a watch event: real incident, investigate, expected or noise |
| Recommendations inbox | the findings that await a decision, one at a time, without duplicates |
| Knowledge base | what the installation remembers and gives to the model on every run |
| Baseline | a knowledge entry describing known, normal noise |
| Proposal | a knowledge entry suggested by a model; inactive until approved |
| Rule draft | a proposed Wazuh rule, stored in the knowledge base |
| Deploy | writing an approved draft to the manager through the Wazuh API (optional) |
| Live verification | checking that a rule matched real events after it was applied |
| Promotion | moving a deployed draft into your own rules file or repository |
| Storage prefix | the name prefix of the application's indices; default `daily-triage` |
| Masking, pseudonym | replacing personal data by a stable token such as `<email:3f9a…>` before it reaches a model |
| Masking profile | the standard detectors plus your own, managed in Settings |
| Query guard | the limits every model or MCP query must pass: fields, time range, result size |
| MCP | Model Context Protocol; lets your own AI assistant use the read-only tools |
| Viewer | the read-only role (viewer password, or an SSO group in `SSO_VIEWER_GROUPS`) |
| ATT&CK tactic / technique | MITRE's names for an attacker's goal (Credential Access) and method (T1110 Brute Force); Wazuh rules carry them in a `<mitre>` block |
| Audit trail | the append-only, hash-chained file of state changes; not the monthly audit report |

## Known limitations

The list is kept on the [Compatibility](Compatibility) page, under *Known limits*.

*Applies to 0.11.0 · reviewed 2026-11-11*

---

[English](FAQ) · [Türkçe](FAQ-TR)
