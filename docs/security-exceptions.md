# Security exceptions

Every security control in this project has a documented way to be bypassed, and every bypass is recorded
here (or in the file it belongs to). An exception without an owner and an expiry date is a finding, not a
decision.

## 1. Dependency vulnerabilities (CI gate)

CI runs `pip-audit -r requirements.txt` and **fails on any known vulnerability** in a runtime dependency
(`.github/workflows/ci.yml`, job `dependencies`). A CycloneDX SBOM is uploaded with every run.

An exception is a line in [`.github/pip-audit-ignore.txt`](../.github/pip-audit-ignore.txt):

```text
# id            owner      expires     reason
GHSA-xxxx-xxxx-xxxx  @rustem  2026-12-31  not reachable: only used in the CLI import path
```

Rules:

1. **Prefer upgrading.** An exception is for a vulnerability that has no fix yet, or that provably cannot be
   reached by this application (document *why*, with the code path).
2. **Always set an expiry date.** The reviewer of the next release checks the list; an expired entry must be
   removed or re-justified. Reviewing the file is part of the release checklist.
3. **Never inline `|| true`** on the audit step, and never disable the job.
4. A vulnerability in a **development-only** dependency is still reported in the SBOM but does not gate the
   build; keep it visible and fix it in the next dependency bump.

## 2. Deliberate insecure overrides

These switches exist for labs, air-gapped demos and TLS-terminating proxies. In production they must be a
conscious decision, and `security.check()` reports them at startup.

| Setting | Bypasses | When it is acceptable | Where documented |
|---|---|---|---|
| `WDT_ALLOW_INSECURE_TLS=1` | The production refusal to start with `verify_tls: false` | First connection test against a self-signed cluster, or an internal CA you cannot install yet. Install the CA and remove the flag. | [permissions.md §3](permissions.md), `.env.example` |
| `WDT_ALLOW_INSECURE_COOKIE=1` | The production refusal to start with `COOKIE_SECURE=false` | The app is only reachable over a loopback/VPN interface and TLS is terminated elsewhere, accepting session-cookie exposure on that last hop | `.env.example` |
| `AUTH_DISABLED=true` | The built-in password login | An SSO reverse proxy (Authentik, Keycloak, oauth2-proxy) authenticates every request and the app is **not** reachable directly. Enforce with a NetworkPolicy/firewall rule. | [permissions.md §4](permissions.md) |
| `WDT_DEMO=true` | Real data and real credentials | Never in production — `security.check()` refuses to start with `WDT_DEMO=true` when `ENVIRONMENT=production` | README |
| `AUDIT_LOG=false` | The audit trail | Tests and short-lived demos only. Production startup warns, it does not fail: the operator must know | [permissions.md §5](permissions.md) |
| `rule_deploy.allow_inconclusive: true` | Fail-closed logtest policy | Rules for events logtest cannot reproduce (manager-internal groups), where the samples were verified manually. The deployment record keeps `state: inconclusive` | [rule-deployment.md](rule-deployment.md) |
| `rule_deploy.require_tests: false` (default) | Requiring test samples for every draft | Drafts written by hand without samples. Turning it on is the stricter choice for production | [rule-deployment.md](rule-deployment.md) |

## 3. Accepted risks

| Risk | Mitigation |
|---|---|
| The deploy API user can overwrite **any** custom rules file (`rules:update` cannot be scoped) | Separate account, credentials only in a secret, the application writes only `rule_deploy.file`, every deploy audited |
| Alert content is attacker-controlled (prompt injection) | Read-only tool set, field allow-list and query caps, proposals require human approval, deploys require a typed rule id for silencing rules |
| A hosted LLM receives alert summaries and log samples | `privacy.mode: mask` (pseudonymised at the LLM boundary, [privacy.md](privacy.md)), a local model, or a provider with a data-processing agreement |
| Shared admin login: the audit trail records the role, not the person | Use `AUTH_DISABLED=true` behind an SSO proxy so `actor(request)` carries the proxy user, and correlate with proxy logs |
| The audit file lives on the same volume as the app | Ship it to write-once/central storage; the hash chain makes later modification detectable, not impossible |

## 4. Supply chain

| Control | Where |
|---|---|
| Dependency audit fails on a known vulnerability | `.github/workflows/ci.yml` job `dependencies` |
| SBOM (CycloneDX) of Python dependencies, per CI run | artifact `sbom-python`, 90 days |
| SBOM (SPDX) of the released image | `release.yml` (`anchore/sbom-action`) |
| Image digest and source revision recorded per release | step summary of `release.yml` — pin `ghcr.io/<repo>@sha256:…` in production |
| Static analysis (CodeQL, `security-and-quality`) | `.github/workflows/codeql.yml`, weekly and on every PR |
| Least-privilege workflows | top-level `permissions: contents: read`; write scopes only in the jobs that publish |

Not done yet (tracked in [ROADMAP.md](../ROADMAP.md)): image signing/attestation (cosign/SLSA), a locked
dependency set (constraints file), and container image scanning beyond the SBOM.

## 5. Reporting

Do not open a public issue for a vulnerability — see [SECURITY.md](../SECURITY.md).
