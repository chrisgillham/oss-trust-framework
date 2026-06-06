# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ Active support |
| 0.1.x | ❌ No longer supported — upgrade to 0.2.x |

---

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

### Contact

Send vulnerability reports to:

**Chris Gillham**
📧 [chris@gillham.net](mailto:chris@gillham.net)

Please use the subject line: `[SECURITY] oss-trust-framework — <brief description>`

### GitHub Security Advisories (preferred)

You can also report privately through GitHub's built-in advisory system:

1. Go to the [Security Advisories](https://github.com/chrisgillham/oss-trust-framework/security/advisories/new) tab
2. Click **New draft security advisory**
3. Fill in the details — this keeps the report private until a fix is ready

---

## What to include in your report

To help triage and reproduce the issue as quickly as possible, please include:

- **Description** — a clear explanation of the vulnerability
- **Component** — which gate, module, or workflow file is affected (e.g. `oss_trust_framework/zeroday/validator.py`, `.github/workflows/dep-trust-check.yml`)
- **Impact** — what an attacker could achieve by exploiting it
- **Reproduction steps** — a minimal, reproducible example or proof of concept
- **Environment** — Python version, OS, framework version (`oss-trust --version`)
- **Suggested fix** — if you have one (optional but appreciated)

---

## Response timeline

| Milestone | Target |
|---|---|
| Acknowledgement of report | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix development begins | Within 10 business days for Critical/High |
| Patch release | Coordinated with reporter |
| Public disclosure | After patch is available (typically 90 days max) |

Response times may vary for lower-severity issues. We will keep you informed of progress throughout.

---

## Severity classification

We use CVSS 3.1 to assess severity. The following table maps severity to response priority:

| Severity | CVSS Score | Response priority |
|---|---|---|
| Critical | 9.0–10.0 | Immediate — fix before next release |
| High | 7.0–8.9 | High priority — fix in next patch |
| Medium | 4.0–6.9 | Scheduled — fix in next minor release |
| Low | 0.1–3.9 | Tracked — fix as capacity allows |

---

## Scope

### In scope

The following are considered valid security vulnerabilities:

- **Gate bypass vulnerabilities** — any input or code path that allows a malicious package to pass a gate it should fail
- **Zero-day lane abuse** — weaknesses in CVE validation, quorum enforcement, MFA verification, or token TTL that allow the expedited lane to be triggered without legitimate authorization
- **Code injection in CI/CD workflows** — user-controlled input interpolated into `run:` or `script:` blocks (see CWE-94)
- **Quorum approval weaknesses** — separation of duties bypass, duplicate vote acceptance, self-approval, or approver impersonation
- **Behavioral pattern evasion** — techniques that allow IronWorm/Miasma-class malware to execute during sandbox evaluation without triggering named patterns
- **Provenance attestation bypass** — weaknesses in publisher repo allowlist verification or attestation parsing
- **Dependency vulnerabilities** — known CVEs in framework dependencies that affect the security posture of the pipeline

### Out of scope

The following are not considered security vulnerabilities for this project:

- Behavioral patterns that don't fire against novel, previously unknown malware families (the framework covers named, confirmed attack families)
- Rate limiting or denial of service against external APIs (OSV, OpenSSF, PyPI) that the framework queries — these are third-party services
- Stub gate implementations (`sbom/differ.py`, `sandbox/runner.py`, `signature/gpg.py`) — these are explicitly documented as unimplemented
- Security issues in packages the framework evaluates — report those to the relevant package maintainer
- Social engineering of quorum approvers — the framework's controls are technical, not procedural
- Vulnerabilities requiring physical access to the runner environment

---

## Coordinated disclosure

We follow the principle of coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm receipt and begin investigation
3. We develop and test a fix
4. We coordinate a disclosure date with the reporter (maximum 90 days from initial report)
5. We release the fix and publish a GitHub Security Advisory
6. Reporter may publish their own writeup after the fix is public

If we are unable to produce a fix within 90 days, we will notify the reporter and coordinate a disclosure timeline that minimizes risk to users.

---

## Security design principles

The OSS Trust Framework is built on the following security principles, which inform how we assess vulnerabilities:

**No single point of failure.** Defeating the framework requires compromising multiple architecturally independent systems (NVD, OSV, OpenSSF Scorecard, the npm attestation registry, and the gVisor sandbox) simultaneously. Vulnerabilities that reduce this to a single-system compromise are treated as Critical.

**Gate bypass is always Critical.** Any vulnerability that allows a malicious package to reach a production environment without triggering the appropriate gate outcome is the highest-priority class of vulnerability in this project.

**Zero-day lane integrity is Critical.** The expedited lane's separation of duties (requester cannot approve, MFA required, time-bounded tokens) are the primary controls preventing abuse. Weaknesses here are treated as Critical.

**Audit trail integrity is High.** The framework is designed to be auditable. Any vulnerability that allows gate decisions or exceptions to be made without corresponding SIEM events degrades the audit capability.

**Behavioral pattern evasion is High.** Techniques that allow IronWorm or Miasma-class malware to execute sandbox events without triggering named patterns undermine Gate 5. Novel evasion techniques for known attack families are in scope.

---

## Bug bounty

This is an open-source project maintained without a formal bug bounty program. We do not currently offer monetary rewards for vulnerability reports. We will acknowledge reporters in the relevant GitHub Security Advisory and release notes.

---

## Past advisories

| Advisory | Severity | Affected versions | Fixed in | Summary |
|---|---|---|---|---|
| — | — | — | — | No advisories to date |

Security advisories will be published at:
`https://github.com/chrisgillham/oss-trust-framework/security/advisories`

---

## Related security resources

- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [SLSA Supply Chain Security Framework](https://slsa.dev)
- [OpenSSF Scorecard](https://securityscorecards.dev)
- [GitHub Security Advisories documentation](https://docs.github.com/en/code-security/security-advisories)
- [CVE Program](https://www.cve.org)
