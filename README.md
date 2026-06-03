# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — including hardened defenses against CI/CD pipeline compromise attacks (Miasma, Shai-Hulud, TanStack, Bitwarden) and a strictly controlled expedited lane for zero-day CVE patches.

> **v0.2 — Miasma/Shai-Hulud coverage added.** Gate 2.5 (CI/CD Pipeline Audit) and behavioral pattern matching in Gate 5 directly counter the compromised-employee-account + OIDC trusted publishing attack class that backdoored 32 Red Hat npm packages in 2026.

---

## Why This Exists

Two distinct supply chain attack patterns are defeating traditional defenses:

**Pattern 1 — Speed attacks.** A compromised maintainer account publishes a malicious release. Automated dependency tooling ingests it within minutes, before anyone notices. The attacker wins the race.

**Pattern 2 — CI/CD pipeline compromise (Miasma class).** An attacker compromises a legitimate employee's GitHub account, pushes orphan commits bypassing PR review, and exploits `id-token: write` CI/CD permissions to publish backdoored packages via OIDC trusted publishing. The packages are *correctly signed* — the signature is real. Traditional signature verification passes. The attack is invisible to every conventional control.

This framework addresses both patterns with layered, independent gates — most of which cannot be bypassed even by a compromised maintainer or CI/CD pipeline.

---

## Key Benefits

### Stops attacks that valid signatures can't catch
The Miasma class of attacks produces packages with legitimate Sigstore signatures — because the attacker controls a real CI/CD pipeline. Gate 2.5 catches this by auditing *how* the publish happened: was there a PR? Did it go through normal merge? Does the attacker need to compromise *multiple* independent systems simultaneously to defeat it?

### Structural defense — not just better tooling
Each gate queries sources that are architecturally independent of the compromised repository. An attacker controlling a single GitHub account cannot manipulate NVD, OSV, OpenSSF Scorecard, and the npm provenance attestation registry at the same time. Defeating this framework requires compromising multiple independent systems simultaneously.

### Behavior-based sandbox patterns defeat encrypted payloads
Miasma v2 generates a unique encrypted payload per infection, making hash-based IOCs useless across versions. Gate 5 matches on *what the payload does* — accessing IMDS endpoints, requesting OIDC tokens, reading cloud credential files — regardless of how the payload is obfuscated.

### Zero-day patches move fast without moving unsafely
The 72-hour age hold is the highest-ROI control in the framework, but it creates a gap when a legitimate zero-day patch drops. The expedited lane bypasses *only* the age gate, with machine-verified CVE confirmation, 2-of-3 MFA quorum approval, and a 6-hour token TTL. Speed and safety are not in conflict.

### Fully auditable by design
Every gate decision, zero-day exception, and approval event emits a structured SIEM event. Ticket linkage is mandatory for exceptions. Monthly retrospectives are enforced by circuit breaker. The framework is designed to be examined — including by auditors who weren't in the room when decisions were made.

### Drop-in CI/CD integration
The GitHub Actions workflow (`dep-trust-check.yml`) fires automatically on any lock file change, comments gate results on the PR, and fails the build on block or quarantine outcomes. No per-repo configuration needed once the framework is deployed at the org level.

---

## Architecture

```
Dependency update request
        │
        ▼
┌──────────────────────┐   < 24 h, no CVE ──► BLOCKED
│  Gate 1: Age Hold    │
│  24 h hard block     │   Zero-day CVE filed? ──► Expedited Lane ──────────────┐
│  72 h soft hold      │                                                         │
└──────────┬───────────┘                                                         │
           │ ≥ 24 h                                                              │
           ▼                                                                     │
┌──────────────────────┐   Repo mismatch ──► BLOCKED   ◄── Miasma: fork/        │
│  Gate 2: Provenance  │                                    employee acct        │
│  Attestation +       │   No attestation ──► QUARANTINE                        │
│  Publisher Allowlist │   (sourceRepositoryURI vs trusted_publishers.yaml)     │
└──────────┬───────────┘                                                         │
           │                                                                     │
           ▼                                                                     │
┌──────────────────────┐   Orphan commit ──► BLOCKED    ◄── Miasma: direct push │
│  Gate 2.5: CI/CD     │   id-token:write ──► QUARANTINE ◄── Miasma: OIDC abuse │
│  Pipeline Audit      │   No PR review  ──► BLOCKED    ◄── Miasma: no oversight│
│  [2.5a] Orphan commits                                                         │
│  [2.5b] Workflow perms                                                         │
│  [2.5c] PR provenance│                                                         │
└──────────┬───────────┘                                                         │
           │                                            ◄── Rejoins here ────────┘
           ▼
┌──────────────────────┐   Score < threshold ──► QUARANTINE
│  Gate 3: Out-of-Band │   Active CVE ──► QUARANTINE
│  Trust Aggregation   │   (OpenSSF · OSV · deps.dev · GHSA)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐   New transitive dep ──► QUARANTINE
│  Gate 4: SBOM Delta  │   Hash mismatch ──► QUARANTINE
│  + Hash Pin          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐   Cloud cred harvest ──► BLOCKED  ◄── Miasma: IMDS/OIDC
│  Gate 5: Behavioral  │   Registry publish ──► BLOCKED    ◄── Miasma: re-publish
│  Sandbox (gVisor)    │   Other malicious ──► BLOCKED
│  + Miasma Patterns   │
└──────────┬───────────┘
           │
           ▼
    ┌──────────────┐
    │ Staged Rollout│──► APPROVED
    │ 72 h canary  │    (ZD lane: immediate + 48 h alert window)
    └──────────────┘
```

### Zero-Day Expedited Lane

Bypasses the **age gate only**. All other gates remain mandatory.

```
CVE validated (NVD + OSV + GHSA — 2-of-3 independent sources required)
        │
        ▼
Quorum approval (2-of-3 named approvers · MFA required · requester excluded)
        │
        ▼
Provenance attestation + timing check (must postdate CVE publication)
        │
        ▼
CI/CD audit Gates 2.5a–c (mandatory — compromised-account patches are still caught)
        │
        ▼
Behavioral sandbox (gVisor · no network · Miasma patterns active)
        │
        ▼
Audit record (SIEM event + ticket link mandatory before deploy)
        │
        ▼
Immediate full-fleet deploy + 48 h elevated alert window
```

---

## Quickstart

```bash
pip install oss-trust-framework

# Run the full pipeline against a single package
oss-trust check \
  --package requests \
  --version 2.32.3 \
  --ecosystem PyPI \
  --github-repo psf/requests

# Request a zero-day expedited exception
oss-trust zeroday request \
  --cve CVE-2024-XXXXX \
  --package requests \
  --version 2.32.4 \
  --requester security@yourorg.com

# Approve a pending zero-day request (run by each named approver)
oss-trust zeroday approve \
  --request-id abc123def456 \
  --approver-id approver_001 \
  --mfa-token 123456

# Check request status
oss-trust zeroday status --request-id abc123def456
```

---

## Installation

```bash
# From PyPI
pip install oss-trust-framework

# From source
git clone https://github.com/YOUR_ORG/oss-trust-framework
cd oss-trust-framework
pip install -e ".[dev]"
cp .env.example .env
```

---

## Configuration

### Core pipeline settings (`config/pipeline.yaml`)

```yaml
age_gate:
  hard_block_hours: 24      # < 24 h: auto-blocked regardless of source
  hold_hours: 72            # 24–72 h: human approval required

cicd_audit:                 # Gate 2.5 — Miasma/Shai-Hulud controls
  orphan_commits:
    enabled: true
    action_on_orphan: block
  workflow_permissions:
    enabled: true
    action_on_finding: quarantine
  pr_provenance:
    enabled: true
    min_pr_reviewers: 1
    action_on_direct_push: block

sandbox:
  runtime: gvisor
  network: none
  behavioral_patterns:
    enabled: true
    block_on_critical: true # IMDS, OIDC token, credential file reads

zero_day:
  required_approvers: 2
  token_ttl_hours: 6
  circuit_breakers:
    max_exceptions_per_24h: 3
```

### Trusted publisher allowlist (`config/trusted_publishers.yaml`)

Maps package names to their canonical GitHub source repo. A provenance attestation pointing to any other repository is treated as a CRITICAL finding and blocked.

```yaml
npm:
  "express": "expressjs/express"
  "@redhat-cloud-services/frontend-components": "RedHatInsights/frontend-components"

PyPI:
  "requests": "psf/requests"
  "cryptography": "pyca/cryptography"

require_attestation:        # Missing attestation = BLOCK (not just quarantine)
  npm:
    - "@redhat-cloud-services/frontend-components"
```

Populate this file from your actual dependency graph. Any package not listed still passes Gate 2 — it just doesn't get the repo-match verification.

---

## CI/CD Integration

### GitHub Actions — automatic PR gate

The included workflow fires on any lock file change (`package-lock.json`, `requirements*.txt`, `Cargo.lock`, `go.sum`) and comments gate results directly on the PR:

```yaml
- name: Validate dependency update
  uses: YOUR_ORG/oss-trust-framework/.github/actions/validate@main
  with:
    package: ${{ env.PACKAGE_NAME }}
    version: ${{ env.PACKAGE_VERSION }}
    ecosystem: ${{ env.ECOSYSTEM }}
    github-repo: ${{ env.GITHUB_REPO }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

See [`.github/workflows/dep-trust-check.yml`](.github/workflows/dep-trust-check.yml) for the full workflow with PR commenting, artifact upload, and matrix strategy across multiple changed packages.

---

## Gate Reference

| Gate | Controls | Fail action | Bypassable? |
|---|---|---|---|
| **1 — Age** | Release timestamp vs 24 h / 72 h thresholds | Block / Hold | Age only — with CVE + MFA quorum |
| **2 — Provenance** | Sigstore attestation present; `sourceRepositoryURI` matches allowlist | Block (mismatch) · Quarantine (missing) | No |
| **2.5a — Orphan commits** | Release tag commit reachable from default branch via BFS graph walk | Block | No |
| **2.5b — Workflow permissions** | `id-token: write` in publishing workflow without branch protection + CODEOWNERS | Quarantine | No |
| **2.5c — PR provenance** | Release backed by merged PR with ≥ 1 approving reviewer | Block (no PR) · Quarantine (no review) | No |
| **3 — OOB Trust** | OpenSSF Scorecard ≥ threshold; zero active CVEs via OSV + deps.dev + GHSA | Quarantine | No |
| **4 — SBOM delta** | No unexpected transitive deps; lock file hash unchanged | Quarantine | No |
| **5 — Behavioral sandbox** | gVisor install-time execution; 18 named Miasma-class behavioral patterns | Block | No |

---

## Miasma / Shai-Hulud Attack Coverage

The [Miasma attack](https://devops.com/shai-hulud-clone-miasma-compromises-32-red-hat-npm-packages/) (also observed in TanStack and Bitwarden compromises) uses a legitimate CI/CD pipeline as the attack surface. Packages are correctly signed — conventional signature verification passes. The same fundamental pattern was used across all three incidents.

### How the attack works

1. Attacker compromises a legitimate employee's GitHub account
2. Uses it to push orphan commits (no PR, no review, no merge queue)
3. The repository's CI/CD workflow has `id-token: write` permission
4. Workflow requests a short-lived OIDC token from GitHub and uses it to publish directly to npm's trusted publishing endpoint — no stored secret required
5. The published package is signed with a valid Sigstore signature pointing to the real org's CI pipeline
6. Payload harvests GCP/Azure/AWS cloud identities from the host environment
7. Miasma v2 generates a unique encrypted payload per infection — hash-based IOCs are version-specific and useless across deployments

### How each attack step is blocked

| Attack step | Gate | Mechanism |
|---|---|---|
| Orphan commit pushed, bypassing PR | **2.5a** | BFS walk from default branch tip; tag commit not reachable → BLOCK |
| No code review on malicious commit | **2.5c** | Commit→PR API check; no merged PR → BLOCK |
| `id-token: write` exploited for OIDC publish | **2.5b** | Workflow YAML parsed; dangerous perm + no env protection → QUARANTINE |
| Published from employee account, not canonical org | **2** | `sourceRepositoryURI` in attestation checked against `trusted_publishers.yaml` → BLOCK |
| Cloud credential harvesting at runtime | **5** | MIASMA-001/002 patterns: IMDS and GCP metadata requests → BLOCK |
| OIDC token requested from install context | **5** | MIASMA-010: `token.actions.githubusercontent.com` network access → BLOCK |
| Re-publish to npm from install script | **5** | PUBLISH-001: PUT to `registry.npmjs.org` during install → BLOCK |
| Unique encrypted payload defeats hash IOCs | **5** | Behavior-matched, not hash-matched — encryption is irrelevant |

### Why this is structurally hard to defeat

Bypassing this framework requires compromising all of the following simultaneously:

- The package registry's provenance attestation system (Sigstore/npm)
- NVD, OSV, and GitHub Security Advisories (for the zero-day lane)
- OpenSSF Scorecard and deps.dev (for Gate 3)
- The behavioral sandbox runtime (gVisor with no network access)
- The quorum approval process (2-of-3 named individuals with MFA)

No single compromised account, repository, or CI/CD pipeline is sufficient.

---

## Zero-Day Lane Circuit Breakers

The expedited lane automatically suspends under these conditions to prevent abuse or normalization of the bypass path:

| Condition | Action |
|---|---|
| > 3 exception requests in 24 hours | Lane suspended pending CISO review |
| Same requester files two exceptions within 48 hours | Second request escalates to CISO sign-off |
| Any exception-deployed package receives a new CVE within 30 days | Lane suspended; retrospective triggered |
| Monthly retrospective finds process violations | Lane suspended until remediation confirmed |

Exception tokens expire after 6 hours. Re-approval is required after expiry — there is no token extension.

---

## Out-of-Band Trust Sources (Gate 3)

All sources queried independently of the package repository. A compromised repo cannot influence these results.

| Source | API endpoint | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Automated security hygiene score (CI, branch protection, code review, signing) |
| deps.dev (Google) | `api.deps.dev/v3alpha/...` | Dependency graph, version history velocity, known advisories |
| OSV.dev | `api.osv.dev/v1/query` | Cross-ecosystem CVE database — checks if patch version appears in fixed list |
| GitHub Security Advisories | `api.github.com/advisories` | Manually reviewed, high-confidence signal |
| npm Advisory DB | `npm audit` | npm-specific compromise and vulnerability history |

---

## Behavioral Patterns (Gate 5)

18 named patterns covering the Miasma attack profile. Matched by event type, not payload hash — encryption and obfuscation do not defeat pattern matching.

| Pattern ID | Category | Severity | Description |
|---|---|---|---|
| MIASMA-001 | Cloud metadata | CRITICAL | AWS/Azure IMDS request (169.254.169.254) |
| MIASMA-002 | Cloud metadata | CRITICAL | GCP metadata server request |
| MIASMA-010 | OIDC token | CRITICAL | GitHub Actions OIDC token endpoint request |
| MIASMA-011 | OIDC token | HIGH | Google Cloud OIDC token request |
| PUBLISH-001 | Registry publish | CRITICAL | npm PUT during package install |
| PUBLISH-002 | Registry publish | CRITICAL | PyPI upload during package install |
| CRED-001 | Credential file | CRITICAL | Kubernetes service account token read |
| CRED-002–005 | Credential file | HIGH | GCP / AWS / Azure / SSH credential file reads |
| ENV-002 | Env var harvest | CRITICAL | Access to `OIDC_PACKAGES`, `GITHUB_TOKEN`, `CI_TOKEN` |
| PROC-002 | Process injection | CRITICAL | `curl` piped to shell from install script |

---

## Project Structure

```
oss-trust-framework/
├── src/
│   ├── age_check/
│   │   └── checker.py              # Gate 1 — multi-ecosystem registry timestamp fetching
│   ├── signature/
│   │   └── provenance.py           # Gate 2 — npm/PyPI attestation + publisher repo allowlist
│   ├── cicd_audit/                 # Gate 2.5 — CI/CD pipeline audit (Miasma class)
│   │   ├── orphan_commits.py       # 2.5a — BFS commit graph walk; detects direct pushes
│   │   ├── workflow_permissions.py # 2.5b — dangerous perm detection + compensating controls
│   │   └── pr_provenance.py        # 2.5c — release must trace to reviewed merged PR
│   ├── trust/
│   │   └── aggregator.py           # Gate 3 — concurrent OpenSSF/OSV/deps.dev/GHSA queries
│   ├── sbom/                       # Gate 4 — SBOM delta and hash pinning (stub)
│   ├── sandbox/
│   │   └── behavioral_patterns.py  # Gate 5 — 18 Miasma-class behavioral signatures
│   ├── zeroday/
│   │   └── validator.py            # CVE machine-validation + quorum approval manager
│   └── pipeline/
│       ├── orchestrator.py         # Full pipeline runner; standard and zero-day routing
│       └── cli.py                  # oss-trust check / zeroday request/approve/status
├── tests/
│   ├── test_age_check.py           # Gate 1: registry API mocks, threshold boundary cases
│   ├── test_cicd_audit.py          # Gate 2.5: orphan, workflow, PR provenance
│   ├── test_behavioral_patterns.py # Gate 5: all Miasma patterns + clean install baseline
│   └── test_zeroday_quorum.py      # ZD lane: expiry, duplicate vote, MFA, self-approval
├── config/
│   ├── pipeline.yaml               # All thresholds, gate config, circuit breakers
│   └── trusted_publishers.yaml     # Publisher repo allowlist (populate from your dep graph)
├── .github/
│   └── workflows/
│       └── dep-trust-check.yml     # PR gate: auto-runs on lock file changes
├── .env.example
├── pyproject.toml
├── CONTRIBUTING.md
└── LICENSE
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Three gates are implemented as stubs awaiting production implementation — good first issues:

| Gate | File | What to implement |
|---|---|---|
| 4 — SBOM delta | `src/sbom/differ.py` | syft/cdxgen invocation; CycloneDX JSON diff; lock file hash pinning |
| 5 — Sandbox runner | `src/sandbox/runner.py` | gVisor container launch; install command execution; event feed to `behavioral_patterns.evaluate_sandbox_events()` |
| 2 — GPG fallback | `src/signature/gpg.py` | GPG verification for ecosystems not yet on Sigstore |

All PRs must pass the framework's own CI gate. Zero-day lane changes require CISO sign-off.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [Miasma attack analysis — devops.com](https://devops.com/shai-hulud-clone-miasma-compromises-32-red-hat-npm-packages/)
- [OpenSSF Scorecard](https://securityscorecards.dev)
- [Sigstore / cosign](https://docs.sigstore.dev)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [Google deps.dev](https://deps.dev)
- [SLSA Framework](https://slsa.dev)
- [npm provenance attestations](https://docs.npmjs.com/generating-provenance-statements)
- [PyPI provenance / Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [gVisor container sandbox](https://gvisor.dev)
- [Socket.dev supply chain analysis](https://socket.dev)
