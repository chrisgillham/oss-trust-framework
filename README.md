# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — with hardened defenses against CI/CD pipeline compromise (Miasma, Shai-Hulud, TanStack, Bitwarden, IronWorm) and a strictly controlled expedited lane for zero-day CVE patches.

> **v0.3 — All gates operational.** Gate 0 (name similarity), Gate 2 (provenance + GPG), Gate 2.5a/b/c (CI/CD audit), Gate 3 (OOB trust), Gate 4 (SBOM delta), Gate 5 (behavioral sandbox via strace/gVisor). Gate 5 sandbox runner active on Linux CI via strace; gVisor provides strongest isolation. See [Contributing](#contributing) for gVisor setup.

---

## These attacks are actively happening now. To trusted projects.

| Attack | Date | Packages | Vector | Status |
|---|---|---|---|---|
| **Miasma / Red Hat Insights** | 2026 | 32 npm | Compromised employee account + OIDC trusted publishing | Active campaign |
| **IronWorm** | 2026-06-03 | 36 npm | Rust ELF preinstall hook + eBPF rootkit + Tor C2 | Active campaign |
| **TanStack** | 2026 | 170 npm | Same OIDC trusted publishing pattern | Active campaign |
| **Bitwarden CLI** | 2026 | npm | Checkmarx campaign — OIDC trusted publishing | Active campaign |
| **XZ Utils** | 2024 | tarball | 2-year social engineering → build script backdoor | CVSS 10.0 |

---

## Why This Exists

Three distinct supply chain attack patterns are defeating traditional defenses right now:

**Pattern 1 — Speed attacks.** A compromised maintainer account publishes a malicious release. Automated dependency tooling (Dependabot, Renovate, npm update) ingests it within minutes. The attacker wins the race against community detection and revocation.

**Pattern 2 — CI/CD pipeline compromise (Miasma class).** An attacker compromises a legitimate employee's GitHub account, pushes orphan commits bypassing PR review, and exploits `id-token: write` CI/CD permissions to publish via OIDC trusted publishing. The packages are *correctly signed* — the signature is real. Traditional signature verification passes completely.

**Pattern 3 — Rust-based infostealer worms (IronWorm class).** A malicious binary is dropped via a package `preinstall` hook. It hides behind an eBPF kernel rootkit, harvests 86+ environment variables including AI API keys (OpenAI, Anthropic), cloud credentials, SSH keys, and cryptocurrency wallet seed phrases, then beacons to a Tor hidden service. It self-propagates by using stolen npm OIDC credentials to publish trojanized versions of victim-owned packages. Hash-based IOCs are useless — IronWorm generates unique encrypted payloads per infection.

This framework addresses all three patterns with layered, independent gates.

---

## Key Benefits

### Catches attacks that valid signatures can't detect
Miasma and IronWorm both produce packages with valid Sigstore signatures — the attacker controls a real CI/CD pipeline with real OIDC credentials. Gate 2.5 audits the *chain of custody* behind the signature: was there a PR? Did it go through normal merge? Does the attestation point to the canonical org repo or a compromised fork?

### Behavior-based patterns defeat encrypted and obfuscated payloads
IronWorm generates a unique encrypted payload per infection specifically to defeat hash-based IOCs. Gate 5 matches on *what the payload does* — Tor .onion connections, eBPF syscalls, AI API key access, Exodus wallet reads — not what it looks like. 34 named patterns (18 Miasma + 16 IronWorm). **Active on Linux CI via strace; gVisor provides strongest isolation for production use.**

### Structural defense — no single point of failure
Each gate queries sources architecturally independent of the compromised repository. Defeating the framework requires compromising NVD + OSV + GHSA + OpenSSF Scorecard + deps.dev + the npm attestation registry simultaneously. No single compromised account, repository, or CI/CD pipeline is sufficient. When the Gate 5 sandbox runner is implemented, IronWorm's eBPF rootkit will also be unable to escape the gVisor kernel boundary.

### Zero-day patches move fast without moving unsafely
The 72-hour age hold is the highest-ROI control in the framework, but it creates a gap when a legitimate zero-day patch drops. The expedited lane bypasses *only* the age gate, with machine-verified CVE confirmation, 2-of-3 MFA quorum approval, and a 6-hour token TTL.

### Fully auditable by design
Every gate decision, zero-day exception, and approval event emits a structured SIEM event. Ticket linkage is mandatory for exceptions. Monthly retrospectives are enforced by circuit breaker. Built to satisfy auditors who weren't in the room.

### Drop-in CI/CD integration
The GitHub Actions workflow fires automatically on any lock file change, comments gate results on PRs, and fails the build on block or quarantine. No per-repo configuration after initial setup.

### Catches typosquatting and package impersonation at the door
Gate 0 runs before any network query. It compares the requested package name against every entry in your trusted publisher allowlist using three algorithms — Levenshtein edit distance, prefix-addition detection, and adjacent character transposition. `postmark-mcp-evil` vs `postmark-mcp` scores 95% similarity and is blocked before Gate 1 even runs. No network required.

### Supply chain integrity — not a substitute for runtime monitoring
The framework validates dependencies **before they enter your environment**. It is a supply chain integrity layer, not a runtime security monitor. Threats that manifest after install — a long-running MCP server BCC'ing outbound email, a library that beacons only after a specific condition is met — require complementary runtime tooling (Falco, Tetragon, eBPF-based monitoring). These are parallel controls, not competing ones.

### 131-test suite with no external dependencies
All tests run offline with mocked API calls. Gate 1 threshold boundaries, all 34 named behavioral patterns, full zero-day quorum lifecycle, cross-gate integration scenarios, and regression tests for known CVE-affected package versions.

---

## OWASP Top 10 CI/CD Security Risks Coverage

The framework directly addresses all 10 of the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/). The mapping below shows which gates implement each control.

| Risk | OWASP description | Framework coverage | Gates |
|---|---|---|---|
| **CICD-SEC-1** | Insufficient Flow Control Mechanisms | The age gate enforces a mandatory hold on all new releases regardless of source. The zero-day lane requires machine-verified CVE + 2-of-3 MFA quorum before bypassing it. No single individual can accelerate a dependency update unilaterally. | Gate 1, ZD lane |
| **CICD-SEC-2** | Inadequate Identity and Access Management | Gate 2.5b audits `id-token: write` and other dangerous permissions in publishing workflows. Gate 2.5c enforces minimum reviewer counts on releases. The zero-day quorum enforces separation of duties — the requester cannot approve their own exception. | Gates 2.5b, 2.5c, ZD lane |
| **CICD-SEC-3** | Dependency Chain Abuse | The core mission of the framework. Gates 1–5 collectively validate every dependency update before ingestion — age, signature, CI/CD pipeline integrity, out-of-band trust, SBOM delta, and behavioral sandbox. This is exactly the attack class the framework was built to stop. | Gates 1–5 |
| **CICD-SEC-4** | Poisoned Pipeline Execution (PPE) | Gate 2.5a detects orphan commits — direct pushes bypassing the merge queue. Gate 2.5c confirms every release traces to a reviewed merged PR. Gate 2.5b flags workflows with dangerous permissions exploitable via PPE. The Miasma / Shai-Hulud attack class is a direct real-world example of PPE. | Gates 2.5a, 2.5b, 2.5c |
| **CICD-SEC-5** | Insufficient PBAC (Pipeline-Based Access Controls) | Gate 2.5b enforces Pipeline-Based Access Controls by auditing `id-token: write`, `contents: write`, and `packages: write` permissions in publishing workflows, and requiring compensating controls (branch protection, CODEOWNERS, environment protection rules) when these permissions exist. | Gate 2.5b |
| **CICD-SEC-6** | Insufficient Credential Hygiene | Gate 5 behavioral patterns detect credential harvesting at install time: AWS/GCP/Azure reads (CRED-001–005), Vault tokens (IRONWORM-004), npm auth tokens (IRONWORM-006), AI API keys (IRONWORM-003). Gate 2 detects stolen OIDC token misuse. **Note:** Gate 5 sandbox runner is a stub — pattern matching is implemented but inactive until `sandbox/runner.py` is completed. See backlog. | Gates 2, 5 |
| **CICD-SEC-7** | Insecure System Configuration | Gate 2.5b checks for insecure CI/CD configuration: `id-token: write` without environment protection rules, missing branch protection, and absent CODEOWNERS. The framework's own `dep-trust-check.yml` workflow is itself subject to the pipeline. | Gate 2.5b |
| **CICD-SEC-8** | Ungoverned Usage of 3rd Party Services | Gate 3 queries OpenSSF Scorecard, OSV, deps.dev, and GitHub Advisories to independently evaluate every third-party dependency. Gate 4 SBOM delta catches unexpected transitive dependencies introduced by third-party packages. `trusted_publishers.yaml` governs which external publisher repos are trusted per package. | Gates 3, 4 |
| **CICD-SEC-9** | Improper Artifact Integrity Validation | Gate 2 verifies Sigstore / GPG cryptographic signatures and cross-checks `sourceRepositoryURI` in provenance attestations against the trusted publishers allowlist. Gate 4 pins exact hashes in lock files and detects integrity changes. Gate 2.5a confirms the tagged commit is reachable from the default branch, preventing detached / orphaned artifact publishing. | Gates 2, 2.5a, 4 |
| **CICD-SEC-10** | Insufficient Logging and Visibility | Every gate decision emits a structured SIEM event. Zero-day exceptions require ticket linkage before deployment. Quorum approval events — including MFA failures and duplicate vote attempts — are emitted immediately. Monthly retrospectives are enforced by circuit breaker. The framework produces a complete, non-repudiable audit trail for every dependency decision. | All gates, ZD lane |

### Coverage summary

| Coverage level | Risks |
|---|---|
| Fully addressed — multiple independent gates | CICD-SEC-3, CICD-SEC-4, CICD-SEC-9 |
| Fully addressed — dedicated gate controls | CICD-SEC-1, CICD-SEC-2, CICD-SEC-5, CICD-SEC-7, CICD-SEC-8, CICD-SEC-10 |
| Not addressed | None — all 10 risks have full gate implementations |

The framework provides full coverage across all 10 OWASP CI/CD Security Risks. Gate 5 is active on Linux CI via strace (install-time behavioral analysis). gVisor provides the strongest isolation for production use — see the [Gate 5 setup guide](docs/gate5_gvisor_setup.md).

---

## Architecture

> **Scope:** This framework validates supply chain integrity at dependency install time. It does not monitor runtime application behaviour. See [Supply chain integrity vs runtime monitoring](#supply-chain-integrity-vs-runtime-monitoring) for details.

```
Dependency update request
        │
        ▼
┌──────────────────────┐   Name ≥ 92% similar to trusted pkg ──► BLOCKED   ◄── postmark-mcp-evil
│  Gate 0: Name        │   Name ≥ 80% similar ──► WARN (manual review)
│  Similarity Check    │   Exact allowlist match ──► pass immediately
│  (local, no network) │   3 algorithms: Levenshtein · prefix · char-swap
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐   < 24 h, no CVE ──► BLOCKED
│  Gate 1: Age Hold    │
│  24 h hard block     │   Zero-day CVE filed? ──► Expedited Lane ──────────────┐
│  72 h soft hold      │                                                         │
└──────────┬───────────┘                                                         │
           │ ≥ 24 h                                                              │
           ▼                                                                     │
┌──────────────────────┐   Repo mismatch ──► BLOCKED   ◄── Miasma/IronWorm:    │
│  Gate 2: Provenance  │                                    fork/employee acct  │
│  Attestation +       │   No attestation ──► QUARANTINE                        │
│  Publisher Allowlist │   (sourceRepositoryURI vs trusted_publishers.yaml)     │
└──────────┬───────────┘                                                         │
           │                                                                     │
           ▼                                                                     │
┌──────────────────────┐   Orphan commit ──► BLOCKED    ◄── Miasma/IronWorm:   │
│  Gate 2.5: CI/CD     │   id-token:write ──► QUARANTINE     direct push       │
│  Pipeline Audit      │   No PR review  ──► BLOCKED    ◄── OIDC abuse         │
│  [2.5a] Orphan commits                                                         │
│  [2.5b] Workflow perms                                                         │
│  [2.5c] PR provenance│                                                         │
└──────────┬───────────┘                                                         │
           │                                            ◄── Rejoins here ────────┘
           ▼
┌──────────────────────┐   Score < threshold ──► QUARANTINE
│  Gate 3: Out-of-Band │   Active CVE ──► QUARANTINE
│  Trust Aggregation   │   (OpenSSF · OSV · deps.dev · GHSA)
│                      │   Note: individual source failures degrade score,
│                      │   they do not fail the gate outright (resilient)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐   New transitive dep ──► QUARANTINE
│  Gate 4: SBOM Delta  │   Hash mismatch ──► QUARANTINE
│  + Hash Pin          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐   Tor C2 / temp.sh ──► BLOCKED  ◄── IronWorm: exfil
│  Gate 5: Behavioral  │   eBPF rootkit ──► BLOCKED       ◄── IronWorm: rootkit
│  Sandbox             │   AI API key harvest ──► BLOCKED  ◄── IronWorm: OPENAI_API_KEY
│  34 patterns active  │   Cloud cred harvest ──► BLOCKED  ◄── Miasma: IMDS/OIDC
│  strace CI backend   │   Exodus wallet ──► BLOCKED       ◄── IronWorm: crypto theft
│  gVisor: strongest   │   Registry publish ──► BLOCKED    ◄── Both: re-publish
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
Behavioral sandbox (34 patterns active · strace backend on Linux CI · gVisor for production)
        │
        ▼
Audit record (SIEM event + ticket link mandatory before deploy)
        │
        ▼
Immediate full-fleet deploy + 48 h elevated alert window
```

---

## Installation

There are two paths depending on what you want to do:

### Use in your project (most common)

You want to protect an existing repo from supply chain attacks. Do **not** clone the framework repo — just install it and add the GitHub Actions workflow.

```bash
# Option A — from GitHub source (works right now)
pip install "git+https://github.com/chrisgillham/oss-trust-framework.git"

# Option B — from PyPI (once published)
pip install oss-trust-framework

# Verify
oss-trust --version
# oss-trust, version 0.3.0
```

Then add the workflow to your repo (see [CI/CD Integration](#cicd-integration) below) and populate `config/trusted_publishers.yaml` with your critical packages.

### Develop the framework (contributors)

Only clone the repo if you are contributing — adding behavioral patterns, implementing stub gates, or working on the codebase.

```bash
# Clone and set up editable install
git clone https://github.com/chrisgillham/oss-trust-framework
cd oss-trust-framework

# Windows
python -m venv .venv && .venv\Scripts\activate

# Mac/Linux
python -m venv .venv && source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Verify
oss-trust --version
# oss-trust, version 0.3.0

cp .env.example .env
# Edit .env — add GITHUB_TOKEN, SIEM_HEC_ENDPOINT, etc.
```

**Note on coverage command:** Use `--cov=oss_trust_framework` not `--cov=src` — the package directory was renamed:
```bash
pytest tests/ -v --cov=oss_trust_framework --cov-report=term-missing
```

---

## Quickstart

> **Installing the framework in your own project?** Use `pip install "git+https://github.com/chrisgillham/oss-trust-framework.git"` — do not clone this repo. See [Installation](#installation) above.

```bash
# Run the full pipeline against a single package
oss-trust check \
  --package requests \
  --version 2.33.0 \
  --ecosystem PyPI \
  --github-repo psf/requests

# Check all packages in requirements.txt + framework_deps.txt
# (with interactive allowlist management for unlisted packages)
python check_all.py

# Request a zero-day expedited exception
oss-trust zeroday request \
  --cve CVE-2024-XXXXX \
  --package requests \
  --version 2.33.1 \
  --requester security@yourorg.com

# Approve (run by each named approver separately)
oss-trust zeroday approve \
  --request-id abc123def456 \
  --approver-id approver_001 \
  --mfa-token 123456

# Check status
oss-trust zeroday status --request-id abc123def456
```

---

## Configuration

### Core pipeline settings (`config/pipeline.yaml`)

```yaml
age_gate:
  hard_block_hours: 24      # < 24 h: auto-blocked regardless of source
  hold_hours: 72            # 24-72 h: human approval required

trust_scoring:
  min_scorecard_score: 6.0  # OpenSSF minimum (0-10)
  require_zero_active_vulns: true
  # Note: if a source is unavailable, the aggregator uses a neutral
  # default score for that source rather than failing the gate.
  # This is intentional resilient behaviour.

cicd_audit:
  orphan_commits:
    enabled: true
    action_on_orphan: block
  workflow_permissions:
    enabled: true
    action_on_finding: quarantine
  pr_provenance:
    min_pr_reviewers: 1
    action_on_direct_push: block

sandbox:
  runtime: gvisor
  network: none
  behavioral_patterns:
    block_on_critical: true

zero_day:
  required_approvers: 2
  token_ttl_hours: 6
  circuit_breakers:
    max_exceptions_per_24h: 3
```

### Trusted publisher allowlist (`config/trusted_publishers.yaml`)

Maps package names to their canonical GitHub source repo. A provenance attestation pointing to any other repository is treated as a CRITICAL finding and blocked.

```yaml
PyPI:
  "requests": "psf/requests"
  "cryptography": "pyca/cryptography"
  "httpx": "encode/httpx"

require_attestation:        # Missing attestation = BLOCK (not just quarantine)
  PyPI:
    - "cryptography"
    - "httpx"
```

Run `python check_all.py` in your project to interactively populate this file from your actual dependency graph. For each unlisted package, the tool auto-looks up the canonical repo from PyPI and offers to add it with Option 1 (allowlist only) or Option 2 (allowlist + require_attestation).

---

## Running Tests

```bash
# Full suite — 131 tests, all offline (no network required)
pytest

# By gate
pytest tests/test_gate1_age.py        # 11 tests — age threshold boundaries
pytest tests/test_gate3_trust.py      # 6 tests  — OOB trust aggregation
pytest tests/test_gate5_behavioral.py # 50 tests — all 34 named patterns
pytest tests/test_zeroday_lane.py     # 23 tests — full quorum lifecycle
pytest tests/test_integration.py      # 10 tests — cross-gate scenarios
pytest tests/test_check_all.py        # 13 tests — dependency check utilities

# With coverage
pytest --cov=oss_trust_framework --cov-report=term-missing
```

### Test design notes

- All external API calls (PyPI, OSV, OpenSSF, GitHub) are mocked — tests run fully offline
- Gate 5 tests cover every named pattern individually — 18 Miasma + 16 IronWorm; sandbox backend mocked in unit tests, active via strace on Linux CI
- Zero-day tests cover the full lifecycle: create → approve (×2) → quorum → post-approval state
- Integration tests include regression cases for `requests 2.32.3` (2 CVEs) vs `2.33.0` (clean)
- Gate 3 source failure is tested: individual source unavailability degrades score gracefully rather than failing the gate

---

## Gate Reference

| Gate | Controls | Fail action | Bypassable? |
|---|---|---|---|
| **0 — Name similarity** | Package name vs trusted allowlist — Levenshtein, prefix-addition, char-swap detection | Warn (≥80%) · Block (≥92%) | No |
| **1 — Age** | Release timestamp vs 24 h / 72 h thresholds | Block / Hold | Age only — with CVE + MFA quorum |
| **2 — Provenance** | Sigstore attestation present; `sourceRepositoryURI` matches allowlist | Block (mismatch) · Quarantine (missing) | No |
| **2.5a — Orphan commits** | Release tag commit reachable from default branch via BFS graph walk | Block | No |
| **2.5b — Workflow permissions** | `id-token: write` in publishing workflow without compensating controls | Quarantine | No |
| **2.5c — PR provenance** | Release backed by merged PR with ≥ 1 approving reviewer | Block (no PR) · Quarantine (no review) | No |
| **3 — OOB Trust** | OpenSSF Scorecard ≥ threshold; zero active CVEs via OSV + deps.dev + GHSA | Quarantine | No |
| **4 — SBOM delta** | No unexpected transitive deps; lock file hash unchanged | Quarantine | No |
| **5 — Behavioral sandbox** | gVisor/strace install-time execution; 34 named behavioral patterns (18 Miasma + 16 IronWorm); behavior-based not hash-based; active on Linux CI via strace | Block | No |

---

## Attack Coverage

### Miasma / Shai-Hulud — Red Hat Insights (2026)

A compromised Red Hat employee GitHub account pushed orphan commits to two RedHatInsights repositories. A CI/CD workflow with `id-token: write` permission published backdoored versions of 32 packages via OIDC trusted publishing. Packages carried valid Sigstore signatures. Same pattern used against TanStack (170 packages) and Bitwarden CLI.

| Attack step | Gate | Mechanism |
|---|---|---|
| Orphan commit pushed, bypassing PR | **2.5a** | BFS walk; tag commit unreachable from main → BLOCK |
| No code review on malicious commit | **2.5c** | No merged PR → DIRECT_PUSH → BLOCK |
| `id-token: write` exploited for OIDC publish | **2.5b** | Dangerous perm + no env protection → QUARANTINE |
| Published from employee fork, not canonical org | **2** | `sourceRepositoryURI` mismatch → BLOCK |
| Cloud credential harvesting (GCP/Azure IMDS) | **5** | MIASMA-001/002: IMDS network events → BLOCK |
| OIDC token requested from install context | **5** | MIASMA-010: `token.actions.githubusercontent.com` → BLOCK |
| Re-publish to npm from install script | **5** | PUBLISH-001: PUT to `registry.npmjs.org` → BLOCK |
| Unique encrypted payload defeats hash IOCs | **5** | Behavior-matched, not hash-matched |

### IronWorm — asteroiddao / Arweave ecosystem (JFrog, 2026-06-03)

A Rust ELF binary (`tools/setup`, UPX-packed with overwritten magic bytes) is dropped via an npm `preinstall` hook. It deploys an eBPF kernel rootkit, harvests 86 environment variables and 20+ credential file paths, and beacons to a Tor hidden service. Self-propagates via stolen npm OIDC credentials. Backdates commits to obscure forensic timeline.

| Attack step | Gate | Mechanism |
|---|---|---|
| Published from compromised `asteroiddao` account | **2** | `sourceRepositoryURI` mismatch → BLOCK |
| Orphan commits with backdated timestamps | **2.5a** | Graph reachability — timestamps irrelevant → BLOCK |
| No merged PR for release | **2.5c** | No PR → DIRECT_PUSH → BLOCK |
| Rust ELF binary dropped via `preinstall` hook | **5** | IRONWORM-002b: `tools/setup` process event → BLOCK |
| eBPF kernel rootkit load | **5** | IRONWORM-002: `BPF_PROG_LOAD` syscall → BLOCK (gVisor kernel boundary prevents rootkit escape) |
| AI API key harvest (OpenAI, Anthropic, Gemini, Cohere) | **5** | IRONWORM-003: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` env access → BLOCK |
| AWS / GCP / Azure / Vault credential theft | **5** | CRED-003/004 + IRONWORM-004: credential file reads → BLOCK |
| SSH key theft | **5** | CRED-005: `/root/.ssh` file access → HIGH |
| Exodus cryptocurrency wallet seed phrase theft | **5** | IRONWORM-005/005b: `~/.config/Exodus` file access → BLOCK |
| Tor hidden service C2 beacon | **5** | IRONWORM-001: `.onion` network event → BLOCK (+ `--network=none`) |
| temp.sh fallback exfil | **5** | IRONWORM-001c: `temp.sh` network event → BLOCK (+ `--network=none`) |
| npm token theft for self-propagation | **5** | IRONWORM-006/006b: `.npmrc` read + `NPM_AUTH_TOKEN` env → BLOCK |
| GitHub Actions workflow overwrite | **5** | IRONWORM-007: write to `.github/workflows/` → BLOCK |
| Vault token theft | **5** | IRONWORM-004b: `VAULT_TOKEN` env access → BLOCK |

### Structural defense

Bypassing the framework requires compromising all of the following simultaneously:

- The package registry's provenance attestation system (Sigstore/npm)
- NVD, OSV, and GitHub Security Advisories (for the zero-day lane)
- OpenSSF Scorecard and deps.dev (Gate 3)
- The behavioral sandbox runtime (when Gate 5 sandbox runner is implemented — currently a strace/gVisor active)
- The quorum approval process (2-of-3 named individuals with MFA)

---

## Zero-Day Lane Circuit Breakers

| Condition | Action |
|---|---|
| > 3 exception requests in 24 hours | Lane suspended pending CISO review |
| Same requester files two exceptions within 48 hours | Second request escalates to CISO sign-off |
| Any exception-deployed package receives a new CVE within 30 days | Lane suspended; retrospective triggered |
| Monthly retrospective finds process violations | Lane suspended until remediation confirmed |

Exception tokens expire after 6 hours. Re-approval required — no extensions.

---

## Out-of-Band Trust Sources (Gate 3)

All sources queried independently of the package repository. A compromised repo cannot influence these results. Individual source failures degrade the composite score but do not fail the gate outright — this is intentional resilient behaviour that prevents a single unavailable API from blocking all dependency updates.

| Source | API endpoint | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Security hygiene score (CI, branch protection, code review, signing) |
| deps.dev (Google) | `api.deps.dev/v3alpha/...` | Dependency graph, version velocity, known advisories |
| OSV.dev | `api.osv.dev/v1/query` | Cross-ecosystem CVE database; patch version "fixed" list verification |
| GitHub Security Advisories | `api.github.com/advisories` | Manually reviewed, high-confidence signal |
| npm Advisory DB | `npm audit` | npm-specific compromise and vulnerability history |

---

## Behavioral Patterns (Gate 5)

34 named patterns across two confirmed attack families. Active on Linux CI via strace; gVisor provides strongest isolation. Matched by event type — encryption, obfuscation, and unique-per-infection payloads are irrelevant to behavioral matching.

### Miasma / Shai-Hulud patterns (18)

| Pattern ID | Category | Severity | Description |
|---|---|---|---|
| MIASMA-001 | Cloud metadata | CRITICAL | AWS/Azure IMDS request (169.254.169.254) |
| MIASMA-002 | Cloud metadata | CRITICAL | GCP metadata server request |
| MIASMA-003 | Cloud metadata | CRITICAL | Azure IMDS endpoint |
| MIASMA-004 | Cloud metadata | HIGH | Kubernetes cluster API from install context |
| MIASMA-010 | OIDC token | CRITICAL | GitHub Actions OIDC token endpoint |
| MIASMA-011 | OIDC token | HIGH | Google Cloud OIDC token endpoint |
| MIASMA-012 | OIDC token | HIGH | Azure AD OIDC token endpoint |
| CRED-001 | Credential file | CRITICAL | Kubernetes service account token |
| CRED-002 | Credential file | HIGH | GCP application default credentials |
| CRED-003 | Credential file | HIGH | AWS credentials file |
| CRED-004 | Credential file | HIGH | Azure CLI credentials |
| CRED-005 | Credential file | HIGH | SSH private key directory |
| PUBLISH-001 | Registry publish | CRITICAL | npm PUT during package install |
| PUBLISH-002 | Registry publish | CRITICAL | PyPI upload during package install |
| ENV-001 | Env var harvest | HIGH | Full environment variable enumeration |
| ENV-002 | Env var harvest | CRITICAL | `OIDC_PACKAGES`, `GITHUB_TOKEN`, `CI_TOKEN` access |
| PROC-001 | Process injection | HIGH | Base64-encoded command execution via shell |
| PROC-002 | Process injection | CRITICAL | curl piped to shell from install script |
| PROC-003 | Process injection | HIGH | Python eval/exec with encoded payload |

### IronWorm patterns (16) — added 2026-06-05

| Pattern ID | Category | Severity | Description |
|---|---|---|---|
| IRONWORM-001 | Encrypted exfil | CRITICAL | Tor .onion C2 connection |
| IRONWORM-001b | Encrypted exfil | CRITICAL | Tor SOCKS port 9050/9150 |
| IRONWORM-001c | Encrypted exfil | CRITICAL | temp.sh fallback exfil |
| IRONWORM-002 | Kernel exploit | CRITICAL | eBPF `BPF_PROG_LOAD` syscall from install context |
| IRONWORM-002b | Kernel exploit | CRITICAL | `tools/setup` Rust ELF binary execution |
| IRONWORM-002c | Kernel exploit | CRITICAL | Rust ELF dropped to `/tmp/tools/` |
| IRONWORM-003 | Env var harvest | CRITICAL | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `COHERE_API_KEY` |
| IRONWORM-004 | Credential file | CRITICAL | HashiCorp Vault token file |
| IRONWORM-004b | Env var harvest | CRITICAL | `VAULT_TOKEN`, `VAULT_ADDR` env access |
| IRONWORM-005 | Crypto wallet | CRITICAL | Exodus wallet `/home/.config/Exodus` |
| IRONWORM-005b | Crypto wallet | CRITICAL | Exodus wallet `/root/.config/Exodus` |
| IRONWORM-005c | Crypto wallet | HIGH | Atomic wallet directory |
| IRONWORM-006 | Credential file | HIGH | `.npmrc` auth token file read |
| IRONWORM-006b | Env var harvest | CRITICAL | `NPM_AUTH_TOKEN`, `NODE_AUTH_TOKEN` env access |
| IRONWORM-007 | Process injection | CRITICAL | Write to `.github/workflows/` — workflow hijack |

---

## Project Structure

```
oss-trust-framework/
├── oss_trust_framework/            # Installable Python package
│   ├── name_similarity/
│   │   └── checker.py              # Gate 0 — typosquat/impersonation detection (3 algorithms)
│   ├── age_check/
│   │   └── checker.py              # Gate 1 — multi-ecosystem registry timestamp fetching
│   ├── signature/
│   │   ├── provenance.py           # Gate 2 — npm/PyPI attestation + publisher repo allowlist
│   │   └── gpg.py                  # Gate 2 — GPG fallback for non-Sigstore ecosystems (keyring population required)
│   ├── cicd_audit/                 # Gate 2.5 — CI/CD pipeline audit (Miasma/IronWorm class)
│   │   ├── orphan_commits.py       # 2.5a — BFS commit graph walk; detects direct pushes
│   │   ├── workflow_permissions.py # 2.5b — dangerous perm detection + compensating controls
│   │   └── pr_provenance.py        # 2.5c — release must trace to reviewed merged PR
│   ├── trust/
│   │   └── aggregator.py           # Gate 3 — concurrent OpenSSF/OSV/deps.dev/GHSA queries
│   ├── sbom/
│   │   └── differ.py               # Gate 4 — CycloneDX SBOM delta + hash pin (syft required)
│   ├── sandbox/
│   │   ├── behavioral_patterns.py  # Gate 5 — 34 patterns: 18 Miasma + 16 IronWorm (COMPLETE)
│   │   └── runner.py               # Gate 5 — sandbox executor (strace/gVisor/audit backends)
│   ├── zeroday/
│   │   └── validator.py            # CVE machine-validation + quorum approval manager
│   ├── config.py                   # Config loader and quorum manager factory
│   └── pipeline/
│       ├── orchestrator.py         # Full pipeline runner; standard and zero-day routing
│       └── cli.py                  # oss-trust check / zeroday request/approve/status
├── tests/
│   ├── conftest.py                 # Shared fixtures (quorum_manager, attack event chains)
│   ├── test_gate1_age.py           # 11 tests — age threshold boundaries, custom thresholds
│   ├── test_gate3_trust.py         # 6 tests  — OOB trust aggregation, source resilience
│   ├── test_gate5_behavioral.py    # 50 tests — all 34 patterns individually + utilities
│   ├── test_zeroday_lane.py        # 23 tests — full quorum lifecycle, MFA, expiry
│   ├── test_integration.py         # 10 tests — cross-gate scenarios, regression tests
│   └── test_scenarios.py           # 18 tests — original demo scenarios
├── config/
│   ├── pipeline.yaml               # All thresholds, gate config, circuit breakers
│   └── trusted_publishers.yaml     # Publisher repo allowlist
├── docs/
│   └── index.html                  # Full documentation site (GitHub Pages)
├── .github/
│   └── workflows/
│       └── dep-trust-check.yml     # PR gate: auto-runs on lock file changes
├── .env.example
├── pyproject.toml
├── CONTRIBUTING.md
└── LICENSE
```

---

## Supply chain integrity vs runtime monitoring

The OSS Trust Framework is a **supply chain integrity** tool. It validates dependencies before they enter your environment. This is a fundamentally different control than runtime security monitoring, and the two are complementary — not competing.

| Threat | Framework coverage | What you also need |
|---|---|---|
| Malicious install script (IronWorm preinstall hook) | Gate 5 — behavioral sandbox (when runner implemented) | — |
| Compromised publisher account (Miasma) | Gates 2, 2.5, 5 | — |
| Typosquat / impersonation (postmark-mcp-evil) | Gate 0 — name similarity | — |
| Known CVE in dependency | Gate 3 — OOB trust aggregation | — |
| **Runtime exfiltration** (MCP server BCC'ing email) | **Not covered** | Runtime monitoring (Falco, Tetragon) |
| **Deferred activation** (library beacons after condition met) | **Not covered** | Runtime monitoring |
| **Semantic impersonation** (secure-requests impersonating requests) | **Not covered** — low string similarity | Manual allowlist review |

The postmark-mcp impersonation attack (September 2025, first in-the-wild malicious MCP server) is a good illustration of this boundary. Gate 0 would have flagged the name similarity. But the BCC behavior itself — triggered at runtime when the server handled email — is outside install-time sandboxing scope. Both layers are necessary.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

**Implemented gates:** 0 (name similarity), 1 (age), 2 (provenance), 2.5a/b/c (CI/CD audit), 3 (OOB trust), zero-day lane.

**Partially implemented:** Gate 4 (SBOM delta logic complete, syft required), Gate 2 GPG fallback (implemented, keyring population required).

**All core gates are implemented and operational.** Gate 5 uses strace on Linux CI and supports gVisor for strongest isolation. See [docs/gate5_gvisor_setup.md](docs/gate5_gvisor_setup.md) for gVisor setup instructions.

Contributions welcome — open issues for feature requests, additional behavioral patterns, or ecosystem support (Cargo, Go, Maven).

All PRs must pass the framework's own CI gate. Zero-day lane changes require CISO sign-off.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [IronWorm: Shai-Hulud's rustier cousin — JFrog Security Research](https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/)
- [IronWorm malware hits 36 npm packages — BleepingComputer](https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/)
- [Miasma compromises 32 Red Hat npm packages — devops.com](https://devops.com/shai-hulud-clone-miasma-compromises-32-red-hat-npm-packages/)
- [TanStack npm supply chain attack — Security Boulevard](https://securityboulevard.com/2026/05/the-tanstack-npm-supply-chain-attack-that-hit-170-packages-and-punishes-you-for-revoking-your-token/)
- [Bitwarden CLI compromise — Security Boulevard](https://securityboulevard.com/2026/04/bitwarden-cli-compromise-linked-to-ongoing-checkmarx-supply-chain-campaign/)
- [OpenSSF Scorecard](https://securityscorecards.dev)
- [Sigstore / cosign](https://docs.sigstore.dev)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [Google deps.dev](https://deps.dev)
- [SLSA Framework](https://slsa.dev)
- [npm provenance attestations](https://docs.npmjs.com/generating-provenance-statements)
- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [gVisor container sandbox](https://gvisor.dev)
- [Socket.dev supply chain analysis](https://socket.dev)
