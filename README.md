# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — with hardened defenses against CI/CD pipeline compromise (Miasma, Shai-Hulud, TanStack, Bitwarden, IronWorm) and a strictly controlled expedited lane for zero-day CVE patches.

> **v0.2 — Miasma/Shai-Hulud and IronWorm coverage added.** Gate 2.5 (CI/CD Pipeline Audit) and 34 behavioral patterns in Gate 5 directly counter the active attack campaigns hitting npm packages right now.

---

## These attacks are actively happening now. To trusted projects.

| Attack | Date | Packages | Vector | Status |
|---|---|---|---|---|
| **Miasma / Red Hat Insights** | 2026 | 32 npm | Compromised employee account + OIDC trusted publishing | Active campaign |
| **IronWorm** | 2026-06-03 | 36 npm | Rust ELF preinstall hook + eBPF rootkit + Tor C2 | **Identified 2 days ago** |
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
IronWorm generates a unique encrypted payload per infection specifically to defeat hash-based IOCs. Gate 5 matches on *what the payload does* — Tor .onion connections, eBPF syscalls, AI API key access, Exodus wallet reads — not what it looks like. 34 named patterns across two confirmed attack families.

### Structural defense — no single point of failure
Each gate queries sources architecturally independent of the compromised repository. Defeating the framework requires compromising NVD + OSV + GHSA + OpenSSF Scorecard + deps.dev + the npm attestation registry + the gVisor sandbox simultaneously. No single compromised account, repository, CI/CD pipeline, or kernel rootkit is sufficient. IronWorm's eBPF rootkit cannot escape the gVisor kernel boundary.

### Zero-day patches move fast without moving unsafely
The 72-hour age hold is the highest-ROI control in the framework, but it creates a gap when a legitimate zero-day patch drops. The expedited lane bypasses *only* the age gate, with machine-verified CVE confirmation, 2-of-3 MFA quorum approval, and a 6-hour token TTL.

### Fully auditable by design
Every gate decision, zero-day exception, and approval event emits a structured SIEM event. Ticket linkage is mandatory for exceptions. Monthly retrospectives are enforced by circuit breaker. Built to satisfy auditors who weren't in the room.

### Drop-in CI/CD integration
The GitHub Actions workflow fires automatically on any lock file change, comments gate results on PRs, and fails the build on block or quarantine. No per-repo configuration after initial setup.

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
│  Sandbox (gVisor)    │   AI API key harvest ──► BLOCKED  ◄── IronWorm: OPENAI_API_KEY
│  34 named patterns   │   Cloud cred harvest ──► BLOCKED  ◄── Miasma: IMDS/OIDC
│  (18 Miasma +        │   Exodus wallet ──► BLOCKED       ◄── IronWorm: crypto theft
│   16 IronWorm)       │   Registry publish ──► BLOCKED    ◄── Both: re-publish
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
Behavioral sandbox (gVisor · no network · all 34 patterns active)
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
git clone https://github.com/chrisgillham/oss-trust-framework
cd oss-trust-framework
pip install -e ".[dev]"
cp .env.example .env
```

---

## Gate Reference

| Gate | Controls | Fail action | Bypassable? |
|---|---|---|---|
| **1 — Age** | Release timestamp vs 24 h / 72 h thresholds | Block / Hold | Age only — with CVE + MFA quorum |
| **2 — Provenance** | Sigstore attestation present; `sourceRepositoryURI` matches allowlist | Block (mismatch) · Quarantine (missing) | No |
| **2.5a — Orphan commits** | Release tag commit reachable from default branch via BFS graph walk | Block | No |
| **2.5b — Workflow permissions** | `id-token: write` in publishing workflow without compensating controls | Quarantine | No |
| **2.5c — PR provenance** | Release backed by merged PR with ≥ 1 approving reviewer | Block (no PR) · Quarantine (no review) | No |
| **3 — OOB Trust** | OpenSSF Scorecard ≥ threshold; zero active CVEs via OSV + deps.dev + GHSA | Quarantine | No |
| **4 — SBOM delta** | No unexpected transitive deps; lock file hash unchanged | Quarantine | No |
| **5 — Behavioral sandbox** | gVisor install-time execution; 34 named behavioral patterns (18 Miasma + 16 IronWorm) | Block | No |

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
| eBPF kernel rootkit load | **5** | IRONWORM-002: `BPF_PROG_LOAD` syscall → BLOCK (gVisor boundary prevents escape) |
| AI API key harvest (OpenAI, Anthropic, etc.) | **5** | IRONWORM-003: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` env access → BLOCK |
| AWS / GCP / Azure / Vault credential theft | **5** | CRED-003/004 + IRONWORM-004: credential file reads → BLOCK |
| SSH key theft | **5** | CRED-005: `/root/.ssh` file access → HIGH |
| Exodus cryptocurrency wallet seed phrase theft | **5** | IRONWORM-005/005b: `~/.config/Exodus` file access → BLOCK |
| Tor hidden service C2 beacon | **5** | IRONWORM-001: `.onion` network event → BLOCK (+ `--network=none`) |
| temp.sh fallback exfil | **5** | IRONWORM-001c: `temp.sh` network event → BLOCK (+ `--network=none`) |
| npm token theft for self-propagation | **5** | IRONWORM-006/006b: `.npmrc` read + `NPM_AUTH_TOKEN` env → BLOCK |
| GitHub Actions workflow overwrite | **5** | IRONWORM-007: write to `.github/workflows/` → BLOCK |
| Vault token theft | **5** | IRONWORM-004b: `VAULT_TOKEN` env access → BLOCK |

### Why this is structurally hard to defeat

Bypassing the framework requires compromising all of the following simultaneously:

- The package registry's provenance attestation system (Sigstore/npm)
- NVD, OSV, and GitHub Security Advisories (for the zero-day lane)
- OpenSSF Scorecard and deps.dev (Gate 3)
- The behavioral sandbox runtime (gVisor — IronWorm's eBPF rootkit cannot escape the kernel boundary)
- The quorum approval process (2-of-3 named individuals with MFA)

---

## Zero-Day Lane Circuit Breakers

| Condition | Action |
|---|---|
| > 3 exception requests in 24 hours | Lane suspended pending CISO review |
| Same requester files two exceptions within 48 hours | Second request escalates to CISO sign-off |
| Any exception-deployed package receives a new CVE within 30 days | Lane suspended; retrospective triggered |
| Monthly retrospective finds process violations | Lane suspended until remediation confirmed |

Exception tokens expire after 6 hours. Re-approval required after expiry — no extensions.

---

## Out-of-Band Trust Sources (Gate 3)

All sources queried independently of the package repository. A compromised repo cannot influence these results.

| Source | API endpoint | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Security hygiene score (CI, branch protection, code review, signing) |
| deps.dev (Google) | `api.deps.dev/v3alpha/...` | Dependency graph, version velocity, known advisories |
| OSV.dev | `api.osv.dev/v1/query` | Cross-ecosystem CVE database; patch version "fixed" list verification |
| GitHub Security Advisories | `api.github.com/advisories` | Manually reviewed, high-confidence signal |
| npm Advisory DB | `npm audit` | npm-specific compromise and vulnerability history |

---

## Behavioral Patterns (Gate 5)

34 named patterns across two confirmed attack families. Matched by event type — encryption, obfuscation, and unique-per-infection payloads are irrelevant.

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
| CRED-002–005 | Credential file | HIGH | GCP / AWS / Azure / SSH credential files |
| PUBLISH-001 | Registry publish | CRITICAL | npm PUT during package install |
| PUBLISH-002 | Registry publish | CRITICAL | PyPI upload during package install |
| ENV-001 | Env var harvest | HIGH | Full environment variable enumeration |
| ENV-002 | Env var harvest | CRITICAL | `OIDC_PACKAGES`, `GITHUB_TOKEN`, `CI_TOKEN` access |
| PROC-001–003 | Process injection | HIGH/CRITICAL | Base64 exec, curl-to-shell, eval/exec obfuscation |

### IronWorm patterns (16) — added 2026-06-05

| Pattern ID | Category | Severity | Description |
|---|---|---|---|
| IRONWORM-001 | Encrypted exfil | CRITICAL | Tor .onion C2 connection |
| IRONWORM-001b | Encrypted exfil | CRITICAL | Tor SOCKS port 9050/9150 |
| IRONWORM-001c | Encrypted exfil | CRITICAL | temp.sh fallback exfil |
| IRONWORM-002 | Kernel exploit | CRITICAL | eBPF `BPF_PROG_LOAD` syscall from install context |
| IRONWORM-002b | Kernel exploit | CRITICAL | `tools/setup` Rust ELF binary execution |
| IRONWORM-002c | Kernel exploit | CRITICAL | Rust ELF dropped to `/tmp/tools/` |
| IRONWORM-003 | Env var harvest | CRITICAL | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` etc. |
| IRONWORM-004 | Credential file | CRITICAL | HashiCorp Vault token file |
| IRONWORM-004b | Env var harvest | CRITICAL | `VAULT_TOKEN`, `VAULT_ADDR` env access |
| IRONWORM-005/b | Crypto wallet | CRITICAL | Exodus wallet data directory (seed phrase theft) |
| IRONWORM-005c | Crypto wallet | HIGH | Atomic wallet directory |
| IRONWORM-006 | Credential file | HIGH | `.npmrc` auth token file read |
| IRONWORM-006b | Env var harvest | CRITICAL | `NPM_AUTH_TOKEN`, `NODE_AUTH_TOKEN` env access |
| IRONWORM-007 | Process injection | CRITICAL | Write to `.github/workflows/` — workflow hijack |

---

## Project Structure

```
oss-trust-framework/
├── oss_trust_framework/            # Installable Python package
│   ├── age_check/
│   │   └── checker.py              # Gate 1 — multi-ecosystem registry timestamp fetching
│   ├── signature/
│   │   └── provenance.py           # Gate 2 — npm/PyPI attestation + publisher repo allowlist
│   ├── cicd_audit/                 # Gate 2.5 — CI/CD pipeline audit (Miasma/IronWorm class)
│   │   ├── orphan_commits.py       # 2.5a — BFS commit graph walk; detects direct pushes
│   │   ├── workflow_permissions.py # 2.5b — dangerous perm detection + compensating controls
│   │   └── pr_provenance.py        # 2.5c — release must trace to reviewed merged PR
│   ├── trust/
│   │   └── aggregator.py           # Gate 3 — concurrent OpenSSF/OSV/deps.dev/GHSA queries
│   ├── sbom/                       # Gate 4 — SBOM delta and hash pinning (stub)
│   ├── sandbox/
│   │   └── behavioral_patterns.py  # Gate 5 — 34 patterns: 18 Miasma + 16 IronWorm
│   ├── zeroday/
│   │   └── validator.py            # CVE machine-validation + quorum approval manager
│   └── pipeline/
│       ├── orchestrator.py         # Full pipeline runner; standard and zero-day routing
│       └── cli.py                  # oss-trust check / zeroday request/approve/status
├── tests/
│   ├── test_age_check.py           # Gate 1: registry API mocks, threshold boundary cases
│   ├── test_cicd_audit.py          # Gate 2.5: orphan, workflow, PR provenance
│   ├── test_behavioral_patterns.py # Gate 5: Miasma + IronWorm patterns + clean baseline
│   └── test_zeroday_quorum.py      # ZD lane: expiry, duplicate vote, MFA, self-approval
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Three gates are implemented as stubs — good first issues:

| Gate | File | What to implement |
|---|---|---|
| 4 — SBOM delta | `src/sbom/differ.py` | syft/cdxgen invocation; CycloneDX JSON diff; lock file hash pinning |
| 5 — Sandbox runner | `src/sandbox/runner.py` | gVisor container launch; install execution; event feed to `behavioral_patterns.evaluate_sandbox_events()` |
| 2 — GPG fallback | `src/signature/gpg.py` | GPG verification for ecosystems not yet on Sigstore |

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
