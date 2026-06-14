# OSS Trust Framework

[![PyPI](https://img.shields.io/pypi/v/oss-trust-framework?color=blue&label=PyPI)](https://pypi.org/project/oss-trust-framework/)
[![Python](https://img.shields.io/pypi/pyversions/oss-trust-framework)](https://pypi.org/project/oss-trust-framework/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — with hardened defenses against CI/CD pipeline compromise (Miasma, Shai-Hulud, TanStack, Bitwarden, IronWorm) and a strictly controlled expedited lane for zero-day CVE patches.

> **v0.6.1 — All gates fully operational.** Multi-ecosystem support: PyPI, npm, Cargo, Go, Maven, NuGet, RubyGems. `oss-trust check-all` available as installed CLI command.

---

## Table of Contents

- [Installation](#installation)
- [Usage Guide](#usage-guide)
  - [Check all deps in a project](#1-check-all-deps-in-a-project-the-most-common-task)
  - [Check a single package](#2-check-a-single-package)
  - [Windows users](#3-windows-users)
  - [CI/CD integration](#4-cicd-integration)
  - [Zero-day expedited lane](#5-zero-day-expedited-lane)
  - [Populate the trusted publishers allowlist](#6-populate-the-trusted-publishers-allowlist)
- [Supported Ecosystems](#supported-ecosystems)
- [Configuration](#configuration)
- [Why This Exists](#why-this-exists)
- [Architecture](#architecture)
- [Gate Reference](#gate-reference)
- [Attack Coverage](#attack-coverage)
- [Running Tests](#running-tests)
- [Contributing](#contributing)

---

## Installation

```bash
pip install oss-trust-framework

# Verify
oss-trust --version
# oss-trust, version 0.6.1
```

> **Windows users:** Set `$env:PYTHONUTF8 = "1"` before running any command, or add it to your PowerShell profile. See [Windows users](#3-windows-users) below.

> **Installing latest dev build from source:**
> ```bash
> pip install "git+https://github.com/chrisgillham/oss-trust-framework.git"
> ```

---

## Usage Guide

### 1. Check all deps in a project (the most common task)

`oss-trust check-all` reads your project's dependency files and runs every package through Gate 1 (age check).

> **Important:** `oss-trust check-all` with no arguments only auto-detects `requirements.txt` and `framework_deps.txt` (Python). For npm, Rust, Ruby, and .NET projects you **must** pass `--manifest` pointing at your lockfile. If you forget, the tool will detect common manifest files in the current directory and tell you the exact command to run.

**npm project:**
```bash
oss-trust check-all --manifest package.json
```

**Python project (`requirements.txt` auto-detected):**
```bash
oss-trust check-all
```

**Rust:**
```bash
oss-trust check-all --manifest Cargo.toml
```

**Ruby:**
```bash
oss-trust check-all --manifest Gemfile.lock
```

**.NET:**
```bash
oss-trust check-all --manifest packages.config
```

**Multiple manifests at once (mixed-stack project):**
```bash
oss-trust check-all --manifest package.json --manifest requirements.txt
```

**Skip dev dependencies (production-only check):**
```bash
oss-trust check-all --prod-only
```

**Non-interactive mode — for CI pipelines:**
```bash
oss-trust check-all --manifest package.json --no-interactive
```

**JSON output — for CI pipelines and reporting:**
```bash
# Linux/Mac
oss-trust check-all --manifest package.json --no-interactive --output json > trust-report.json

# Windows PowerShell (UTF-8 encoding required for redirect)
$env:PYTHONUTF8 = "1"
oss-trust check-all --manifest package.json --no-interactive --output json 2>$null > trust-report.json
```

**Fail the build if any package is in HOLD state:**
```bash
oss-trust check-all --manifest package.json --no-interactive --fail-on-hold
```

**What the output looks like:**

```
OSS Trust Framework - check-all
config: ./config/trusted_publishers.yaml

  package.json -> 9 packages

Running Gate 1 age checks on 9 packages...

All packages are in the trusted_publishers allowlist.

Ecosystem  Package             Version  Allowlist  Age (h)   Gate 1  Outcome
npm        express             4.18.2   check      32261.3   pass    PASS
npm        jsonwebtoken        9.0.2    check       24445.0  pass    PASS
npm        uuid                14.0.0   check       168.2    pass    PASS
...

Summary: 9 packages -- 9 passed  0 on hold  0 blocked  0 errors
```

**What the JSON output looks like (`trust-report.json`):**

```json
[
  {
    "ecosystem": "npm",
    "package": "express",
    "version": "4.18.2",
    "source": "package.json",
    "in_allowlist": true,
    "attestation_required": false,
    "age_hours": 32261.3,
    "gate1_decision": "pass",
    "gate1_message": "express@4.18.2 is 32261.3h old -- age gate cleared.",
    "outcome": "PASS"
  }
]
```

---

### 2. Check a single package

Use this when you want to validate one specific package version before upgrading — especially useful after `npm audit fix --force` or a Dependabot PR.

```bash
# Basic check — Gate 1 (age) only
oss-trust check --package express --version 5.0.0 --ecosystem npm

# Full pipeline check — all gates including provenance and OOB trust
oss-trust check \
  --package requests \
  --version 2.33.0 \
  --ecosystem PyPI \
  --github-repo psf/requests

# npm package with GitHub repo for full gate coverage
oss-trust check \
  --package jsonwebtoken \
  --version 9.0.2 \
  --ecosystem npm \
  --github-repo auth0/node-jsonwebtoken

# Cargo crate
oss-trust check --package serde --version 1.0.200 --ecosystem Cargo

# Maven artifact (use groupId:artifactId format)
oss-trust check \
  --package "org.apache.commons:commons-lang3" \
  --version 3.14.0 \
  --ecosystem Maven
```

**Supported `--ecosystem` values:**
`PyPI` `npm` `Cargo` `Go` `Maven` `NuGet` `RubyGems`

**What a PASS looks like:**
```
Gate 1 (Age):       PASS  — requests@2.33.0 is 1847.2h old
Gate 2 (Provenance): PASS  — published from psf/requests (expected)
Gate 3 (OOB Trust):  PASS  — score 82.5/100, 0 active CVEs
Outcome: APPROVED
```

**What a BLOCK looks like (new release):**
```
Gate 1 (Age): BLOCK — express@5.0.1 is 4.2h old
Hard block threshold is 24h.
File a CVE reference to route through the zero-day expedited lane.
Outcome: BLOCKED
```

**What a HOLD looks like (24-72h window):**
```
Gate 1 (Age): HOLD — cryptography@44.0.1 is 31.5h old
Within the 72h hold window. Human approval required.
Outcome: HOLD
```

---

### 3. Windows users

PowerShell redirects (`>`) default to cp1252 encoding, which can't handle some Unicode characters in Rich terminal output. Set UTF-8 mode first:

```powershell
# For the current session
$env:PYTHONUTF8 = "1"

# Make it permanent (run once)
New-Item -ItemType Directory -Force -Path (Split-Path $PROFILE)
Add-Content $PROFILE "`n`$env:PYTHONUTF8 = '1'"
```

**Redirect stderr away from the JSON output** when saving to a file (the Rich table goes to stderr, JSON goes to stdout):

```powershell
# Save only the JSON, suppress the table display
oss-trust check-all --manifest package.json --output json 2>$null > trust-report.json

# View the JSON report
Get-Content trust-report.json | ConvertFrom-Json | Format-Table ecosystem, package, version, outcome
```

---

### 4. CI/CD integration

**GitHub Actions — auto-runs on any lock file change:**

Add `.github/workflows/dep-trust-check.yml` to your repo:

```yaml
name: Dependency trust check

on:
  pull_request:
    paths:
      - '**/package.json'
      - '**/package-lock.json'
      - '**/requirements.txt'
      - '**/Cargo.toml'
      - '**/Cargo.lock'
      - '**/Gemfile.lock'

jobs:
  trust-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install OSS Trust Framework
        run: pip install oss-trust-framework

      - name: Run trust check
        run: |
          oss-trust check-all \
            --manifest package.json \
            --no-interactive \
            --fail-on-hold \
            --output json > trust-report.json

      - name: Upload trust report
        uses: actions/upload-artifact@v4
        with:
          name: trust-report
          path: trust-report.json
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | All packages passed |
| `1` | One or more packages BLOCKED or (with `--fail-on-hold`) HELD |
| `2` | No packages found to check |

---

### 5. Zero-day expedited lane

When a legitimate zero-day patch drops for a package you depend on, the 72-hour age hold creates a gap. The expedited lane bypasses **only** the age gate — all other gates remain mandatory.

**Step 1 — Request an exception:**
```bash
oss-trust zeroday request \
  --cve CVE-2024-12345 \
  --package cryptography \
  --version 44.0.1 \
  --ecosystem PyPI \
  --requester security@yourorg.com
```

Output:
```
CVE-2024-12345 validated against NVD + OSV + GHSA (2-of-3 sources required)
Quorum request created: request-id abc123def456
Notify approvers: approver_001, approver_002, approver_003
Token TTL: 6 hours
```

**Step 2 — Each approver approves separately (MFA required):**
```bash
oss-trust zeroday approve \
  --request-id abc123def456 \
  --approver-id approver_001 \
  --mfa-token 123456
```

**Step 3 — Check status:**
```bash
oss-trust zeroday status --request-id abc123def456
```

**Rules:**
- Requester cannot approve their own request (separation of duties)
- 2-of-3 named approvers required
- Token expires after 6 hours — no extensions
- More than 3 exceptions in 24 hours suspends the lane pending CISO review

---

### 6. Populate the trusted publishers allowlist

The allowlist maps package names to their canonical GitHub source repo. Gate 2 uses this to verify that a package's provenance attestation points to the right repo — not a compromised fork or employee account (the Miasma attack pattern).

**Interactive population — recommended first step for any project:**
```bash
# Run from your project directory
oss-trust check-all --manifest package.json
```

For any package not in the allowlist, you'll be prompted:
```
express@4.18.2 is not in trusted_publishers.yaml
  Looking up canonical repo... found: expressjs/express

  [1] Add to allowlist only
  [2] Add to allowlist + require_attestation (block if no Sigstore attestation)
  [s] Skip
  [q] Quit interactive mode

  Choice [1/2/s/q]: 1
  Added npm/express: expressjs/express
  config/trusted_publishers.yaml saved.
```

**Auto-populate without prompts (scripts/automation):**
```bash
# In scripts/check_all.py — emit YAML entries for all deps in a manifest
python scripts/check_all.py --populate-allowlist npm package.json
```

Output:
```yaml
# npm trusted_publishers entries
# Generated from package.json

  "express": "expressjs/express"
  "jsonwebtoken": "auth0/node-jsonwebtoken"
  "helmet": "helmetjs/helmet"
  # "acme-client": "FIXME/repo"   <-- couldn't auto-resolve, fill in manually
```

Paste into `config/trusted_publishers.yaml` under the `npm:` section.

**Manual editing of `config/trusted_publishers.yaml`:**
```yaml
npm:
  "express": "expressjs/express"
  "jsonwebtoken": "auth0/node-jsonwebtoken"
  "uuid": "uuidjs/uuid"

PyPI:
  "cryptography": "pyca/cryptography"
  "requests": "psf/requests"

Cargo:
  "serde": "serde-rs/serde"
  "tokio": "tokio-rs/tokio"

require_attestation:        # These packages BLOCK if no Sigstore attestation found
  PyPI:
    - "cryptography"
    - "requests"
  npm:
    - "jsonwebtoken"
```

---

## Supported Ecosystems

| Ecosystem | Registry | Package format | Example |
|-----------|----------|----------------|---------|
| `PyPI` | pypi.org | `package==version` | `requests==2.33.0` |
| `npm` | npmjs.com | `package@version` | `express@4.18.2` |
| `Cargo` | crates.io | `crate@version` | `serde@1.0.200` |
| `Go` | proxy.golang.org | module path | `github.com/gin-gonic/gin` |
| `Maven` | search.maven.org | `groupId:artifactId` | `org.apache.commons:commons-lang3` |
| `NuGet` | nuget.org | `PackageId` | `Newtonsoft.Json` |
| `RubyGems` | rubygems.org | `gem` | `rails` |

**Manifest file auto-detection:**

| File | Ecosystem detected |
|------|--------------------|
| `package.json` | npm |
| `requirements.txt` | PyPI |
| `framework_deps.txt` | Multi (prefix format: `PyPI:requests==2.33.0`) |
| `Cargo.toml` | Cargo |
| `Gemfile.lock` | RubyGems |
| `packages.config` | NuGet |

---

## Configuration

### `config/pipeline.yaml` — gate thresholds

```yaml
age_gate:
  hard_block_hours: 24      # Releases younger than this: auto-blocked
  hold_hours: 72            # 24-72h: human approval required before proceeding

trust_scoring:
  min_scorecard_score: 6.0  # OpenSSF Scorecard minimum (0-10 scale)
  require_zero_active_vulns: true

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
  runtime: gvisor            # gvisor | strace | audit
  network: none
  behavioral_patterns:
    block_on_critical: true

zero_day:
  required_approvers: 2
  token_ttl_hours: 6
  circuit_breakers:
    max_exceptions_per_24h: 3
```

### `config/trusted_publishers.yaml` — per-package allowlist

See [Populate the trusted publishers allowlist](#6-populate-the-trusted-publishers-allowlist) above. The full pre-populated allowlist covering 100+ high-value packages across all 7 ecosystems ships with the framework at `config/trusted_publishers.yaml`.

---

## Why This Exists

Three distinct supply chain attack patterns are defeating traditional defenses right now:

**Pattern 1 — Speed attacks.** A compromised maintainer account publishes a malicious release. Automated dependency tooling (Dependabot, Renovate, npm update) ingests it within minutes. The attacker wins the race against community detection and revocation.

**Pattern 2 — CI/CD pipeline compromise (Miasma class).** An attacker compromises a legitimate employee's GitHub account, pushes orphan commits bypassing PR review, and exploits `id-token: write` CI/CD permissions to publish via OIDC trusted publishing. The packages are *correctly signed* — the signature is real. Traditional signature verification passes completely.

**Pattern 3 — Rust-based infostealer worms (IronWorm class).** A malicious binary is dropped via a package `preinstall` hook. It hides behind an eBPF kernel rootkit, harvests 86+ environment variables including AI API keys (OpenAI, Anthropic), cloud credentials, SSH keys, and cryptocurrency wallet seed phrases, then beacons to a Tor hidden service. It self-propagates by using stolen npm OIDC credentials to publish trojanized versions of victim-owned packages. Hash-based IOCs are useless — IronWorm generates unique encrypted payloads per infection.

### Active attacks

| Attack | Date | Packages | Vector | Status |
|---|---|---|---|---|
| **Miasma / Red Hat Insights** | 2026 | 32 npm | Compromised employee account + OIDC trusted publishing | Active campaign |
| **IronWorm** | 2026-06-03 | 36 npm | Rust ELF preinstall hook + eBPF rootkit + Tor C2 | Active campaign |
| **TanStack** | 2026 | 170 npm | Same OIDC trusted publishing pattern | Active campaign |
| **Bitwarden CLI** | 2026 | npm | Checkmarx campaign — OIDC trusted publishing | Active campaign |
| **XZ Utils** | 2024 | tarball | 2-year social engineering -> build script backdoor | CVSS 10.0 |

---

## Architecture

```
Dependency update request
        |
        v
+----------------------+   Name >= 92% similar to trusted pkg --> BLOCKED   <-- postmark-mcp-evil
|  Gate 0: Name        |   Name >= 80% similar --> WARN (manual review)
|  Similarity Check    |   Exact allowlist match --> pass immediately
|  (local, no network) |   3 algorithms: Levenshtein, prefix, char-swap
+----------+-----------+
           |
           v
+----------------------+   < 24 h, no CVE --> BLOCKED
|  Gate 1: Age Hold    |
|  24 h hard block     |   Zero-day CVE filed? --> Expedited Lane ----------+
|  72 h soft hold      |                                                     |
+----------+-----------+                                                     |
           | >= 24 h                                                         |
           v                                                                 |
+----------------------+   Repo mismatch --> BLOCKED   <-- Miasma/IronWorm  |
|  Gate 2: Provenance  |   No attestation --> QUARANTINE                    |
|  Attestation +       |   (sourceRepositoryURI vs trusted_publishers.yaml) |
|  Publisher Allowlist |                                                     |
+----------+-----------+                                                     |
           |                                                                 |
           v                                                                 |
+----------------------+   Orphan commit --> BLOCKED   <-- Miasma/IronWorm  |
|  Gate 2.5: CI/CD     |   id-token:write --> QUARANTINE                    |
|  Pipeline Audit      |   No PR review --> BLOCKED                         |
+----------+-----------+                           <-- Rejoins here --------+
           |
           v
+----------------------+   Score < threshold --> QUARANTINE
|  Gate 3: Out-of-Band |   Active CVE --> QUARANTINE
|  Trust Aggregation   |   (OpenSSF, OSV, deps.dev, GHSA)
+----------+-----------+
           |
           v
+----------------------+   New transitive dep --> QUARANTINE
|  Gate 4: SBOM Delta  |   Hash mismatch --> QUARANTINE
+----------+-----------+
           |
           v
+----------------------+   Tor C2 --> BLOCKED       <-- IronWorm: exfil
|  Gate 5: Behavioral  |   eBPF rootkit --> BLOCKED  <-- IronWorm: rootkit
|  Sandbox             |   AI API key harvest --> BLOCKED
|  34 patterns active  |   Cloud cred harvest --> BLOCKED
+----------+-----------+
           |
           v
    +--------------+
    | Staged Rollout| --> APPROVED
    | 72 h canary  |
    +--------------+
```

---

## Gate Reference

| Gate | Controls | Fail action | Bypassable? |
|---|---|---|---|
| **0 — Name similarity** | Package name vs trusted allowlist — Levenshtein, prefix-addition, char-swap detection | Warn (>=80%) · Block (>=92%) | No |
| **1 — Age** | Release timestamp vs 24 h / 72 h thresholds | Block / Hold | Age only — with CVE + MFA quorum |
| **2 — Provenance** | Sigstore attestation present; `sourceRepositoryURI` matches allowlist | Block (mismatch) · Quarantine (missing) | No |
| **2.5a — Orphan commits** | Release tag commit reachable from default branch via BFS graph walk | Block | No |
| **2.5b — Workflow permissions** | `id-token: write` in publishing workflow without compensating controls | Quarantine | No |
| **2.5c — PR provenance** | Release backed by merged PR with >= 1 approving reviewer | Block (no PR) · Quarantine (no review) | No |
| **3 — OOB Trust** | OpenSSF Scorecard >= threshold; zero active CVEs via OSV + deps.dev + GHSA | Quarantine | No |
| **4 — SBOM delta** | No unexpected transitive deps; lock file hash unchanged | Quarantine | No |
| **5 — Behavioral sandbox** | gVisor/strace install-time execution; 34 named behavioral patterns (18 Miasma + 16 IronWorm) | Block | No |

---

## Attack Coverage

### Miasma / Shai-Hulud — Red Hat Insights (2026)

| Attack step | Gate | Mechanism |
|---|---|---|
| Orphan commit pushed, bypassing PR | **2.5a** | BFS walk; tag commit unreachable from main -> BLOCK |
| No code review on malicious commit | **2.5c** | No merged PR -> DIRECT_PUSH -> BLOCK |
| `id-token: write` exploited for OIDC publish | **2.5b** | Dangerous perm + no env protection -> QUARANTINE |
| Published from employee fork, not canonical org | **2** | `sourceRepositoryURI` mismatch -> BLOCK |
| Cloud credential harvesting (GCP/Azure IMDS) | **5** | MIASMA-001/002: IMDS network events -> BLOCK |
| OIDC token requested from install context | **5** | MIASMA-010: `token.actions.githubusercontent.com` -> BLOCK |
| Re-publish to npm from install script | **5** | PUBLISH-001: PUT to `registry.npmjs.org` -> BLOCK |

### IronWorm — asteroiddao / Arweave ecosystem (JFrog, 2026-06-03)

| Attack step | Gate | Mechanism |
|---|---|---|
| Published from compromised `asteroiddao` account | **2** | `sourceRepositoryURI` mismatch -> BLOCK |
| Orphan commits with backdated timestamps | **2.5a** | Graph reachability — timestamps irrelevant -> BLOCK |
| Rust ELF binary dropped via `preinstall` hook | **5** | IRONWORM-002b: `tools/setup` process event -> BLOCK |
| eBPF kernel rootkit load | **5** | IRONWORM-002: `BPF_PROG_LOAD` syscall -> BLOCK |
| AI API key harvest (OpenAI, Anthropic, Gemini) | **5** | IRONWORM-003: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` -> BLOCK |
| AWS / GCP / Azure / Vault credential theft | **5** | CRED-003/004 + IRONWORM-004 -> BLOCK |
| Tor hidden service C2 beacon | **5** | IRONWORM-001: `.onion` network event -> BLOCK |
| npm token theft for self-propagation | **5** | IRONWORM-006/006b: `.npmrc` read + `NPM_AUTH_TOKEN` -> BLOCK |

---

## Zero-Day Lane Circuit Breakers

| Condition | Action |
|---|---|
| > 3 exception requests in 24 hours | Lane suspended pending CISO review |
| Same requester files two exceptions within 48 hours | Second request escalates to CISO sign-off |
| Any exception-deployed package receives a new CVE within 30 days | Lane suspended; retrospective triggered |

Exception tokens expire after 6 hours. Re-approval required — no extensions.

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

# With coverage
pytest --cov=oss_trust_framework --cov-report=term-missing
```

All external API calls (PyPI, OSV, OpenSSF, GitHub) are mocked — tests run fully offline.

---

## OWASP Top 10 CI/CD Security Risks Coverage

| Risk | Framework coverage | Gates |
|---|---|---|
| **CICD-SEC-1** Insufficient Flow Control | Age gate enforces mandatory hold. Zero-day lane requires CVE + 2-of-3 MFA quorum. No individual can accelerate unilaterally. | Gate 1, ZD lane |
| **CICD-SEC-2** Inadequate IAM | Gate 2.5b audits `id-token: write`. Gate 2.5c enforces reviewer counts. ZD quorum enforces separation of duties. | Gates 2.5b, 2.5c, ZD lane |
| **CICD-SEC-3** Dependency Chain Abuse | Core mission. Gates 1-5 validate every dependency update. | Gates 1-5 |
| **CICD-SEC-4** Poisoned Pipeline Execution | Gate 2.5a detects orphan commits. Gate 2.5c confirms PR review. Gate 2.5b flags dangerous permissions. | Gates 2.5a, 2.5b, 2.5c |
| **CICD-SEC-5** Insufficient PBAC | Gate 2.5b enforces pipeline-based access controls on publishing workflows. | Gate 2.5b |
| **CICD-SEC-6** Insufficient Credential Hygiene | Gate 5 detects credential harvesting at install time (AWS/GCP/Azure, Vault, npm, AI API keys). | Gates 2, 5 |
| **CICD-SEC-7** Insecure System Configuration | Gate 2.5b checks for missing branch protection, CODEOWNERS, environment protection rules. | Gate 2.5b |
| **CICD-SEC-8** Ungoverned 3rd Party Services | Gate 3 queries OpenSSF, OSV, deps.dev, GHSA independently. Gate 4 SBOM delta catches unexpected transitive deps. | Gates 3, 4 |
| **CICD-SEC-9** Improper Artifact Integrity | Gate 2 verifies Sigstore/GPG signatures and `sourceRepositoryURI`. Gate 4 pins hashes. Gate 2.5a verifies tag reachability. | Gates 2, 2.5a, 4 |
| **CICD-SEC-10** Insufficient Logging | Every gate decision emits a structured SIEM event. Zero-day exceptions require ticket linkage. Full non-repudiable audit trail. | All gates, ZD lane |

---

## Project Structure

```
oss-trust-framework/
+-- oss_trust_framework/            # Installable Python package (pip install oss-trust-framework)
|   +-- check_all.py                # oss-trust check-all command
|   +-- name_similarity/checker.py  # Gate 0 -- typosquat detection
|   +-- age_check/checker.py        # Gate 1 -- multi-ecosystem age check
|   +-- signature/provenance.py     # Gate 2 -- Sigstore attestation + allowlist
|   +-- cicd_audit/                 # Gate 2.5 -- CI/CD pipeline audit
|   +-- trust/aggregator.py         # Gate 3 -- OpenSSF/OSV/deps.dev/GHSA
|   +-- sbom/differ.py              # Gate 4 -- SBOM delta + hash pin
|   +-- sandbox/                    # Gate 5 -- behavioral sandbox (34 patterns)
|   +-- zeroday/validator.py        # CVE validation + quorum approval
|   +-- pipeline/orchestrator.py    # Full pipeline runner
|   +-- cli.py                      # oss-trust CLI entry point
+-- scripts/check_all.py            # Multi-ecosystem batch checker (all 7 registries)
+-- check_all.py                    # Repo-root shim (python check_all.py)
+-- config/
|   +-- pipeline.yaml               # Gate thresholds and circuit breakers
|   +-- trusted_publishers.yaml     # Publisher allowlist (100+ packages, 7 ecosystems)
+-- requirements.txt                # Framework runtime deps (pinned, Dependabot-clean)
+-- framework_deps.txt              # Self-validation dep declarations
+-- tests/                          # 131 tests, all offline
+-- docs/index.html                 # Full documentation site
+-- .github/workflows/
    +-- dep-trust-check.yml         # PR gate: auto-runs on lock file changes
    +-- publish.yml                 # PyPI publish on GitHub Release
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

All PRs must pass the framework's own CI gate (`dep-trust-check.yml`). Zero-day lane changes require CISO sign-off.

Contributions welcome — open issues for feature requests, additional behavioral patterns, or ecosystem support.

---

## Supply chain integrity vs runtime monitoring

The framework validates dependencies **before they enter your environment**. It is not a runtime security monitor.

| Threat | Covered? | If not, use |
|---|---|---|
| Malicious install script (IronWorm preinstall hook) | Gate 5 | — |
| Compromised publisher account (Miasma) | Gates 2, 2.5, 5 | — |
| Typosquat / impersonation | Gate 0 | — |
| Known CVE in dependency | Gate 3 | — |
| Runtime exfiltration (MCP server BCC'ing email) | No | Falco, Tetragon |
| Deferred activation (beacons after condition met) | No | Runtime monitoring |
| Semantic impersonation (low string similarity) | No | Manual allowlist review |

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
