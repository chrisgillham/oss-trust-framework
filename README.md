# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A world-class, multi-layer security framework that validates open source dependency updates across their entire lifecycle — from the first PR gate through post-deployment runtime monitoring — with a hardened expedited lane for zero-day CVE patches, a Discord-based human quorum override, continuous runtime telemetry, and a policy-as-code governance engine.

**Author:** Chris Gillham

> **This framework augments a mature dependency security posture. It does not replace one.** See [Prerequisite best practices](#prerequisite-best-practices) for the baseline controls that must be in place regardless of this framework.

---

## Table of Contents

- [The problem](#the-problem)
- [Architecture overview](#architecture-overview)
- [Validation pipeline](#validation-pipeline)
  - [Nine-gate architecture](#nine-gate-architecture)
  - [Zero-day expedited lane](#zero-day-expedited-lane)
  - [Gate reference](#gate-reference)
  - [Zero-day lane circuit breakers](#zero-day-lane-circuit-breakers)
  - [Out-of-band trust sources](#out-of-band-trust-sources)
- [Trust scoring](#trust-scoring)
  - [Score computation](#score-computation)
  - [Historical reputation modifier](#historical-reputation-modifier)
  - [Score bands](#score-bands)
- [Transitive dependency coverage](#transitive-dependency-coverage)
- [Reachability analysis](#reachability-analysis)
- [SLSA provenance enforcement](#slsa-provenance-enforcement)
- [License compliance gate](#license-compliance-gate)
- [CI/CD pipeline self-auditing](#cicd-pipeline-self-auditing)
- [AI hallucination detection](#ai-hallucination-detection)
- [Policy-as-code governance](#policy-as-code-governance)
- [Runtime telemetry and post-merge monitoring](#runtime-telemetry-and-post-merge-monitoring)
- [Public trust registry](#public-trust-registry)
- [Developer feedback loop](#developer-feedback-loop)
- [Notification platform](#notification-platform)
  - [Discord](#discord)
  - [MS Teams](#ms-teams)
  - [Slack](#slack)
  - [Choosing a platform](#choosing-a-platform)
- [Discord quorum override](#discord-quorum-override)
  - [Quorum architecture](#quorum-architecture)
  - [Discord vote flow](#discord-vote-flow)
  - [Voting rules](#voting-rules)
  - [Quorum math](#quorum-math)
  - [Audit log](#audit-log)
- [CI/CD integration](#cicd-integration)
  - [GitHub Actions workflow](#github-actions-workflow)
  - [Workflow jobs](#workflow-jobs)
  - [PR check flow](#pr-check-flow)
- [Setup guide](#setup-guide)
  - [1. Create the Discord bot](#1-create-the-discord-bot)
  - [2. Set up Google Sheets audit log](#2-set-up-google-sheets-audit-log)
  - [3. Configure quorum members](#3-configure-quorum-members)
  - [4. Configure policy-as-code](#4-configure-policy-as-code)
  - [5. Add GitHub secrets](#5-add-github-secrets)
  - [6. Add repository files](#6-add-repository-files)
- [Configuration reference](#configuration-reference)
- [Trust outcomes](#trust-outcomes)
- [Project structure](#project-structure)
- [Compliance mapping](#compliance-mapping)
- [Troubleshooting](#troubleshooting)
- [Prerequisite best practices](#prerequisite-best-practices)
- [Contributing](#contributing)
- [References](#references)

---

## The problem

Malicious packages depend on speed. A compromised maintainer account publishes a malicious release; automated dependency tooling ingests it within minutes. The attacker wins before anyone notices.

Traditional tools address part of this. CVE scanners catch known vulnerabilities — but most supply chain attacks arrive before any CVE exists. Signature checks verify the publisher — but don't tell you if the publisher's account was hijacked. Sandbox tests catch install-time behavior — but not runtime exfiltration that activates after deployment. And every existing tool stops at the gate: once a package is approved, it disappears from view.

This framework addresses the full lifecycle: it breaks the attacker's speed advantage with nine mandatory validation gates and a configurable age hold, provides a strictly controlled bypass for legitimate zero-day patches, gates flagged packages behind a human quorum with full auditability, and then continues monitoring approved packages after deployment through runtime telemetry and SIEM correlation.

---

## Architecture overview

```
Developer opens PR with dependency change
                │
                ▼
    ┌───────────────────────┐
    │  Nine-gate pipeline   │ ← transitive + direct scope
    │  (automated)          │
    └──────────┬────────────┘
               │
    ┌──────────▼────────────┐
    │  Reachability filter  │ ← quarantine → hold if unreachable
    └──────────┬────────────┘
               │
    ┌──────────▼────────────┐
    │  Policy-as-code       │ ← conditional quorum thresholds,
    │  evaluation           │   CISO escalation, license policy
    └──────────┬────────────┘
               │
      ┌────────┴─────────┐
      │                  │
   APPROVED           BLOCKED / QUARANTINED
      │                  │
      ▼                  ▼
  Post-merge         Discord quorum
  runtime            (configurable
  telemetry          majority vote)
      │                  │
      ▼              ┌───┴──────────┐
  SIEM events    APPROVED        DENIED
      │              │               │
      ▼              ▼               ▼
  30-day        Runtime          Audit log
  monitoring    telemetry        + PR blocked
  window        continues
```

---

## Validation pipeline

### Nine-gate architecture

The original five gates have been expanded to nine, adding SLSA provenance, reachability, license compliance, and CI/CD self-auditing as first-class gates.

```
Dependency update request (direct + transitive scope)
        │
        ▼
┌───────────────────┐     < 24 h, no CVE ──► BLOCKED
│  Gate 1: Age      │
│  < 72 h hold      │     Zero-day CVE? ──► Expedited Lane (see below)
└────────┬──────────┘
         │ ≥ 24 h
         ▼
┌───────────────────┐
│  Gate 2: Sig      │     Mismatch / weak ──► REJECTED
│  Sigstore / GPG   │
│  SLSA level ≥ min │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 3: SLSA     │     SLSA 0 in critical path ──► QUARANTINE
│  Provenance       │     SLSA < configured min ──► HOLD
│  Attestation      │ ◄── Zero-day lane rejoins here
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 4: OOB      │     Score low ──► QUARANTINE
│  OpenSSF/OSV/     │
│  deps.dev / Socket│
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 4.5:        │     Not reachable ──► downgrade QUARANTINE → HOLD
│  Reachability     │     (avoids false-positive quorum triggers)
│  Analysis         │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 5: License  │     License change or non-allowlist ──► HOLD / BLOCK
│  SPDX compliance  │
│  + change detect  │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 6: SBOM     │     New transitive deps ──► QUARANTINE
│  delta (recursive)│     Hash mismatch ──► REJECTED
│  + hash pin       │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 7: Sandbox  │     Malicious behavior ──► BLOCKED
│  gVisor / no net  │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 8: AI       │     Hallucinated name match ──► BLOCKED
│  Hallucination    │     LLM-fabricated package ──► BLOCKED
│  Detection        │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 9: CI/CD    │     Tag-pinned action ──► QUARANTINE
│  Pipeline Audit   │     New third-party action ──► HOLD
│  (self-check)     │
└────────┬──────────┘
         │
         ▼
    Staged rollout ──────────────────────────────► APPROVED
         │
         ▼
    Runtime telemetry begins (30-day monitoring window)
```

### Zero-day expedited lane

Bypasses the **age gate only**. All other gates remain mandatory.

```
CVE validated (NVD + OSV + GHSA, 2-of-3 sources)
        │
        ▼
Quorum approval (2-of-3 named approvers, MFA required, requester excluded)
        │
        ▼
SLSA provenance check (signed after CVE publication timestamp)
        │
        ▼
Signature + timing check
        │
        ▼
Reachability check (is the patched function actually called?)
        │
        ▼
Isolated sandbox (gVisor, no network)
        │
        ▼
License delta check (ensure patch doesn't change license)
        │
        ▼
Audit record (SIEM event + ticket link mandatory)
        │
        ▼
Rejoin at Gate 3 (out-of-band trust)
        │
        ▼
Immediate full-fleet deploy + 48 h elevated alert window
        │
        ▼
Runtime telemetry active for 30 days post-deploy
```

### Gate reference

| Gate | What it checks | Fail action | Bypassable? |
|---|---|---|---|
| 1 — Age | Release timestamp vs configurable thresholds | Block / Hold | Yes, with CVE + quorum |
| 2 — Signature | Sigstore transparency log / GPG key + strength | Reject | No |
| 3 — SLSA Provenance | SLSA level vs configured minimum; critical-path enforcement | Quarantine / Hold | No |
| 4 — OOB Trust | OpenSSF Scorecard, OSV, deps.dev, Socket behavioral analysis | Quarantine | No |
| 4.5 — Reachability | Whether flagged code paths are actually called by this application | Downgrade to Hold | N/A (reduces false positives) |
| 5 — License | SPDX identifier against allowlist; license change vs prior version | Hold / Block | No |
| 6 — SBOM delta | Recursive transitive dependency diff + hash pinning | Quarantine / Reject | No |
| 7 — Sandbox | Install-time behavior in isolated gVisor/Firecracker VM | Block | No |
| 8 — AI Hallucination | Package name against known-hallucinated name registry | Block | No |
| 9 — CI/CD Audit | Actions pinned to commit SHAs; new third-party action detection | Quarantine / Hold | No |

### Zero-day lane circuit breakers

The expedited lane automatically suspends under these conditions:

- More than 3 exception requests in a 24-hour window
- Same requester files two exceptions within 48 hours (escalates to CISO)
- Any exception-deployed package receives a new CVE within 30 days
- Runtime telemetry fires an anomaly alert within the 48-hour elevated window
- Monthly retrospective finds process violations

### Out-of-band trust sources

Gate 4 queries these sources independently of the package repository:

| Source | API | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Security hygiene score (0–10) |
| deps.dev (Google) | `api.deps.dev` | Full transitive dependency graph, advisories |
| OSV.dev | `api.osv.dev` | Cross-ecosystem CVE database |
| GitHub Advisories | `api.github.com/advisories` | Manually reviewed, high signal |
| Socket.dev | `api.socket.dev` | Behavioral / malware-specific analysis |
| npm Advisory DB | Built into `npm audit` | npm-specific compromise history |

---

## Trust scoring

### Score computation

The trust score is a 0–100 composite drawn from eight signal categories. It drives the embed color and band shown to quorum voters, and is persisted in the audit log for trend analysis and historical reputation.

**Deductions applied to the base score of 100 (cumulative, floor at 0):**

*Cryptographic integrity*

| Condition | Deduction |
|---|---|
| No cryptographic signature | −40 |
| Signature present but weak algorithm (RSA < 3072-bit, SHA-1, GPG without transparency log) | −20 |
| Signature present but verification failed | −10 |
| No published checksum, or checksum mismatch | −15 |

*Provenance and SLSA*

| Condition | Deduction |
|---|---|
| SLSA level 0 (no provenance) in a critical dependency position | −30 |
| SLSA level 0 (non-critical path) | −15 |
| SLSA level 1–2 (provenance present but not hermetic build) | −5 |
| SLSA level 3+ | No deduction |

*Supply-chain flags*

| Condition | Deduction |
|---|---|
| Typosquatting — package name closely resembles a known popular package | −25 |
| Behavioral change — new version requests permissions or network access not present in prior version | −20 |
| Author reputation — new or changed maintainer, or sudden activity surge after long inactivity | −15 |
| Provenance/activity — no verifiable commit history or SLSA attestation | −10 |
| AI hallucination flag — name matches known LLM-fabricated package list | −30 |

*License*

| Condition | Deduction |
|---|---|
| License changed between versions (any direction) | −15 |
| License not on organizational allowlist | −25 |
| License changed to copyleft (MIT → GPL, etc.) | −35 |

### Historical reputation modifier

Every package evaluation starts at 100. But packages with a prior history of quorum events in the audit log receive an automatic adjustment before any signal deductions are applied, creating organizational memory:

| Prior event | Adjustment |
|---|---|
| Previous DENIED quorum vote (any version) | −15 |
| Previous EXPIRED quorum vote (deadline passed) | −10 |
| Previous BLOCKED outcome that required quorum | −10 |
| 2+ prior quorum events for this package | Additional −10 |
| Prior APPROVED quorum with no subsequent runtime anomaly | +5 |

The historical modifier queries the Google Sheets audit log at evaluation time and is logged in the `trust_deductions` column alongside signal-based deductions, making it fully auditable.

### Score bands

| Band | Score | Embed color | Quorum behavior |
|---|---|---|---|
| 🟢 HIGH | 80–100 | Green | Standard threshold (configurable, default >50%) |
| 🟡 MEDIUM | 50–79 | Amber | Standard threshold |
| 🔴 LOW | 0–49 | Red | Policy-as-code can require elevated threshold (e.g. 3-of-5) |

---

## Transitive dependency coverage

All nine gates operate on both **direct** and **transitive** dependencies introduced by a package update. This is the most common blind spot in existing tools — a single innocent-looking direct dependency upgrade can silently introduce dozens of new transitive packages with no scrutiny.

Gate 6 (SBOM delta) computes a recursive diff between the full dependency tree before and after the update, and flags:

- Any new transitive package not present in the prior lockfile
- Any transitive package whose hash has changed without a version bump (silent replacement attack)
- Any transitive package that itself has a trust score below the configured minimum

New transitive packages introduced by an update are each individually evaluated through Gates 3, 4, 4.5, and 5 before the direct package is allowed to proceed. A clean direct package that pulls in a malicious transitive package fails the same as if the direct package itself were malicious.

**Configuration:**

```yaml
sbom:
  recursive: true                 # Evaluate full transitive tree (default: true)
  max_transitive_depth: 10        # How deep to recurse (default: 10)
  new_transitive_action: quarantine  # quarantine | hold | block
  min_transitive_trust_score: 50  # Transitive packages below this score block the parent
```

---

## Reachability analysis

Gate 4.5 sits between OOB Trust and License, and is the primary mechanism for avoiding alert fatigue. When Gate 4 returns a QUARANTINE outcome, reachability analysis asks: is the flagged vulnerable code path actually callable from this application's active execution paths?

If the answer is no — the vulnerable function exists in a sub-dependency but is never reached by any application code path — the outcome is **downgraded from QUARANTINE to HOLD**. The package is still flagged and logged, but does not trigger a full quorum vote. Voters see a HOLD with a reachability note rather than a QUARANTINE requiring a majority decision.

This matters because a typical enterprise application may have thousands of reported dependency vulnerabilities of which only a small fraction affect code that actually executes. Without reachability filtering, every one of those would trigger a quorum vote — killing adoption through fatigue.

**Integration:** Gate 4.5 integrates with Endor Labs, Snyk Reachability, or Contrast SCA via configurable adapter. A call graph of the application is generated at build time and cached; the reachability check queries this graph against the specific vulnerable function identifier from the OSV advisory.

```yaml
reachability:
  enabled: true
  adapter: endor_labs        # endor_labs | snyk | contrast | none
  cache_ttl_hours: 24        # Rebuild call graph if older than this
  on_unreachable: hold       # Downgrade QUARANTINE → HOLD when not reachable
  on_adapter_failure: quarantine  # Fail behavior if reachability service is unavailable
```

---

## SLSA provenance enforcement

Gate 3 evaluates SLSA (Supply Chain Levels for Software Artifacts) provenance attestations as a first-class gate. SLSA level is not just an informational field — it directly affects the trust score and the gate outcome.

**SLSA level requirements by dependency criticality:**

| Dependency class | Minimum SLSA level | Below minimum → |
|---|---|---|
| Authentication / authorization | SLSA 3 | QUARANTINE |
| Cryptography / TLS | SLSA 3 | QUARANTINE |
| Data serialization / parsing | SLSA 2 | HOLD |
| General utility | SLSA 1 | HOLD |
| Dev tooling (not in production build) | SLSA 0 | Advisory only |

Critical dependency classes are configured in `pipeline.yaml`. Packages not matching any class default to the General utility requirement.

**Why this matters:** A SLSA 4 artifact can be built from SLSA 0 dependencies — the main artifact's high provenance level does not flow through to its dependencies. This gate closes that gap by requiring verifiable build provenance independently for each dependency.

```yaml
slsa:
  critical_packages:
    - pattern: "*auth*"
      min_level: 3
    - pattern: "*crypto*"
      min_level: 3
    - pattern: "*tls*"
      min_level: 3
    - pattern: "*jwt*"
      min_level: 3
  default_min_level: 1
  on_missing_attestation: quarantine
```

---

## License compliance gate

Gate 5 compares SPDX license identifiers against an organizational allowlist and detects license changes between versions. License risk is a supply-chain attack vector that most security tools ignore entirely — a dependency upgrade that changes from MIT to GPL-3.0 can create open-source obligations your legal team doesn't know about, and a Commons Clause addition can invalidate commercial use.

**Gate 5 checks:**

- SPDX identifier of the new version against the allowlist
- SPDX identifier of the new version vs prior version (change detection)
- Copyleft escalation (permissive → copyleft triggers stronger action)
- Commons Clause or SSPL presence (commercial-use restrictions)

```yaml
license:
  allowlist:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - 0BSD
  warn_on_change: true        # Notify even if new license is on allowlist
  block_copyleft: true        # GPL-2.0, GPL-3.0, AGPL-3.0 → BLOCKED
  block_commercial_restrict: true  # Commons Clause, SSPL → BLOCKED
  on_unlicensed: block        # Package has no license identifier
```

---

## CI/CD pipeline self-auditing

Gate 9 turns the framework on itself — auditing the GitHub Actions workflows in `.github/workflows/*.yml` of the consuming repository for supply-chain vulnerabilities in the CI/CD pipeline itself.

The SolarWinds and Codecov attacks both compromised the build pipeline, not the source code. A repository can have every dependency gated perfectly while still being vulnerable to a malicious GitHub Action pinned to a mutable tag rather than a commit SHA.

**Gate 9 checks:**

- All `uses:` references in workflow files are pinned to a full 40-character commit SHA, not a branch or version tag
- Any newly introduced third-party action (not in the prior approved action inventory) is flagged as HOLD pending review
- Actions from owners with no verified identity are flagged
- `pull_request_target` workflows with write permissions are flagged (common privilege escalation pattern)

```yaml
cicd_audit:
  enabled: true
  require_sha_pinning: true        # Flag any action not pinned to a commit SHA
  new_action_action: hold          # hold | quarantine for new third-party actions
  approved_action_inventory: .github/approved-actions.json
  flag_pull_request_target: true
```

**Approved action inventory** (`.github/approved-actions.json`):
```json
{
  "approved": [
    {
      "action": "actions/checkout",
      "sha": "11bd71901bbe5b1630ceea73d27597364c9af683",
      "approved_by": "security-team",
      "approved_at": "2026-01-15"
    }
  ]
}
```

---

## AI hallucination detection

Gate 8 addresses a threat that no existing framework currently gates on explicitly: AI coding assistants hallucinating package names that don't exist, which attackers then squat on and publish with malicious content.

LLMs have documented patterns of fabricating package names — particularly for niche utilities, hyphenated name variants, and framework-specific helpers. When a developer asks an AI assistant for a package recommendation and the assistant invents a name, that name often matches something an attacker has pre-registered precisely to catch this pattern.

**Gate 8 checks:**

- Package name against a community-maintained registry of documented LLM-hallucinated package names (updated daily via OSS feed)
- Package name against a similarity check vs known hallucination patterns (e.g. adding `-utils`, `-helper`, `-lib` suffixes to known package names)
- Package age < 90 days with zero prior download history (consistent with squatted hallucination targets)
- Package name that is a valid-but-nonexistent variant of a top-1000 package by download count

```yaml
ai_hallucination:
  enabled: true
  hallucination_registry_url: https://api.oss-trust.dev/hallucinations  # community feed
  similarity_threshold: 0.85      # Name similarity to known packages that triggers flag
  new_package_age_days: 90        # Flag packages newer than this with no download history
  on_confirmed_hallucination: block
  on_suspected: quarantine
```

---

## Policy-as-code governance

The quorum system is no longer a single threshold configured in a JSON file. Policy-as-code allows organizations to express conditional quorum policy that responds to trust signals, package criticality, and organizational role requirements — making the human gate enterprise-governance-ready.

**`policy.yaml`:**

```yaml
# OSS Trust Framework — Policy-as-Code
# Evaluated after trust scoring, before quorum is triggered.

quorum_policy:

  # Default: simple majority of configured members
  default:
    threshold: 0.5
    deadline_hours: 24

  # Escalate to elevated threshold for LOW trust scores
  low_trust_override:
    condition: trust_score < 30
    threshold: 0.75              # 3-of-4, not simple majority
    deadline_hours: 12
    require_members:             # Named individuals must be in the approving set
      - CISO_DISCORD_ID
    notify_additional:           # Notify but don't require vote from
      - LEGAL_DISCORD_ID

  # Critical dependency classes require named approvers
  critical_path_override:
    condition: slsa_level < 3 AND dependency_class IN [auth, crypto, tls]
    threshold: 0.67
    require_members:
      - SECURITY_ARCH_DISCORD_ID
      - CISO_DISCORD_ID
    deadline_hours: 8

  # License changes always notify legal regardless of trust score
  license_change_notify:
    condition: license_changed == true
    notify_additional:
      - LEGAL_DISCORD_ID
    threshold: 0.5               # Voting threshold unchanged

  # Runtime anomaly escalation: if a previously approved package fires
  # a SIEM alert, re-open quorum with elevated requirements
  runtime_anomaly_escalation:
    condition: runtime_anomaly == true AND days_since_approval < 30
    threshold: 1.0               # Unanimous revocation required
    require_members:
      - CISO_DISCORD_ID
      - SECURITY_ARCH_DISCORD_ID
    deadline_hours: 4
    action_on_approval: revoke_package  # Trigger automated rollback
```

**Compliance output:** Policy-as-code evaluation results are logged with every audit row, enabling automated evidence generation for SOC 2 (CC6.1, CC6.8), ISO 27001 (A.12.6, A.14.2), NIST SSDF (PW.4, PS.2), and FedRAMP SA-12.

---

## Runtime telemetry and post-merge monitoring

The framework does not stop at the gate. Once a package is approved and merged, a 30-day monitoring window opens. The SIEM HEC endpoint (already wired into the workflow) receives structured events throughout this window, enabling correlation of runtime anomalies against the quorum audit trail.

### Telemetry events emitted

| Event | When emitted | SIEM fields |
|---|---|---|
| `PACKAGE_APPROVED` | On merge after quorum APPROVED | package, version, quorum_id, trust_score, approvers |
| `PACKAGE_DEPLOYED` | On production deploy (webhook) | package, version, environment, deploy_id |
| `MONITORING_WINDOW_OPEN` | 0h after deploy | package, version, window_expires_at |
| `RUNTIME_ANOMALY_DETECTED` | When SIEM correlates anomaly | package, version, anomaly_type, severity |
| `MONITORING_WINDOW_CLOSED` | 30 days after deploy | package, version, anomaly_count, clean |
| `QUORUM_REOPENED` | If anomaly triggers policy escalation | package, version, original_quorum_id, escalation_reason |

### SIEM correlation rules (Splunk / Elastic / Sentinel)

The framework ships example correlation rules that link:

- Outbound network connections from processes loaded from approved-but-new packages → `RUNTIME_ANOMALY_DETECTED`
- Credential file access (`~/.aws/`, `/etc/passwd`, `~/.ssh/`) by package install paths → `RUNTIME_ANOMALY_DETECTED`
- Unexpected child process spawning from package executables → `RUNTIME_ANOMALY_DETECTED`

When a `RUNTIME_ANOMALY_DETECTED` event fires within the 30-day window, the policy-as-code `runtime_anomaly_escalation` rule automatically re-opens the quorum in Discord with elevated requirements and an option to trigger automated rollback.

### Rollback integration

```yaml
runtime:
  monitoring_window_days: 30
  siem_hec_endpoint: ${SIEM_HEC_ENDPOINT}
  siem_hec_token: ${SIEM_HEC_TOKEN}
  anomaly_webhook: ${ANOMALY_WEBHOOK_URL}   # Receives anomaly events from your SIEM
  rollback:
    enabled: true
    adapter: helm                            # helm | ansible | terraform | custom
    on_unanimous_revocation: auto_rollback   # Trigger rollback without manual step
    rollback_timeout_minutes: 15
```

---

## Public trust registry

When `public_registry: true` is set in `pipeline.yaml`, the framework contributes anonymized, aggregated trust signal data to a community trust registry — a crowd-sourced package reputation score built from real quorum decisions across all participating organizations.

No organization-specific data (PR content, quorum member identities, internal package names) is shared. What is contributed:

- Package name, version, ecosystem
- Trust score band (HIGH / MEDIUM / LOW) — not the raw score
- Verdict (APPROVED / DENIED / EXPIRED) — not voter identities
- Which signal categories fired (not their values)
- SLSA level observed

**Why this matters:** Every organization using the framework benefits from the aggregate. A package that has been DENIED by 12 other organizations arrives at your gate with a pre-loaded historical reputation modifier of −15, before your own evaluations begin. This creates a network-effect moat that no single-organization implementation can replicate — and that no commercial vendor currently offers for quorum-based human decisions.

```yaml
public_registry:
  enabled: false              # Opt-in
  endpoint: https://api.oss-trust.dev/registry
  api_key: ${PUBLIC_REGISTRY_API_KEY}
  contribute_verdicts: true
  contribute_signal_flags: true
  consume_community_scores: true   # Use community history in scoring
```

---

## Developer feedback loop

When a package is QUARANTINED or BLOCKED, the developer whose PR triggered it receives a GitHub comment with the verdict, the trust score breakdown, and — critically — actionable remediation guidance so they can resolve the issue without waiting for a quorum decision.

**The PR comment includes:**

- The specific deductions that caused the score to land in QUARANTINE/BLOCKED territory
- Alternative versions of the same package that pass all gates (queried from deps.dev)
- The specific OSV advisory ID and a direct link, if a CVE was the trigger
- The minimum change required to proceed without a quorum vote (e.g. "version 4.17.21 passes all gates with a score of 87/100")
- A link to the SLSA attestation page if the block was provenance-related
- License change details and legal contact if the block was license-related

This turns every security gate from a frustrating blocker into an educational moment — developers learn supply-chain security patterns through the normal flow of their work rather than through separate training.

---

## Discord quorum override

When a package is `blocked` or `quarantined` and the policy-as-code engine determines quorum is required, the system posts an override request to a configured Discord channel. Named quorum members vote by reacting to the message. The threshold is determined by policy-as-code (simple majority by default, elevated for LOW trust scores or critical paths). Every quorum event is written to a Google Sheets audit log.

### Quorum architecture

```
quorum-engine.js
      │
      ├── Reads:  trust-result.json (from artifact)
      ├── Reads:  .github/quorum-config.json (members, base threshold)
      ├── Reads:  policy.yaml (conditional thresholds, required members)
      ├── Queries: Google Sheets audit log (historical reputation)
      │
      ├── Evaluates: policy-as-code rules → effective threshold + required members
      │
      ├── POST  Discord embed  ──► #security-dep-approvals channel
      ├── PUT   ✅ reaction    ──► seed vote anchor
      ├── PUT   ❌ reaction    ──► seed vote anchor
      │
      │   ┌─── poll every 30 s ────────────────────────────────┐
      │   │                                                     │
      │   │   GET /reactions/✅  →  filter to quorum members   │
      │   │   GET /reactions/❌  →  filter to quorum members   │
      │   │   check required_members voted                     │
      │   │   evaluate effective threshold                     │
      │   │   → APPROVED / DENIED / wait                       │
      │   │                                                     │
      │   └─────────────────────────────────────────────────────┘
      │
      ├── PATCH Discord embed      ──► final verdict
      ├── POST  Google Sheets      ──► audit row (33 columns)
      ├── POST  GitHub PR          ──► result comment + remediation guidance
      ├── POST  SIEM HEC           ──► PACKAGE_APPROVED or PACKAGE_DENIED event
      │
      └── exit 0 (approved) or exit 1 (denied / expired)
```

### Discord vote flow

When a package is flagged, the bot posts a quorum request embed:

```
┌──────────────────────────────────────────────────────────────┐
│ 🔐  Quorum Override Request — `lodash@4.17.20`               │
│                                                              │
│  The OSS Trust Framework flagged lodash@4.17.20 (npm) as    │
│  BLOCKED. A simple majority quorum is required to override   │
│  and allow this dependency into the PR.                      │
│                                                              │
│  📝 Reason for update                                        │
│  fix(deps): bump lodash from 4.17.19 to 4.17.20             │
│  Addresses CVE-2021-23337. Lodash 4.17.19 is in the         │
│  dependency graph of build-tools and test-utils.             │
│                                                              │
│  📦 Source repository                                        │
│  `https://registry.npmjs.org`                               │
│                                                              │
│  🔒 Trust level       🔴 LOW (45/100)                       │
│  🏗️  SLSA level       1 (signed, non-hermetic build)        │
│  🔏 Signature status  ⚠️ Valid — rsa-sha256 (weak)          │
│  🔑 Key / log ID      `4d8f2a3c...`                         │
│  🧮 Checksum          ✅ Verified (sha256)                   │
│  📜 License           MIT → MIT (no change)                 │
│  🚩 Supply-chain flags                                       │
│     ⚠️ Behavior change — new network access vs prior version │
│  ⚠️ Trust deductions  -20 weak algorithm                    │
│                        -20 behavior change                   │
│                        -15 SLSA level 1 (not hermetic)      │
│  📊 Community score   🔴 LOW — 3 prior DENIALs across       │
│                        community registry                    │
│                                                              │
│  ⚠️ Policy: LOW trust score — elevated threshold required   │
│  Quorum ID      QR-1748441234-A3F9C1                         │
│  Trust Outcome  BLOCKED                                      │
│  Ecosystem      npm                                          │
│  Votes Needed   3-of-4 (elevated: trust score < 30)         │
│  Deadline       in 12 hours                                  │
│                                                              │
│  How to vote: React ✅ to approve override, ❌ to deny.      │
│                                                              │
│  Eligible voters:  @alice  @bob  @carol  @dave              │
│  Required voters:  @carol (Security Architect)              │
└──────────────────────────────────────────────────────────────┘
```

### Voting rules

| Rule | Behaviour |
|---|---|
| **Who can vote** | Only Discord user IDs listed in `quorum-config.json` → `members`. All other reactions are ignored. |
| **Required members** | Policy-as-code can designate specific members who must be in the approving set (e.g. CISO for critical-path packages). A majority that doesn't include required members does not carry. |
| **Bot seed reactions** | The bot adds its own ✅ and ❌ to anchor the reactions UI. Bot reactions are excluded from tallying. |
| **Dual reaction** | If a member reacts with both ✅ and ❌, their vote counts as ❌ (fail-safe / more conservative). |
| **Effective threshold** | Determined by policy-as-code at vote creation time. Displayed in the embed. Default is simple majority (>50%); escalates for LOW trust scores or critical dependencies. |
| **Deadline** | If no majority is reached by the configured deadline, the vote closes as **EXPIRED** and the override is **DENIED** (fail-closed). |
| **Fail-closed** | Any error in the quorum engine causes exit 1, keeping the PR blocked. |

### Quorum math

Simple majority means strictly more than 50% of the **total quorum size** (not just those who voted). Policy-as-code can raise this threshold based on trust score or dependency class.

| Quorum size | Votes needed (threshold = 0.5) | Votes needed (threshold = 0.75) |
|---|---|---|
| 2 | 2 | 2 |
| 3 | 2 | 3 |
| 4 | 3 | 3 |
| 5 | 3 | 4 |
| 6 | 4 | 5 |
| 7 | 4 | 6 |

Formula: `required = floor(size × threshold) + 1`

Abstentions count against approval — creating an incentive for all members to participate.

### Audit log

Every quorum event writes one row to Google Sheets with 33 columns:

| Column | Description | Example |
|---|---|---|
| `quorum_id` | Unique ID for this vote | `QR-1748441234-A3F9C1` |
| `package` / `version` / `ecosystem` | Package identity | `lodash` / `4.17.20` / `npm` |
| `source_repository` | Registry or artifact proxy URL | `https://registry.npmjs.org` |
| `trust_level` / `trust_level_score` | Band and numeric score | `LOW` / `45` |
| `slsa_level` | SLSA level observed | `1` |
| `sig_status` / `sig_algorithm` / `sig_strength` / `sig_key_id` | Signature detail | `valid` / `rsa-sha256` / `weak` / `4d8f...` |
| `chk_status` / `chk_algorithm` | Checksum detail | `verified` / `sha256` |
| `license_current` / `license_prior` / `license_changed` | License tracking | `MIT` / `MIT` / `false` |
| `flag_typosquatting` / `flag_behavior_change` / `flag_author_reputation` / `flag_provenance` / `flag_ai_hallucination` | Boolean flags | `false` / `true` / `false` / `false` / `false` |
| `trust_deductions` | All deductions applied, pipe-separated | `-20 weak algorithm \| -20 behavior change` |
| `policy_applied` | Which policy rule governed this quorum | `low_trust_override` |
| `effective_threshold` | Threshold used for this vote | `0.75` |
| `required_members_met` | Whether required members voted | `true` |
| `community_score_band` | Band from public trust registry | `LOW` |
| `trust_outcome` | Gate outcome | `blocked` |
| `update_reason` | PR title + body, flattened | `fix(deps): bump lodash…` |
| `initiated_at` / `deadline` | Timestamps | ISO 8601 |
| `quorum_size` / `threshold` / `approve_count` / `deny_count` / `abstain_count` | Vote detail | — |
| `final_verdict` / `decided_at` / `decided_by` | Decision | `APPROVED` / ISO 8601 / `QUORUM_VOTE` |
| `voter_detail` | Per-voter breakdown | `✅ alice (111…) \| ❌ carol (333…)` |
| `discord_message_id` / `github_pr` / `run_id` | Traceability | — |
| `override_rationale` | Summary sentence | `Quorum override: 3/4 approved` |
| `runtime_monitoring_expires` | When the 30-day window closes | ISO 8601 |

**Updated Sheets header row:**

```
quorum_id | package | version | ecosystem | source_repository |
trust_level | trust_level_score | slsa_level |
sig_status | sig_algorithm | sig_strength | sig_key_id |
chk_status | chk_algorithm |
license_current | license_prior | license_changed |
flag_typosquatting | flag_behavior_change | flag_author_reputation |
flag_provenance | flag_ai_hallucination |
trust_deductions | policy_applied | effective_threshold | required_members_met |
community_score_band | trust_outcome | update_reason |
initiated_at | deadline | quorum_size | threshold |
approve_count | deny_count | abstain_count |
final_verdict | decided_at | decided_by | voter_detail |
discord_message_id | github_pr | run_id | override_rationale |
runtime_monitoring_expires
```

---

## CI/CD integration

### GitHub Actions workflow

The `dep-trust-check.yml` workflow runs on every pull request that touches a dependency file. It evaluates each changed package — including its full transitive tree — through the OSS Trust Framework pipeline, applies policy-as-code governance, and triggers Discord quorum for flagged packages.

**Triggers on changes to:**

| File pattern | Ecosystem |
|---|---|
| `**/requirements*.txt` | PyPI |
| `**/pyproject.toml` | PyPI |
| `**/package-lock.json` | npm |
| `**/package.json` | npm |
| `**/Cargo.lock` | Cargo |
| `**/go.sum` | Go |
| `**/*.csproj` / `**/packages.lock.json` | NuGet |
| `**/Gemfile.lock` | RubyGems |
| `**/.github/workflows/*.yml` | CI/CD self-audit (Gate 9) |

### Workflow jobs

**`detect-changes`** — Diffs lock files and workflow files between base and head SHA, outputs a JSON array of changed packages including transitive scope.

**`validate`** — Matrix job, one leg per changed package. Runs `oss-trust check` with full transitive evaluation, applies reachability analysis, checks SLSA attestations, validates licenses, runs policy-as-code evaluation, uploads `trust-result.json` as an artifact, and posts a PR comment with the result and remediation guidance.

**`quorum-override`** — Runs only when `validate` has at least one failing leg. Downloads trust result artifacts, applies policy-as-code to determine effective threshold and required members, runs the Discord quorum engine, emits SIEM telemetry, and exits 0 (approved) or 1 (denied/expired).

**`runtime-monitor-register`** — Runs on merge to main. Registers the approved package with the runtime monitoring service and opens the 30-day SIEM correlation window.

### PR check flow

```
Pull request opened or updated
           │
           ▼
┌─────────────────────────┐
│   detect-changes        │  ← includes transitive scope
│   + CI/CD self-audit    │    and workflow file changes
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│   validate (matrix)     │  ← nine gates + reachability
│                         │    + policy-as-code eval
│                         │    + remediation guidance
│  approved ───────────► PR check ✅ + remediation PR comment
│  hold     ───────────► PR check ✅ + advisory PR comment
│  quarantined ─────────► quorum-override ──────────────────┐
│  blocked  ───────────► quorum-override ──────────────────┐│
└─────────────────────────┘                                ││
                                                           ▼▼
                                              ┌─────────────────────────┐
                                              │  quorum-override        │
                                              │  (policy-as-code        │
                                              │   threshold applied)    │
                                              │                         │
                                              │  APPROVED ──► ✅ + SIEM │
                                              │  DENIED   ──► 🔴 + SIEM │
                                              │  EXPIRED  ──► 🔴 + SIEM │
                                              └─────────────────────────┘
                                                           │
                                              ┌────────────▼────────────┐
                                              │  runtime-monitor-       │
                                              │  register (on merge)    │
                                              │  30-day window opens    │
                                              └─────────────────────────┘
```
---

## Notification platform

The quorum engine supports three notification platforms. Set `QUORUM_PLATFORM` (or `platform` in `quorum-config.json`) to select one. Only the secrets for the chosen platform are required.

| Platform | Voting mechanism | Best for |
|---|---|---|
| `discord` (default) | Bot seeds ✅ ❌ reactions; engine polls reactions every 30 s | Teams already on Discord; free tier sufficient |
| `teams` | Adaptive Card with ✅ ❌ Action.Submit buttons; votes arrive via webhook | Organizations standardized on Microsoft 365 |
| `slack` | Block Kit message with ✅ ❌ buttons + confirmation dialog; votes arrive via Slack interactivity | Organizations standardized on Slack |

### Discord

See [Setup guide → 1. Create the Discord bot](#1-create-the-discord-bot) for full steps.

**Required secrets:** `DISCORD_BOT_TOKEN`, `DISCORD_CHANNEL_ID`, `DISCORD_GUILD_ID`

**Member ID format:** 18-19 digit numeric user ID. Developer Mode on → right-click username → Copy User ID.

**How voting works:** The bot seeds ✅ and ❌ reactions on the embed. Quorum members click a reaction. The engine polls `GET /reactions` every 30 seconds until majority is reached or the deadline expires.

### MS Teams

**Required secrets:** `TEAMS_WEBHOOK_URL`, `TEAMS_VOTE_WEBHOOK_URL`

**Optional secrets:** `TEAMS_TENANT_ID`

**Member ID format:** Azure AD Object ID (GUID). Azure Portal → Users → select user → Object ID field.

**How voting works:** The engine posts an Adaptive Card to the channel via the incoming webhook. The card has ✅ **Approve Override** and ❌ **Deny Override** `Action.Submit` buttons. When a member clicks a button, Teams POSTs the vote payload to `TEAMS_VOTE_WEBHOOK_URL`. The engine also starts a local HTTP server on `VOTE_SERVER_PORT` (default `3000`) to capture these callbacks directly.

**Setting up the vote endpoint:**

`TEAMS_VOTE_WEBHOOK_URL` must be a publicly reachable HTTPS endpoint. Options:

1. **Azure Function** (recommended for production):
   ```
   POST {function-url}/api/quorum-vote
   Body: { "quorum_id": "QR-...", "vote": "approve", "member_id": "<aad-guid>", "member_name": "Alice" }
   Response: { "type": "message", "text": "Vote recorded" }
   ```
   The function should forward the vote to the engine's local server at `http://localhost:3000` within the same Actions runner network, or persist it to a shared store (Azure Table Storage, Cosmos DB).

2. **Logic App** — use the HTTP trigger and same request/response contract above.

3. **ngrok tunnel** (testing only):
   ```bash
   ngrok http 3000   # Expose the engine's local vote server
   # Set TEAMS_VOTE_WEBHOOK_URL to the ngrok HTTPS URL
   ```

**Incoming webhook setup:**
1. In Teams, go to the approval channel → ••• → Connectors → Incoming Webhook → Configure
2. Name it `OSS Trust Quorum` and copy the webhook URL → `TEAMS_WEBHOOK_URL`

**Setting up Action.Submit routing:**
The Adaptive Card's `Action.Submit` buttons include `url: TEAMS_VOTE_WEBHOOK_URL` in the action data. When submitted, Teams sends the card data as a POST to that URL with `member_id` and `member_name` resolved from the authenticated Teams user context.

### Slack

**Required secrets:** `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`, `SLACK_VOTE_WEBHOOK_URL`

**Member ID format:** Slack member ID starting with `U`. Click a user's profile → ••• More → Copy member ID.

**How voting works:** The engine posts a Block Kit message with ✅ and ❌ buttons (both with confirmation dialogs to prevent accidental votes). When a member clicks, Slack POSTs an interactivity payload to `SLACK_VOTE_WEBHOOK_URL`. The engine's local HTTP server on `VOTE_SERVER_PORT` (default `3000`) captures these callbacks.

**Bot scopes required:** `chat:write`, `chat:write.public`, `users:read`

**Setting up the Slack app:**

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → Create New App → From scratch
2. Under **OAuth & Permissions**, add scopes: `chat:write`, `chat:write.public`, `users:read`
3. Install the app to your workspace → copy the **Bot User OAuth Token** → `SLACK_BOT_TOKEN`
4. Under **Interactivity & Shortcuts** → enable Interactivity → set **Request URL** to `SLACK_VOTE_WEBHOOK_URL`
5. Invite the bot to your approval channel: `/invite @your-bot-name`
6. Copy the channel ID (right-click channel → Copy link → extract the `C...` portion) → `SLACK_CHANNEL_ID`

**Vote endpoint contract** (same for all push-based platforms):

The engine starts an HTTP server on `VOTE_SERVER_PORT`. For Slack, it expects the standard `application/x-www-form-urlencoded` interactivity payload with a `payload` field containing the JSON action data:

```json
{
  "user":    { "id": "U123456", "name": "alice" },
  "actions": [{ "action_id": "approve", "value": "QR-1748441234-A3F9C1" }]
}
```

The engine responds immediately with `200` and an ephemeral acknowledgement message to dismiss Slack's loading state.

**Latest vote wins:** If a member changes their vote by clicking the other button, the latest vote replaces their prior vote in the tally. The audit log records the final state only.

### Choosing a platform

| Consideration | Discord | Teams | Slack |
|---|---|---|---|
| Setup complexity | Low | Medium | Medium |
| Voting UX | Click reaction | Click card button (with confirmation) | Click button (with confirmation dialog) |
| Vote change | Re-react (remove + add) | Click other button (latest wins) | Click other button (latest wins) |
| Message updates | In-place embed edit | New follow-up card | In-place message edit |
| Accidental vote prevention | None (reactions are easy to click) | None | ✅ Confirmation dialog on both buttons |
| Requires external endpoint | No | Yes (TEAMS_VOTE_WEBHOOK_URL) | Yes (SLACK_VOTE_WEBHOOK_URL) |
| Member ID lookup | Developer Mode toggle | Azure Portal | Profile menu |
| Free tier sufficient | ✅ Yes | ✅ Yes (incoming webhook is free) | ✅ Yes (free plan allows bots) |


---

## Setup guide

### 1. Create the Discord bot

> **Skip this section** if you are using Teams or Slack. See [Notification platform](#notification-platform) for platform-specific setup.

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications) and click **New Application**.
2. Name it (e.g. `dep-trust-bot`) and click **Create**.
3. In the left sidebar click **Bot**, then click **Reset Token** and copy the token — this becomes `DISCORD_BOT_TOKEN`.
4. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
5. In the left sidebar click **OAuth2 → URL Generator**. Select scopes: `bot`. Select bot permissions:

   | Permission | Why |
   |---|---|
   | Send Messages | Post quorum embeds |
   | Add Reactions | Seed ✅ ❌ vote anchors |
   | Read Message History | Fetch reactions from past messages |
   | Embed Links | Render rich embeds |
   | View Channels | Access the approval channel |

6. Copy the generated URL, open it in a browser, and invite the bot to your server.
7. In Discord with **Developer Mode** enabled (Settings → Advanced → Developer Mode):
   - Right-click your server name → **Copy Server ID** → `DISCORD_GUILD_ID`
   - Right-click your approval channel → **Copy Channel ID** → `DISCORD_CHANNEL_ID`

> **Finding a Discord user ID:** Developer Mode on → right-click any username → **Copy User ID**.

### 2. Set up Google Sheets audit log

1. Go to [Google Cloud Console](https://console.cloud.google.com) → **APIs & Services → Enable APIs** → enable **Google Sheets API**.
2. Go to **IAM & Admin → Service Accounts** → **Create Service Account** (name: `dep-trust-sheets`).
3. Click the service account → **Keys** → **Add Key → Create new key → JSON**. Download the file.
4. Base64-encode it:
   ```bash
   # Linux / macOS
   base64 -w0 service-account.json

   # macOS alternative
   base64 -i service-account.json | tr -d '\n'
   ```
   The output becomes `SHEETS_CREDENTIALS`.
5. Create a blank Google Sheet. The ID from its URL becomes `SHEETS_SPREADSHEET_ID`.
6. Share the Sheet with the service account's `client_email` with **Editor** access.
7. Rename the first tab to `QuorumAuditLog`.
8. Add a header row matching the schema in the [Audit log](#audit-log) section.

### 3. Configure quorum members

Edit `.github/quorum-config.json`:

```json
{
  "members": [
    "111111111111111111",
    "222222222222222222",
    "333333333333333333"
  ],
  "threshold": 0.5,
  "deadlineHours": 24,
  "namedRoles": {
    "CISO": "111111111111111111",
    "SECURITY_ARCH": "222222222222222222",
    "LEGAL": "444444444444444444"
  }
}
```

The `namedRoles` block maps role names used in `policy.yaml` to Discord user IDs.

### 4. Configure policy-as-code

Copy `config/policy.yaml.example` to `config/policy.yaml` and customize the quorum thresholds, required members, and license allowlist for your organization. At minimum, set the Discord user IDs for `CISO_DISCORD_ID` and `SECURITY_ARCH_DISCORD_ID` in your `.env` file.

### 5. Add GitHub secrets

Go to **Settings → Secrets and variables → Actions → New repository secret**:

| Secret name | Value | Required |
|---|---|---|
| `QUORUM_PLATFORM` | `discord`, `teams`, or `slack` | ✅ Yes |
| `DISCORD_BOT_TOKEN` | Bot token (Discord only) | Discord only |
| `DISCORD_CHANNEL_ID` | Approval channel ID (Discord only) | Discord only |
| `DISCORD_GUILD_ID` | Server ID (Discord only) | Discord only |
| `TEAMS_WEBHOOK_URL` | Incoming webhook URL for approval channel (Teams only) | Teams only |
| `TEAMS_VOTE_WEBHOOK_URL` | HTTPS endpoint receiving Action.Submit vote payloads (Teams only) | Teams only |
| `TEAMS_TENANT_ID` | Azure AD tenant ID (Teams only) | Optional |
| `SLACK_BOT_TOKEN` | Bot OAuth token with `chat:write`, `users:read` (Slack only) | Slack only |
| `SLACK_CHANNEL_ID` | Channel ID for quorum messages (Slack only) | Slack only |
| `SLACK_VOTE_WEBHOOK_URL` | Slack app Interactivity Request URL (Slack only) | Slack only |
| `SHEETS_CREDENTIALS` | Base64-encoded service account JSON | ✅ Yes |
| `SHEETS_SPREADSHEET_ID` | Spreadsheet ID from URL | ✅ Yes |
| `OSV_API_KEY` | OSV.dev API key | Optional |
| `SIEM_HEC_ENDPOINT` | Splunk/SIEM HEC endpoint URL | Optional |
| `SIEM_HEC_TOKEN` | Splunk/SIEM HEC token | Optional |
| `ANOMALY_WEBHOOK_URL` | Webhook your SIEM calls on runtime anomaly | Optional |
| `ENDOR_LABS_API_KEY` | Endor Labs API key for reachability analysis | Optional |
| `PUBLIC_REGISTRY_API_KEY` | OSS Trust public registry API key | Optional |

> `GITHUB_TOKEN` is provided automatically by GitHub Actions — do not add it as a secret.

### 6. Add repository files

```
.github/
├── workflows/
│   └── dep-trust-check.yml
├── scripts/
│   ├── post-trust-comment.js
│   └── quorum-engine.js
├── approved-actions.json          ← CI/CD self-audit inventory
└── quorum-config.json

config/
├── pipeline.yaml
└── policy.yaml

scripts/
└── extract_dep_changes.py         ← you provide this
```

---

## Configuration reference

### `config/pipeline.yaml`

```yaml
age_gate:
  hard_block_hours: 24
  hold_hours: 72

trust_scoring:
  min_score: 60
  require_zero_vulns: true

slsa:
  critical_packages:
    - pattern: "*auth*"
      min_level: 3
    - pattern: "*crypto*"
      min_level: 3
  default_min_level: 1
  on_missing_attestation: quarantine

reachability:
  enabled: true
  adapter: endor_labs
  cache_ttl_hours: 24
  on_unreachable: hold
  on_adapter_failure: quarantine

license:
  allowlist: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD]
  block_copyleft: true
  block_commercial_restrict: true
  on_unlicensed: block

sbom:
  recursive: true
  max_transitive_depth: 10
  new_transitive_action: quarantine
  min_transitive_trust_score: 50

sandbox:
  runtime: gvisor
  network: none
  timeout_seconds: 120

ai_hallucination:
  enabled: true
  similarity_threshold: 0.85
  new_package_age_days: 90
  on_confirmed_hallucination: block

cicd_audit:
  enabled: true
  require_sha_pinning: true
  new_action_action: hold
  approved_action_inventory: .github/approved-actions.json

zero_day:
  required_approvers: 2
  token_ttl_hours: 6
  max_exceptions_per_24h: 3

runtime:
  monitoring_window_days: 30
  siem_hec_endpoint: ${SIEM_HEC_ENDPOINT}
  siem_hec_token: ${SIEM_HEC_TOKEN}
  anomaly_webhook: ${ANOMALY_WEBHOOK_URL}
  rollback:
    enabled: true
    adapter: helm
    on_unanimous_revocation: auto_rollback

public_registry:
  enabled: false
  endpoint: https://api.oss-trust.dev/registry
  contribute_verdicts: true
  consume_community_scores: true
```

### Supported ecosystems

`npm` · `pypi` · `cargo` · `go` · `maven` · `nuget` · `rubygems`

---

## Trust outcomes

| Outcome | Meaning | PR check | Quorum triggered |
|---|---|---|---|
| `approved` | Passed all nine gates | ✅ Green | No |
| `hold` | Advisory; flagged but not blocked (reachability downgrade, minor license change, SLSA below preferred) | ✅ Green with comment | No |
| `pending_quorum` | External quorum process required | ✅ Green | No (external) |
| `quarantined` | Flagged; quorum override possible | 🔴 Red | **Yes** |
| `blocked` | Hard block; quorum override possible with policy compliance | 🔴 Red | **Yes** |
| `rejected` | Cryptographic failure; no override path | 🔴 Red | No |

---

## Project structure

```
oss-trust-framework/
├── src/
│   ├── age_check/           # Gate 1 — release timestamp validation
│   ├── signature/           # Gate 2 — Sigstore / GPG + strength check
│   ├── slsa/                # Gate 3 — SLSA provenance attestation
│   ├── trust/               # Gate 4 — OOB trust aggregation (OSV, Scorecard, Socket)
│   ├── reachability/        # Gate 4.5 — call graph reachability analysis
│   ├── license/             # Gate 5 — SPDX allowlist + change detection
│   ├── sbom/                # Gate 6 — recursive SBOM delta + hash pinning
│   ├── sandbox/             # Gate 7 — behavioral sandbox (gVisor / Firecracker)
│   ├── ai_hallucination/    # Gate 8 — hallucinated package name detection
│   ├── cicd_audit/          # Gate 9 — CI/CD pipeline self-audit
│   ├── zeroday/             # Expedited lane — CVE validation + quorum
│   ├── policy/              # Policy-as-code evaluation engine
│   ├── runtime/             # Post-merge telemetry + SIEM integration
│   ├── registry/            # Public trust registry client
│   └── pipeline/            # Orchestrator — runs all gates in sequence
├── tests/
├── docs/
├── config/
│   ├── pipeline.yaml
│   └── policy.yaml
├── .github/
│   ├── workflows/
│   │   └── dep-trust-check.yml
│   ├── scripts/
│   │   ├── post-trust-comment.js
│   │   └── quorum-engine.js
│   ├── approved-actions.json
│   └── quorum-config.json
├── scripts/
│   └── extract_dep_changes.py
├── correlation-rules/
│   ├── splunk/              # Splunk correlation search SPL for runtime anomaly
│   ├── elastic/             # Elastic SIEM detection rules (JSON)
│   └── sentinel/            # Microsoft Sentinel analytic rules (JSON)
├── .env.example
└── pyproject.toml
```

---

## Compliance mapping

The framework's audit trail and policy-as-code engine generate evidence that maps directly to major compliance frameworks:

| Control | Framework | How this framework satisfies it |
|---|---|---|
| Software composition analysis | NIST SSDF PW.4 | Gates 1–8 with full audit log per evaluation |
| Third-party component vetting | NIST SP 800-161 SA-12 | Trust scoring + quorum override with named approver record |
| Build provenance | SLSA L1–L4 | Gate 3 enforces minimum SLSA level per dependency class |
| Change management for software | SOC 2 CC6.8 | Quorum audit log provides evidence of authorized change |
| Access control over production changes | SOC 2 CC6.1 | Policy-as-code required-member enforcement |
| Vulnerability management | ISO 27001 A.12.6 | Gates 4 + 4.5 with reachability-filtered output |
| Secure development lifecycle | ISO 27001 A.14.2 | Full gate pipeline with artifact retention |
| Supply chain risk | FedRAMP SA-12 | Trust scoring + SLSA attestation + runtime telemetry |
| Incident response | NIST CSF RS.AN | Runtime anomaly → SIEM → quorum re-open → rollback |

---

## Troubleshooting

**Quorum job never starts**

The `quorum-override` job only runs when `validate` exits with `result == 'failure'`. Check the validate job logs for `::error ::Trust check failed`.

**Reachability analysis times out**

The reachability adapter requires a pre-built call graph. If the graph is stale (older than `cache_ttl_hours`) or missing, the gate falls back to the `on_adapter_failure` action (`quarantine` by default). Ensure the call graph build step runs on your main branch on a schedule.

**Discord embed not appearing**

Verify `DISCORD_BOT_TOKEN`, `DISCORD_CHANNEL_ID`, and `DISCORD_GUILD_ID` in secrets. Confirm the bot has been invited with the required permissions. Check step logs for `HTTP 4xx` from the Discord API.

**Required member not counted**

Verify the Discord user ID in `namedRoles` in `quorum-config.json` is the 18-19 digit numeric ID, not a username. Usernames and display names are not accepted.

**SLSA gate failing for all packages**

Most public packages are SLSA 0. Set `default_min_level: 0` and use the `critical_packages` block to enforce higher levels only for packages you've specifically classified. Apply graduated requirements — blocking all SLSA 0 packages immediately will block most of your dependency tree.

**SIEM telemetry not reaching HEC endpoint**

Verify `SIEM_HEC_ENDPOINT` includes the full path (e.g. `https://splunk.yourorg.com:8088/services/collector`). The HEC token requires the `can_post_events` capability. Check for TLS certificate validation failures if using a self-signed cert.

**Runtime anomaly quorum not re-opening**

The `ANOMALY_WEBHOOK_URL` must be a publicly reachable endpoint that accepts POST requests from your SIEM. The webhook payload must include `package`, `version`, and `original_quorum_id` fields. Verify the `monitoring_window_days` has not expired for the package in question.

**CI/CD self-audit flagging your own actions**

Add the action SHA to `.github/approved-actions.json`. The CI/CD audit is only effective if the approved action inventory is kept current — schedule a monthly review of the inventory as part of your security program.

---

## Prerequisite best practices

The OSS Trust Framework augments a mature dependency security posture — it does not replace one. The following controls must be in place regardless of this framework. Without them, the framework addresses only part of the threat surface.

### Why pinning alone is not enough

Pinning to known-good versions is a necessary baseline, but in today's landscape — where malicious open-source packages have surged and attackers specifically target developer tooling, CI/CD secrets, and credentials — a set-and-forget approach can trap you in maintenance debt while leaving you exposed. Continuous validation across the full dependency lifecycle is required.

### 1. Local curation and perimeter controls

Direct all developer machines and CI/CD pipelines to pull exclusively from a managed private artifact repository (Artifactory, Nexus, Cloudsmith). Block direct access to public registries at the network layer. Quarantine packages newer than 30 days automatically. Ensure internal package names are scoped to prevent dependency confusion attacks.

### 2. Cryptographic anchoring

Always commit lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`) that mandate SHA-256 or SHA-512 hashes for every dependency and transitive dependency. Pinning a version number without a hash leaves you open to mirror attacks and silent package replacement.

### 3. Sandboxing and runtime isolation

Disable installation script execution globally (`npm install --ignore-scripts`) unless explicitly audited. Run CI/CD runners in isolated, ephemeral environments with strict egress-filtered network policies.

### 4. Active behavioral analysis

Static CVE scanning misses malware that arrives before any CVE is filed. Use behavioral SCA tooling (Socket.dev, Endor Labs) that monitors package behavior — flagging unexpected file access, shell spawning, or outbound network requests.

### 5. Guardrails for AI-assisted development

Treat AI coding agents as first-class supply chain participants. Assign them specific non-human identities, limit their access via least privilege, and continuously audit their package pulls. Gate 8 in this framework specifically addresses AI hallucination as an attack vector.

### Summary checklist

| Control | Defense layer | What it addresses |
|---|---|---|
| Private proxy repository | Perimeter | Blocks unvetted public code; enforces licensing |
| Age-based quarantine (≥30 days) | Perimeter | Prevents immediate consumption of zero-day malware |
| `--ignore-scripts` globally | Build / install | Neutralizes malicious installation hooks |
| Cryptographic lockfiles (SHA-256/512) | Configuration | Prevents silent package substitution |
| Egress-filtered CI/CD runners | Infrastructure | Stops exfiltration of secrets |
| Sigstore / SLSA provenance (Gate 2–3) | Supply chain | Verifiable build chain of custody |
| Recursive transitive SBOM (Gate 6) | Supply chain | No hidden malicious transitive packages |
| Reachability analysis (Gate 4.5) | Application | Filters noise; focuses effort on real risk |
| Behavioral SCA tooling (Gate 4) | Runtime | Catches malware with no CVE |
| License compliance gate (Gate 5) | Legal / supply chain | Prevents silent license obligation changes |
| CI/CD self-audit (Gate 9) | Infrastructure | Closes the build pipeline attack surface |
| Runtime telemetry (30-day window) | Runtime | Detects post-deployment activation of dormant malware |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs must pass the framework's own nine-gate pipeline — we eat our own cooking.

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [OpenSSF Scorecard](https://securityscorecards.dev)
- [Sigstore / cosign](https://docs.sigstore.dev)
- [OSV — Open Source Vulnerabilities](https://osv.dev)
- [Google deps.dev](https://deps.dev)
- [SLSA Framework](https://slsa.dev)
- [Socket.dev supply chain analysis](https://socket.dev)
- [gVisor container sandbox](https://gvisor.dev)
- [Endor Labs reachability analysis](https://endorlabs.com)
- [in-toto attestation framework](https://in-toto.io)
- [NIST SSDF — Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [NIST SP 800-161 — Supply Chain Risk Management](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final)
- [CycloneDX SBOM standard](https://cyclonedx.org)
- [SPDX License List](https://spdx.org/licenses)
