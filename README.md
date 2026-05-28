# OSS Trust Framework

**Open Source Supply Chain Trust Validation Pipeline**

A multi-gate security framework that validates open source dependency updates before they reach your application — with a hardened expedited lane for zero-day CVE patches and a Discord-based human quorum override for flagged packages in pull requests.

**Author:** Chris Gillham

---

## Table of Contents

- [The problem](#the-problem)
- [Validation pipeline](#validation-pipeline)
  - [Five-gate architecture](#five-gate-architecture)
  - [Zero-day expedited lane](#zero-day-expedited-lane)
  - [Gate reference](#gate-reference)
  - [Zero-day lane circuit breakers](#zero-day-lane-circuit-breakers)
  - [Out-of-band trust sources](#out-of-band-trust-sources)
- [Quickstart](#quickstart)
- [Installation](#installation)
- [Configuration](#configuration)
- [CI/CD integration](#cicd-integration)
  - [GitHub Actions workflow](#github-actions-workflow)
  - [Workflow jobs](#workflow-jobs)
  - [PR check flow](#pr-check-flow)
- [Discord quorum override](#discord-quorum-override)
  - [Quorum architecture](#quorum-architecture)
  - [Discord vote flow](#discord-vote-flow)
  - [Voting rules](#voting-rules)
  - [Quorum math](#quorum-math)
  - [Audit log](#audit-log)
- [Setup guide](#setup-guide)
  - [1. Create the Discord bot](#1-create-the-discord-bot)
  - [2. Set up Google Sheets audit log](#2-set-up-google-sheets-audit-log)
  - [3. Configure quorum members](#3-configure-quorum-members)
  - [4. Add GitHub secrets](#4-add-github-secrets)
  - [5. Add repository files](#5-add-repository-files)
- [Configuration reference](#configuration-reference)
- [Trust outcomes](#trust-outcomes)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [References](#references)

---

## The problem

Malicious packages depend on speed. A compromised maintainer account publishes a malicious release; automated dependency tooling ingests it within minutes. The attacker wins before anyone notices.

This framework breaks that race with five mandatory validation gates and a configurable age hold — while providing a strictly controlled bypass for legitimate zero-day patches that need to move fast. When a package is flagged in a pull request, a configurable Discord quorum of named approvers can vote to override the block with full auditability.

---

## Validation pipeline

### Five-gate architecture

```
Dependency update request
        │
        ▼
┌───────────────────┐     < 24 h, no CVE ──► BLOCKED
│  Gate 1: Age      │
│  < 72 h hold      │     Zero-day CVE? ──► Expedited Lane (see below)
└────────┬──────────┘
         │ ≥ 24 h
         ▼
┌───────────────────┐
│  Gate 2: Sig      │     Mismatch ──► REJECTED
│  Sigstore / GPG   │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 3: OOB      │     Score low ──► QUARANTINE
│  OpenSSF/OSV/     │
│  deps.dev         │ ◄── Zero-day lane rejoins here
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 4: SBOM     │     Unexpected deps ──► QUARANTINE
│  delta + hash pin │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Gate 5: Sandbox  │     Malicious behavior ──► BLOCKED
│  gVisor / no net  │
└────────┬──────────┘
         │
         ▼
    Staged rollout ──────────────────────────────► APPROVED
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
Signature + timing check (signed after CVE publication)
        │
        ▼
Isolated sandbox (gVisor, no network)
        │
        ▼
Audit record (SIEM event + ticket link mandatory)
        │
        ▼
Rejoin at Gate 3 (out-of-band trust)
        │
        ▼
Immediate full-fleet deploy + 48 h elevated alert window
```

### Gate reference

| Gate | What it checks | Fail action | Bypassable? |
|---|---|---|---|
| 1 — Age | Release timestamp vs configurable thresholds | Block / Hold | Yes, with CVE + quorum |
| 2 — Signature | Sigstore transparency log / GPG key | Reject | No |
| 3 — OOB Trust | OpenSSF Scorecard, OSV, deps.dev | Quarantine | No |
| 4 — SBOM delta | New transitive dependencies, hash mismatch | Quarantine | No |
| 5 — Sandbox | Install-time behavior in isolated VM | Block | No |

### Zero-day lane circuit breakers

The expedited lane automatically suspends under these conditions:

- More than 3 exception requests in a 24-hour window
- Same requester files two exceptions within 48 hours (escalates to CISO)
- Any exception-deployed package receives a new CVE within 30 days
- Monthly retrospective finds process violations

### Out-of-band trust sources

Gate 3 queries these sources independently of the package repository:

| Source | API | What it provides |
|---|---|---|
| OpenSSF Scorecard | `api.securityscorecards.dev` | Security hygiene score |
| deps.dev (Google) | `api.deps.dev` | Dependency graph, advisories |
| OSV.dev | `api.osv.dev` | Cross-ecosystem CVE database |
| GitHub Advisories | `api.github.com/advisories` | Manually reviewed, high signal |
| npm Advisory DB | Built into `npm audit` | npm-specific compromise history |

---

## Quickstart

```bash
pip install oss-trust-framework

# Run the full pipeline against a single package
oss-trust check --package requests --version 2.32.3 --ecosystem PyPI

# Request a zero-day expedited exception
oss-trust zeroday request \
  --cve CVE-2024-XXXXX \
  --package requests \
  --version 2.32.4 \
  --requester security@yourorg.com
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
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Key settings in `config/pipeline.yaml`:

```yaml
age_gate:
  hard_block_hours: 24      # Releases younger than this: auto-blocked
  hold_hours: 72            # Releases in this window: human approval required

trust_scoring:
  min_score: 60             # OpenSSF composite score threshold (0-100)
  require_zero_vulns: true  # Fail if any active CVE against this version

zero_day:
  required_approvers: 2     # Quorum size
  token_ttl_hours: 6        # Exception token expiry
  max_exceptions_per_24h: 3 # Circuit breaker

sandbox:
  runtime: gvisor           # gvisor | firecracker | docker
  network: none
  timeout_seconds: 120
```

---

## CI/CD integration

### GitHub Actions workflow

The `dep-trust-check.yml` workflow runs on every pull request that touches a dependency file. It validates each changed package through the OSS Trust Framework pipeline and — for packages that are `blocked` or `quarantined` — triggers a Discord quorum vote before allowing the PR to merge.

**Triggers on changes to:**

| File pattern | Ecosystem |
|---|---|
| `**/requirements*.txt` | PyPI |
| `**/pyproject.toml` | PyPI |
| `**/package-lock.json` | npm |
| `**/package.json` | npm |
| `**/Cargo.lock` | Cargo |
| `**/go.sum` | Go |

For a basic single-package validation without the quorum system, you can also use the reusable action directly:

```yaml
- name: Validate dependency update
  uses: chrisgillham/oss-trust-framework/.github/actions/validate@main
  with:
    package: ${{ env.PACKAGE_NAME }}
    version: ${{ env.PACKAGE_VERSION }}
    ecosystem: ${{ env.ECOSYSTEM }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    osv-api-key: ${{ secrets.OSV_API_KEY }}
```

### Workflow jobs

The full `dep-trust-check.yml` runs three jobs in sequence:

**`detect-changes`** — Diffs lock files between base and head SHA using `scripts/extract_dep_changes.py` and outputs a JSON array of changed packages. If no packages changed, all downstream jobs are skipped.

**`validate`** — Runs as a matrix with one parallel leg per changed package. For each package it runs `oss-trust check`, uploads `trust-result.json` as an artifact (retained 7 days), posts a PR comment with the result, and exits 1 if the outcome is `blocked` or `quarantined`.

**`quorum-override`** — Runs only when `validate` has at least one failing leg. Downloads the trust result artifact for each flagged package and runs the Discord quorum engine. Exits 0 (approved) or 1 (denied/expired), which sets the final PR check status.

### PR check flow

```
Pull request opened or updated
           │
           ▼
┌─────────────────────────┐
│   detect-changes job    │
│                         │
│  Diffs lock files and   │
│  extracts changed       │
│  packages as JSON array │
└──────────┬──────────────┘
           │  [{package, version, ecosystem}, ...]
           ▼
┌─────────────────────────┐
│   validate job          │  ← matrix: one leg per changed package
│                         │
│  oss-trust check        │
│  → trust-result.json    │
│                         │
│  approved  ──────────► PR check ✅
│  hold      ──────────► PR check ✅ (with advisory comment)
│  pending_quorum ──────► PR check ✅ (pending external quorum)
│  quarantined ─────────► job fails → quorum-override ─┐
│  blocked   ───────────► job fails → quorum-override ─┘
└─────────────────────────┘
           │ (blocked or quarantined only)
           ▼
┌─────────────────────────┐
│  quorum-override job    │
│                         │
│  Posts Discord embed    │
│  Seeds ✅ ❌ reactions  │
│  Polls for votes        │
│                         │
│  APPROVED ───────────► PR check ✅  +  audit row  +  PR comment
│  DENIED   ───────────► PR check 🔴  +  audit row  +  PR comment
│  EXPIRED  ───────────► PR check 🔴  +  audit row  +  PR comment
└─────────────────────────┘
```

---

## Discord quorum override

When a package is `blocked` or `quarantined`, the quorum system posts an override request to a configured Discord channel. Named quorum members vote by reacting to the message. Simple majority carries the vote. Every quorum event — including individual voter decisions — is written to a Google Sheets audit log.

### Quorum architecture

```
quorum-engine.js
      │
      ├── Reads:  trust-result.json (from artifact)
      ├── Reads:  .github/quorum-config.json (members, threshold, deadline)
      │
      ├── POST  Discord embed  ──► #security-dep-approvals channel
      ├── PUT   ✅ reaction    ──► seed vote anchor
      ├── PUT   ❌ reaction    ──► seed vote anchor
      │
      │   ┌─── poll every 30 s ────────────────────────────────┐
      │   │                                                     │
      │   │   GET /reactions/✅  →  filter to quorum members   │
      │   │   GET /reactions/❌  →  filter to quorum members   │
      │   │   evaluate majority  →  APPROVED / DENIED / wait   │
      │   │                                                     │
      │   └─────────────────────────────────────────────────────┘
      │
      ├── PATCH Discord embed   ──► final verdict
      ├── POST  Google Sheets   ──► audit row (20 columns)
      ├── POST  GitHub PR       ──► result comment
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
│  Addresses CVE-2021-23337 (prototype pollution via           │
│  _.template). Lodash 4.17.19 is in the dependency graph     │
│  of build-tools and test-utils. This patch upgrades both.   │
│                                                              │
│  📦 Source repository                                        │
│  `https://registry.npmjs.org`                               │
│                                                              │
│  🔒 Trust level       🔴 LOW (45/100)                       │
│  🔏 Signature status  ⚠️ Valid — rsa-sha256 (weak)          │
│  🔑 Key / log ID      `4d8f2a3c...`                         │
│  🧮 Checksum          ✅ Verified (sha256)                   │
│  🚩 Supply-chain flags                                       │
│     ⚠️ Behavior change — new network access vs prior version │
│  ⚠️ Trust deductions  -20 weak algorithm                    │
│                        -20 behavior change                   │
│                                                              │
│  Quorum ID      QR-1748441234-A3F9C1                         │
│  Trust Outcome  BLOCKED                                      │
│  Ecosystem      npm                                          │
│  PR             github.com/org/repo/pull/42                  │
│  Quorum Size    3 eligible                                   │
│  Votes Needed   2 to approve or deny                         │
│  Deadline       in 24 hours                                  │
│                                                              │
│  How to vote: React ✅ to approve override, ❌ to deny.      │
│  Only votes from quorum members below are counted.           │
│                                                              │
│  Eligible voters:  @alice  @bob  @carol                      │
│                                                              │
│  HITL Quorum · Simple Majority (>50%) · Chris Gillham        │
└──────────────────────────────────────────────────────────────┘
```

Quorum members click ✅ or ❌ directly on the message. The bot checks reactions every 30 seconds. When majority is reached (or the deadline expires) the embed updates with the final verdict:

```
┌──────────────────────────────────────────────────────────────┐
│ ✅  Quorum APPROVED — `lodash@4.17.20`                       │
│                                                              │
│  📝 Reason for update                                        │
│  fix(deps): bump lodash from 4.17.19 to 4.17.20             │
│  Addresses CVE-2021-23337 (prototype pollution via           │
│  _.template). Lodash 4.17.19 is in the dependency graph…    │
│                                                              │
│  📦 Source repository                                        │
│  `https://registry.npmjs.org`                               │
│                                                              │
│  🔒 Trust level       🔴 LOW (45/100)                       │
│  🔏 Signature status  ⚠️ Valid — rsa-sha256 (weak)          │
│  🔑 Key / log ID      `4d8f2a3c...`                         │
│  🧮 Checksum          ✅ Verified (sha256)                   │
│  🚩 Supply-chain flags                                       │
│     ⚠️ Behavior change — new network access vs prior version │
│                                                              │
│  Quorum ID      QR-1748441234-A3F9C1                         │
│  Final Verdict  APPROVED                                     │
│  Trust Outcome  BLOCKED                                      │
│  ✅ Approve     2                                            │
│  ❌ Deny        1                                            │
│  ⬜ Abstain     0                                            │
│                                                              │
│  Voter detail:                                               │
│    ✅ alice (111111111111111111)                              │
│    ✅ bob   (222222222222222222)                              │
│    ❌ carol (333333333333333333)                              │
│                                                              │
│  Decided at 2026-05-28T15:30:00Z · Chris Gillham             │
└──────────────────────────────────────────────────────────────┘
```

### Voting rules

| Rule | Behaviour |
|---|---|
| **Who can vote** | Only Discord user IDs listed in `quorum-config.json` → `members`. All other reactions are ignored. |
| **Bot seed reactions** | The bot adds its own ✅ and ❌ to anchor the reactions UI. Bot reactions are excluded from tallying. |
| **Dual reaction** | If a member reacts with both ✅ and ❌, their vote counts as ❌ (fail-safe / more conservative). |
| **Simple majority** | Strictly more than 50% of the quorum size. For 3 members: 2 votes needed. For 5 members: 3 votes needed. |
| **Deadline** | If no majority is reached by the configured deadline, the vote closes as **EXPIRED** and the override is **DENIED** (fail-closed). |
| **Fail-closed** | Any error in the quorum engine (bad config, Discord API failure, unparseable trust result) causes the job to exit 1, keeping the PR blocked. |

### Quorum math

Simple majority means strictly more than 50% of the **total quorum size** (not just those who voted). Abstentions count against approval — a member who does not vote reduces the effective approval percentage, creating an incentive for all members to participate.

| Quorum size | Votes needed (threshold = 0.5) |
|---|---|
| 1 | 1 |
| 2 | 2 |
| 3 | 2 |
| 4 | 3 |
| 5 | 3 |
| 6 | 4 |
| 7 | 4 |

Formula: `required = floor(size × threshold) + 1`

### Audit log

Every quorum event writes one row to Google Sheets with 33 columns:

| Column | Description | Example |
|---|---|---|
| `quorum_id` | Unique ID for this vote | `QR-1748441234-A3F9C1` |
| `package` / `version` / `ecosystem` | Package identity | `lodash` / `4.17.20` / `npm` |
| `source_repository` | Registry or artifact proxy URL the package was fetched from | `https://registry.npmjs.org` |
| `trust_level` | Computed band: `HIGH`, `MEDIUM`, or `LOW` | `MEDIUM` |
| `trust_level_score` | Numeric score 0–100 | `45` |
| `sig_status` | `valid`, `invalid`, or `none` | `valid` |
| `sig_algorithm` | Cryptographic algorithm used | `rsa-sha256` |
| `sig_strength` | `strong`, `weak`, or `none` | `weak` |
| `sig_key_id` | Key fingerprint or Sigstore log ID | `4d8f2a3c...` |
| `chk_status` | `verified`, `mismatch`, or `none` | `verified` |
| `chk_algorithm` | Hash algorithm used for checksum | `sha256` |
| `flag_typosquatting` | `true` if name resembles a known package | `false` |
| `flag_behavior_change` | `true` if new version requests new permissions/network access | `true` |
| `flag_author_reputation` | `true` if maintainer is new or activity pattern is suspicious | `false` |
| `flag_provenance` | `true` if no verifiable commit history or SLSA attestation | `false` |
| `trust_deductions` | Pipe-separated list of all deductions applied | `-20 weak algorithm \| -20 behavior change` |
| `trust_outcome` | Original trust check result | `blocked` |
| `update_reason` | PR title + body, flattened (max 500 chars) | `fix(deps): bump lodash \| Addresses CVE-2021-23337…` |
| `initiated_at` / `deadline` | Vote open and expiry timestamps | ISO 8601 |
| `quorum_size` / `threshold` | Eligible voters and approval fraction | `3` / `0.5` |
| `approve_count` / `deny_count` / `abstain_count` | Vote tally | `2` / `1` / `0` |
| `final_verdict` | `APPROVED`, `DENIED`, or `EXPIRED` | `APPROVED` |
| `decided_by` | `QUORUM_VOTE` or `DEADLINE` | `QUORUM_VOTE` |
| `voter_detail` | Per-voter breakdown | `✅ alice (111...) \| ❌ carol (333...)` |
| `discord_message_id` | Links back to the exact embed | `1234567890123456789` |
| `github_pr` / `run_id` | PR URL and Actions run ID | Full URL / numeric |
| `override_rationale` | Summary sentence | `Quorum override: 2/3 approved` |

Update the Sheets header row to match the new column order:

```
quorum_id | package | version | ecosystem | source_repository |
trust_level | trust_level_score |
sig_status | sig_algorithm | sig_strength | sig_key_id |
chk_status | chk_algorithm |
flag_typosquatting | flag_behavior_change | flag_author_reputation | flag_provenance |
trust_deductions | trust_outcome | update_reason | initiated_at | deadline |
quorum_size | threshold | approve_count | deny_count | abstain_count |
final_verdict | decided_at | decided_by | voter_detail |
discord_message_id | github_pr | run_id | override_rationale
```

---

## Setup guide

### 1. Create the Discord bot

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

> **Finding your own Discord user ID (to add as a quorum member):** Developer Mode on → right-click your username anywhere in Discord → **Copy User ID**.

### 2. Set up Google Sheets audit log

1. Go to [Google Cloud Console](https://console.cloud.google.com) → **APIs & Services → Enable APIs** → enable **Google Sheets API**.
2. Go to **IAM & Admin → Service Accounts** → **Create Service Account**.
   - Name: `dep-trust-sheets` (or similar)
   - Role: **Editor**, or a custom role with `spreadsheets.values.append`
3. Click the service account → **Keys** → **Add Key → Create new key → JSON**. Download the file.
4. Base64-encode the JSON key for the secret:
   ```bash
   # Linux / macOS
   base64 -w0 service-account.json

   # macOS (if -w0 not supported)
   base64 -i service-account.json | tr -d '\n'
   ```
   The output becomes `SHEETS_CREDENTIALS`.
5. Create a blank Google Sheet. Copy the spreadsheet ID from the URL:
   ```
   https://docs.google.com/spreadsheets/d/THIS_IS_THE_ID/edit
   ```
   This becomes `SHEETS_SPREADSHEET_ID`.
6. Share the Sheet with the service account's `client_email` (from the JSON file) with **Editor** access.
7. Rename the first tab to `QuorumAuditLog` (or set `SHEETS_SHEET_NAME` to match).
8. Add a header row with these column names — the engine appends data rows below row 1:
   ```
   quorum_id | package | version | ecosystem | source_repository |
   trust_level | trust_level_score |
   sig_status | sig_algorithm | sig_strength | sig_key_id |
   chk_status | chk_algorithm |
   flag_typosquatting | flag_behavior_change | flag_author_reputation | flag_provenance |
   trust_deductions | trust_outcome | update_reason | initiated_at | deadline |
   quorum_size | threshold | approve_count | deny_count | abstain_count |
   final_verdict | decided_at | decided_by | voter_detail |
   discord_message_id | github_pr | run_id | override_rationale
   ```

### 3. Configure quorum members

Edit `.github/quorum-config.json` in your repository:

```json
{
  "members": [
    "111111111111111111",
    "222222222222222222",
    "333333333333333333"
  ],
  "threshold": 0.5,
  "deadlineHours": 24
}
```

Replace the placeholder IDs with real Discord user IDs. Commit and push — no other changes are needed to add or remove voters.

| Field | Type | Default | Description |
|---|---|---|---|
| `members` | string array | — | Discord user IDs eligible to vote. **Required.** |
| `threshold` | float | `0.5` | Fraction of quorum required for majority. `0.5` = strictly more than half. |
| `deadlineHours` | integer | `24` | Hours before an undecided vote closes as EXPIRED (DENIED). |

All three fields can be overridden at runtime via environment variables (`QUORUM_MEMBERS`, `QUORUM_THRESHOLD`, `QUORUM_DEADLINE_HOURS`) without committing config changes — useful for testing.

### 4. Add GitHub secrets

Go to **Settings → Secrets and variables → Actions → New repository secret**:

| Secret name | Value | Required |
|---|---|---|
| `DISCORD_BOT_TOKEN` | Bot token from step 1 | ✅ Yes |
| `DISCORD_CHANNEL_ID` | Approval channel ID from step 1 | ✅ Yes |
| `DISCORD_GUILD_ID` | Server ID from step 1 | ✅ Yes |
| `SHEETS_CREDENTIALS` | Base64-encoded service account JSON from step 2 | ✅ Yes |
| `SHEETS_SPREADSHEET_ID` | Spreadsheet ID from step 2 | ✅ Yes |
| `OSV_API_KEY` | OSV.dev API key (if required by your oss-trust config) | Optional |
| `SIEM_HEC_ENDPOINT` | Splunk/SIEM HEC endpoint URL | Optional |
| `SIEM_HEC_TOKEN` | Splunk/SIEM HEC token | Optional |

> `GITHUB_TOKEN` is provided automatically by GitHub Actions — do not add it as a secret.

### 5. Add repository files

Copy these files into your repository at the exact paths shown:

```
.github/
├── workflows/
│   └── dep-trust-check.yml       ← main workflow
├── scripts/
│   ├── post-trust-comment.js     ← posts trust result to PR
│   └── quorum-engine.js          ← Discord quorum engine
└── quorum-config.json            ← member list and policy

scripts/
└── extract_dep_changes.py        ← you provide this
```

`extract_dep_changes.py` receives `--base <sha>` and `--head <sha>` and must write to `$GITHUB_OUTPUT`:

```
packages=[{"package":"lodash","version":"4.17.20","ecosystem":"npm"}]
```

Output `packages=[]` if no dependency files changed.

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

zero_day:
  required_approvers: 2
  token_ttl_hours: 6
  max_exceptions_per_24h: 3

sandbox:
  runtime: gvisor           # gvisor | firecracker | docker
  network: none
  timeout_seconds: 120
```

### `.github/quorum-config.json`

```json
{
  "members": ["<discord_user_id>", "..."],
  "threshold": 0.5,
  "deadlineHours": 24
}
```

### Environment variable overrides for quorum

| Variable | Overrides | Format |
|---|---|---|
| `QUORUM_MEMBERS` | `members` | Comma-separated Discord user IDs: `"111,222,333"` |
| `QUORUM_THRESHOLD` | `threshold` | Float string: `"0.5"` |
| `QUORUM_DEADLINE_HOURS` | `deadlineHours` | Integer string: `"48"` |
| `SHEETS_SHEET_NAME` | Sheet tab name | String: `"QuorumAuditLog"` |

### Supported ecosystems

`npm` · `pypi` · `cargo` · `go` · `maven` · `nuget` · `rubygems`

---

## Trust outcomes

| Outcome | Meaning | PR check | Quorum triggered |
|---|---|---|---|
| `approved` | Passed all trust gates | ✅ Green | No |
| `hold` | Advisory notice; no block | ✅ Green | No |
| `pending_quorum` | External quorum process required | ✅ Green | No (external) |
| `quarantined` | Flagged; override possible | 🔴 Red | **Yes** |
| `blocked` | Blocked; override possible | 🔴 Red | **Yes** |

### Trust level scoring

The quorum embed shows a computed trust level drawn from six signal categories in `trust-result.json`. This gives voters a single at-a-glance risk score covering cryptographic integrity, checksum verification, and supply-chain provenance — not just the binary blocked/quarantined outcome.

| Band | Score | Meaning |
|---|---|---|
| 🟢 HIGH | 80–100 | Strong integrity signals; low additional risk |
| 🟡 MEDIUM | 50–79 | One or more moderate concerns; review carefully before approving |
| 🔴 LOW | 0–49 | Significant integrity or provenance concerns; strong justification required |

**Deductions applied to the base score of 100 (cumulative, floor at 0):**

*Cryptographic integrity*

| Condition | Deduction |
|---|---|
| No cryptographic signature | −40 |
| Signature present but weak algorithm (RSA < 3072-bit, SHA-1, GPG without transparency log) | −20 |
| Signature present but verification failed | −10 |
| No published checksum, or checksum mismatch | −15 |

*Provenance and supply-chain*

| Condition | Deduction |
|---|---|
| Typosquatting — package name closely resembles a known popular package | −25 |
| Behavioral change — new version requests permissions or network access not present previously | −20 |
| Author reputation — new or changed maintainer, or sudden activity surge after long inactivity | −15 |
| Provenance/activity — no verifiable commit history or SLSA attestation | −10 |

A LOW trust level does not automatically change the quorum threshold, but it is logged in the audit record and displayed prominently in the embed so voters can weight their decision accordingly. Teams may choose to require a higher approval count for LOW-trust packages by setting a per-band threshold override in `quorum-config.json`.

**Strong vs. weak signature algorithms:**

| Algorithm | Strength |
|---|---|
| ed25519, ECDSA-P256 or higher, RSA ≥ 3072-bit, Sigstore/Cosign | Strong |
| RSA < 3072-bit, SHA-1 signed, MD5 signed, GPG without Sigstore transparency log | Weak |
| No signature present | None |

---

## Project structure

```
oss-trust-framework/
├── src/
│   ├── age_check/        # Gate 1 — release timestamp validation
│   ├── signature/        # Gate 2 — Sigstore / GPG verification
│   ├── trust/            # Gate 3 — out-of-band trust aggregation
│   ├── sbom/             # Gate 4 — SBOM delta and hash pinning
│   ├── sandbox/          # Gate 5 — behavioral sandbox
│   ├── zeroday/          # Expedited lane — CVE validation + quorum
│   └── pipeline/         # Orchestrator — runs all gates in sequence
├── tests/
├── docs/
├── config/
│   └── pipeline.yaml
├── .github/
│   ├── workflows/
│   │   └── dep-trust-check.yml
│   ├── scripts/
│   │   ├── post-trust-comment.js
│   │   └── quorum-engine.js
│   └── quorum-config.json
├── scripts/
│   └── extract_dep_changes.py
├── .env.example
└── pyproject.toml
```

---

## Troubleshooting

**Quorum job never starts**

The `quorum-override` job only runs when `validate` exits with `result == 'failure'`. Check that the `Enforce trust outcome` step in `validate` is actually exiting 1 for your package's outcome. Look at the validate job logs for `::error ::Trust check failed`.

**Discord embed not appearing**

- Verify `DISCORD_BOT_TOKEN`, `DISCORD_CHANNEL_ID`, and `DISCORD_GUILD_ID` are set correctly in secrets.
- Confirm the bot has been invited to the server and has the required permissions in the specific channel (not just server-level).
- Check the `Run quorum engine` step logs for `HTTP 4xx` errors from the Discord API.

**Reactions not being counted**

- Confirm **Message Content Intent** is enabled on the bot in the Discord Developer Portal.
- Verify voter Discord user IDs in `quorum-config.json` are the 18-19 digit numeric IDs. Usernames and display names will not work.
- The bot's own seed reactions are filtered out automatically — this is expected.

**Google Sheets append failing**

- Confirm the service account email has been shared on the spreadsheet with Editor access.
- Verify `SHEETS_CREDENTIALS` is the full base64-encoded JSON with no line breaks.
- Verify `SHEETS_SPREADSHEET_ID` is just the ID portion of the URL, not the full URL.
- Check that the Google Sheets API is enabled in the Google Cloud project that owns the service account.

**Vote expired before anyone voted**

The default deadline is 24 hours. For testing, set `QUORUM_DEADLINE_HOURS=1` as an environment variable override. The GitHub Actions job `timeout-minutes` is set to 1500 (25 hours) to accommodate the default — if you increase `deadlineHours` beyond 24, increase `timeout-minutes` proportionally.

**PR check stays red after quorum approved**

The `quorum-override` job exit code drives the PR check. If the job shows green but the PR check is still red, a different required check may be failing. Check **Settings → Branches → Branch protection rules** to see which checks are marked as required.

**Zero-day expedited lane not triggering**

Confirm the CVE is present in at least 2 of the 3 required sources (NVD, OSV, GHSA) and that `oss-trust zeroday request` is being called with valid `--cve`, `--package`, `--version`, and `--requester` flags. Check `config/pipeline.yaml` for `zero_day.max_exceptions_per_24h` — if the circuit breaker has tripped, the lane is suspended until the window resets.

---

## Prerequisite best practices

The OSS Trust Framework augments a mature dependency security posture — it does not replace one. The following controls should be in place in your environment regardless of whether this framework is deployed. Without them, the framework addresses only part of the threat surface.

### Why pinning alone is not enough

Pinning to known-good versions is a necessary baseline, but in today's landscape — where malicious open-source packages have surged and attackers specifically target developer tooling, CI/CD secrets, and credentials — a set-and-forget approach to pinning can trap you in maintenance debt while leaving you exposed to sophisticated attacks. Malware campaigns are optimized for developer workflows, exploiting typosquatting, dependency confusion, and hijacked legitimate accounts. Continuous validation is required.

### 1. Local curation and perimeter controls

You cannot rely on public registries (npm, PyPI, Maven, etc.) to act as your first line of defense. Malware often stays live on public registries for hours or days before being reported and removed.

**Establish a single source of truth.** Direct all developer machines and CI/CD pipelines to pull exclusively from a managed private artifact repository (Artifactory, Nexus, Cloudsmith). Block direct access to public registries at the network layer.

**Automate edge curation.** Implement proxy policies that quarantine any package or update that is less than 30 days old, has a brand-new maintainer, or lacks verifiable history. This quarantine period gives the community time to discover and report zero-day malicious packages before they reach your builds.

**Prevent dependency confusion.** Ensure internal private package names are explicitly registered or scoped (e.g. `@yourorg/package`) on public registries. An unregistered internal name can be hijacked by an attacker publishing a higher-versioned public package with the same name, which your build system will pull automatically.

### 2. Advanced version pinning and cryptographic anchoring

**Pin via lockfiles with cryptographic hashes.** Pinning `package==1.2.3` in a manifest file alone is insufficient — mirror attacks and package tampering can still substitute content. Always commit lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`) that mandate SHA-256 or SHA-512 hashes for every dependency and transitive dependency.

**Verify code provenance.** Prioritize packages that adhere to the [SLSA framework](https://slsa.dev) and use cryptographic signing (Sigstore/Cosign) to provide a verifiable chain of custody from source repository to binary registry. This is what Gate 2 and the trust level scoring in this framework validate.

### 3. Sandboxing and runtime isolation

**Disable arbitrary execution hooks.** Many package managers execute installation scripts automatically (npm `preinstall`/`postinstall`). This is the primary injection vector for malware targeting environment variables, SSH keys, and cloud credentials. Disable these globally during installation (e.g. `npm install --ignore-scripts`) unless explicitly audited and whitelisted. This is what Gate 5 (sandbox) in this framework tests for.

**Network-isolate build environments.** Run CI/CD runners in isolated, ephemeral environments with strict egress-filtered network policies. A build pipeline rarely needs unrestricted internet access; blocking unknown outbound connections prevents a compromised package from exfiltrating secrets to an attacker's C2 server.

### 4. Active vulnerability and behavioral analysis

**Incorporate behavioral analysis.** Static CVE scanning is insufficient for catching malware, because malware rarely receives a CVE before it strikes. Use Software Composition Analysis tooling that monitors package behavior — flagging packages that attempt to access `/etc/passwd`, spawn unexpected shells, or make outbound network requests to unlisted domains.

**Use reachability analysis.** To avoid alert fatigue, use tools that determine whether a vulnerable or suspicious code path is actually reachable in your application's active execution paths, rather than flagging dead code in sub-dependencies.

### 5. Guardrails for AI-assisted development

**Address AI package hallucinations.** Large language models frequently hallucinate non-existent packages or recommend abandoned, vulnerable libraries. Ensure automated guardrails in your pipeline catch and block illegitimate package references before they reach a build stage.

**Govern non-human identities.** Treat AI coding agents as first-class citizens. Assign them specific non-human identities, limit their access via least privilege, and continuously audit their package pulls.

### Summary checklist

| Control | Defense layer | What it addresses |
|---|---|---|
| Private proxy repository | Perimeter | Blocks unvetted public code; enforces licensing policies |
| Age-based quarantine (≥30 days) | Perimeter | Prevents immediate consumption of newly published zero-day malware |
| `--ignore-scripts` flag | Build / install | Neutralizes malicious installation hooks targeting credentials |
| Cryptographic lockfiles (SHA-256/512) | Configuration | Ensures the exact same untampered binary is used across all environments |
| Egress-filtered CI/CD runners | Infrastructure | Stops compromised packages from exfiltrating secrets |
| Sigstore / SLSA provenance | Supply chain | Provides verifiable chain of custody from source to binary |
| Behavioral SCA tooling | Runtime | Catches malware that has no CVE at time of publish |
| Scoped internal package names | Registry | Prevents dependency confusion attacks |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All PRs must pass the framework's own pipeline check — we eat our own cooking.

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
