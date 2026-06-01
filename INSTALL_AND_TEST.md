# OSS Trust Framework — Installation & Test Guide

**Version:** 2.0.0  
**Author:** Chris Gillham  
**Repo:** github.com/chrisgillham/oss-trust-framework

This document covers every step required to go from a fresh clone to a fully
operational nine-gate dependency trust pipeline with Discord / Teams / Slack
quorum voting, runtime SIEM telemetry, and the GitHub-native public trust
registry.

---

## Table of Contents

- [System requirements](#system-requirements)
- [Part 1 — Local development setup](#part-1--local-development-setup)
  - [1.1 Clone and install](#11-clone-and-install)
  - [1.2 Environment variables](#12-environment-variables)
  - [1.3 Configuration files](#13-configuration-files)
  - [1.4 Verify the CLI](#14-verify-the-cli)
  - [1.5 Run the test suite](#15-run-the-test-suite)
- [Part 2 — GitHub repository setup](#part-2--github-repository-setup)
  - [2.1 Upload repository files](#21-upload-repository-files)
  - [2.2 Workflow permissions](#22-workflow-permissions)
  - [2.3 Create issue labels](#23-create-issue-labels)
  - [2.4 Add GitHub secrets](#24-add-github-secrets)
  - [2.5 Configure branch protection](#25-configure-branch-protection)
- [Part 3 — Notification platform setup](#part-3--notification-platform-setup)
  - [3.1 Discord](#31-discord)
  - [3.2 MS Teams](#32-ms-teams)
  - [3.3 Slack](#33-slack)
- [Part 4 — Google Sheets audit log](#part-4--google-sheets-audit-log)
- [Part 5 — Public trust registry](#part-5--public-trust-registry)
- [Part 6 — Quorum member configuration](#part-6--quorum-member-configuration)
- [Part 7 — SIEM / runtime telemetry](#part-7--siem--runtime-telemetry)
- [Part 8 — End-to-end test](#part-8--end-to-end-test)
  - [8.1 Test the registry ingest workflow](#81-test-the-registry-ingest-workflow)
  - [8.2 Test the full pipeline locally](#82-test-the-full-pipeline-locally)
  - [8.3 Test the quorum workflow in GitHub Actions](#83-test-the-quorum-workflow-in-github-actions)
  - [8.4 Test the zero-day expedited lane](#84-test-the-zero-day-expedited-lane)
- [Part 9 — Optional integrations](#part-9--optional-integrations)
  - [9.1 Reachability analysis (Endor Labs)](#91-reachability-analysis-endor-labs)
  - [9.2 Socket.dev behavioral analysis](#92-socketdev-behavioral-analysis)
  - [9.3 gVisor sandbox](#93-gvisor-sandbox)
- [Troubleshooting](#troubleshooting)
- [Verification checklist](#verification-checklist)

---

## System requirements

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.11+ | 3.12 recommended |
| Node.js | 18+ | Required for quorum engine only |
| Docker | 24+ | Required for Gate 7 sandbox (optional) |
| gVisor (`runsc`) | Any | Optional — Docker fallback used if absent |
| Git | 2.30+ | For `extract_dep_changes.py` SHA operations |
| OS | Linux / macOS | Windows requires WSL2 for sandbox gate |
| GitHub account | Any plan | Public repo for registry; Actions for CI/CD |

---

## Part 1 — Local development setup

### 1.1 Clone and install

```bash
# Clone the framework repo
git clone https://github.com/chrisgillham/oss-trust-framework.git
cd oss-trust-framework

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows (PowerShell)

# Install the framework and all runtime dependencies
pip install -e .

# Install development dependencies (pytest, ruff, mypy, coverage)
pip install -e ".[dev]"

# Verify the CLI is available
oss-trust --help
```

Expected output:
```
Usage: oss-trust [OPTIONS] COMMAND [ARGS]...

  OSS Trust Framework — supply chain trust validation.

Options:
  --help  Show this message and exit.

Commands:
  anomaly   Report a runtime anomaly for a monitored package.
  check     Run the full nine-gate trust pipeline against a single package.
  zeroday   Zero-day expedited lane commands.
```

---

### 1.2 Environment variables

```bash
# Copy the template and fill in your values
cp .env.example .env
```

Open `.env` and populate the fields relevant to your setup. At minimum for
local testing you need:

```bash
# Required for GitHub API calls (contributions, PR comments)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Required for whichever notification platform you choose
QUORUM_PLATFORM=discord           # discord | teams | slack
```

All other variables are optional for local testing — the pipeline gates that
require external credentials gracefully degrade to HOLD rather than failing.

To load the variables into your shell:

```bash
# Linux / macOS — using a dotenv-compatible loader
set -a && source .env && set +a

# Or use python-dotenv if already installed
pip install python-dotenv
python -c "from dotenv import load_dotenv; load_dotenv()"
```

---

### 1.3 Configuration files

The framework ships with reference configurations. Copy and customise them:

```bash
# Pipeline gate configuration (age thresholds, SLSA minimums, license allowlist, etc.)
# The file is already at config/pipeline.yaml — review and adjust for your org
vi config/pipeline.yaml

# Policy-as-code quorum governance
# Replace Discord user ID placeholders with real IDs
vi config/policy.yaml
```

Key settings to review before first run:

```yaml
# config/pipeline.yaml

age_gate:
  hard_block_hours: 24    # Raise to 72 for stricter environments
  hold_hours: 72

trust_scoring:
  min_score: 60           # Lower to 40 for permissive mode during initial rollout

reachability:
  enabled: false          # Set true only after configuring an adapter
  adapter: endor_labs

sandbox:
  runtime: docker         # Use 'none' to skip sandbox during initial setup

public_registry:
  enabled: false          # Enable after completing Part 5
```

---

### 1.4 Verify the CLI

Run the pipeline against a well-known, stable package to confirm the local
install is working. This will make real HTTP calls to OSV, OpenSSF, and
deps.dev:

```bash
# Should complete in ~10 seconds and exit 0
oss-trust check \
  --package requests \
  --version 2.32.3 \
  --ecosystem pypi \
  --config config/pipeline.yaml \
  --output table
```

Expected: Gates 1–9 all show APPROVED or HOLD (no credentials means some
optional gates degrade gracefully). Trust score should be 60–100/100.

```bash
# Test JSON output (this is what the GitHub Actions workflow uses)
oss-trust check \
  --package requests \
  --version 2.32.3 \
  --ecosystem pypi \
  --output json | jq '{outcome, trust_score, trust_level}'
```

Expected:
```json
{
  "outcome": "approved",
  "trust_score": 80,
  "trust_level": "HIGH"
}
```

---

### 1.5 Run the test suite

```bash
# Run all tests with coverage
pytest tests/ -v --tb=short

# Run with coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Run a specific test file
pytest tests/test_license.py -v
pytest tests/test_policy.py -v
pytest tests/test_registry_ingest.py -v

# Run only fast tests (skip integration markers if you add them)
pytest tests/ -v -m "not integration"
```

Expected output (all tests pass):

```
tests/test_age_check.py          ....          4 passed
tests/test_ai_hallucination.py   .....         5 passed
tests/test_cicd_audit.py         ......        6 passed
tests/test_extract_dep_changes.py ............. 13 passed
tests/test_license.py            ......        6 passed
tests/test_pipeline.py           .......       7 passed
tests/test_policy.py             .....         5 passed
tests/test_registry_ingest.py    .................... 20 passed
tests/test_zeroday.py            .....         5 passed

============ 71 passed in X.XXs ============
```

Run the linter and type checker:

```bash
# Lint (zero warnings expected)
ruff check src/ scripts/ tests/

# Type check
mypy src/
```

---

## Part 2 — GitHub repository setup

All steps in this part are performed in the GitHub web interface at
`github.com/chrisgillham/oss-trust-framework`.

### 2.1 Upload repository files

The files from the zip map directly to paths in the repo. Use
**Add file → Create new file** for new files or the **pencil icon → Edit**
for existing ones.

**New files to create** (paste content from the zip):

| Path in repo | From zip |
|---|---|
| `registry/README.md` | `registry/README.md` |
| `registry/SCHEMA.md` | `registry/SCHEMA.md` |
| `registry/index.json` | `registry/index.json` |
| `registry/packages/npm/lodash.json` | `registry/packages/npm/lodash.json` |
| `registry/packages/pypi/.gitkeep` | Empty file (type `.gitkeep` as content) |
| `registry/packages/cargo/.gitkeep` | Same |
| `registry/packages/go/.gitkeep` | Same |
| `registry/packages/maven/.gitkeep` | Same |
| `registry/packages/nuget/.gitkeep` | Same |
| `registry/packages/rubygems/.gitkeep` | Same |
| `scripts/extract_dep_changes.py` | `scripts/extract_dep_changes.py` |
| `scripts/registry_ingest.py` | `scripts/registry_ingest.py` |
| `.github/workflows/registry-ingest.yml` | `.github/workflows/registry-ingest.yml` |
| `.github/scripts/quorum-engine.js` | `.github/scripts/quorum-engine.js` |
| `.github/scripts/post-trust-comment.js` | `.github/scripts/post-trust-comment.js` |
| `.github/quorum-config.json` | `.github/quorum-config.json` |
| `.github/approved-actions.json` | `.github/approved-actions.json` |
| `config/pipeline.yaml` | `config/pipeline.yaml` |
| `config/policy.yaml` | `config/policy.yaml` |
| `src/` (all modules) | All files under `src/` |
| `tests/` (all test files) | All files under `tests/` |
| `correlation-rules/` | All files under `correlation-rules/` |
| `pyproject.toml` | `pyproject.toml` |
| `.env.example` | `.env.example` |
| `CONTRIBUTING.md` | `CONTRIBUTING.md` |

**Existing file to update:**

| Path | What changed |
|---|---|
| `.github/workflows/dep-trust-check.yml` | Fixed duplicate `env:` block; added Teams/Slack secrets; added runtime-monitor-register job |

> **Tip:** For `src/` and `tests/` which contain many files, use the GitHub web
> editor's drag-and-drop upload via **Add file → Upload files** to upload
> multiple files at once.

---

### 2.2 Workflow permissions

The `registry-ingest.yml` workflow pushes commits to the repo. GitHub Actions
needs write permission.

1. Go to **Settings → Actions → General**
2. Under **Workflow permissions**, select **Read and write permissions**
3. Click **Save**

If you prefer a scoped PAT instead of broad write access:

1. Go to **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**
2. Set resource owner to your account
3. Select the `oss-trust-framework` repository only
4. Under **Repository permissions**: `Contents` → Read and write, `Issues` → Read and write
5. Generate and copy the token
6. Go to **Settings → Secrets and variables → Actions → New repository secret**
7. Name: `REGISTRY_BOT_TOKEN`, Value: your PAT
8. In `registry-ingest.yml`, replace both occurrences of `secrets.GITHUB_TOKEN` with `secrets.REGISTRY_BOT_TOKEN`

---

### 2.3 Create issue labels

Go to **Issues → Labels → New label** and create these four:

| Label name | Suggested color | Description |
|---|---|---|
| `registry-contribution` | `#0075ca` (blue) | Automated registry contribution from OSS Trust pipeline |
| `accepted` | `#0e8a16` (green) | Contribution successfully merged into registry |
| `rejected-validation` | `#e4e669` (yellow) | Contribution failed schema validation |
| `rejected-rate-limit` | `#e4e669` (yellow) | Contribution rejected — rate limit (1 per package per 24 h) |

---

### 2.4 Add GitHub secrets

Go to **Settings → Secrets and variables → Actions → New repository secret** and add each secret below. Only add the secrets relevant to your chosen notification platform and enabled integrations.

**Always required:**

| Secret name | Value | Where to get it |
|---|---|---|
| `GITHUB_TOKEN` | Auto-provided | GitHub Actions provides this automatically — do not add manually |
| `SHEETS_CREDENTIALS` | Base64-encoded Google service account JSON | See Part 4 |
| `SHEETS_SPREADSHEET_ID` | Spreadsheet ID from URL | See Part 4 |

**Notification platform (add the set matching `QUORUM_PLATFORM`):**

| Secret name | Platform | Value |
|---|---|---|
| `QUORUM_PLATFORM` | All | `discord`, `teams`, or `slack` |
| `DISCORD_BOT_TOKEN` | Discord | Bot token from Discord Developer Portal |
| `DISCORD_CHANNEL_ID` | Discord | Numeric channel ID |
| `DISCORD_GUILD_ID` | Discord | Numeric server ID |
| `TEAMS_WEBHOOK_URL` | Teams | Incoming webhook URL |
| `TEAMS_VOTE_WEBHOOK_URL` | Teams | Azure Function / Logic App URL for vote callbacks |
| `SLACK_BOT_TOKEN` | Slack | Bot OAuth token (`xoxb-...`) |
| `SLACK_CHANNEL_ID` | Slack | Channel ID (`C...`) |
| `SLACK_VOTE_WEBHOOK_URL` | Slack | Slack app Interactivity Request URL |

**Policy-as-code named roles (use platform-appropriate member IDs):**

| Secret name | Value |
|---|---|
| `CISO_DISCORD_ID` | Platform member ID for CISO |
| `SECURITY_ARCH_DISCORD_ID` | Platform member ID for Security Architect |
| `LEGAL_DISCORD_ID` | Platform member ID for Legal |

**Optional integrations:**

| Secret name | Value |
|---|---|
| `SIEM_HEC_ENDPOINT` | Splunk HEC URL (e.g. `https://splunk.org.com:8088/services/collector`) |
| `SIEM_HEC_TOKEN` | Splunk HEC token |
| `ANOMALY_WEBHOOK_URL` | Webhook your SIEM calls on runtime anomaly detection |
| `OSV_API_KEY` | OSV.dev API key |
| `SOCKET_API_KEY` | Socket.dev API key |
| `ENDOR_LABS_API_KEY` | Endor Labs API key |
| `ENDOR_LABS_PROJECT_UUID` | Endor Labs project UUID |

---

### 2.5 Configure branch protection

To make the pipeline a required gate on pull requests:

1. Go to **Settings → Branches → Add branch protection rule**
2. Branch name pattern: `main`
3. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require status checks to pass before merging
   - In the search box, add: `Validate` (the validate job from `dep-trust-check.yml`)
4. Save

This means any PR touching a dependency file cannot merge until `validate` passes (or `quorum-override` approves an exception).

---

## Part 3 — Notification platform setup

Only configure the platform you chose in `QUORUM_PLATFORM`. Skip the others.

### 3.1 Discord

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications) → **New Application** → name it (e.g. `oss-trust-bot`)
2. Left sidebar → **Bot** → **Reset Token** → copy → `DISCORD_BOT_TOKEN` secret
3. Under **Privileged Gateway Intents** → enable **Message Content Intent**
4. Left sidebar → **OAuth2 → URL Generator**:
   - Scopes: `bot`
   - Bot permissions: `Send Messages`, `Add Reactions`, `Read Message History`, `Embed Links`, `View Channels`
5. Copy the generated URL → open in browser → invite bot to your server
6. In Discord, enable Developer Mode: **Settings → Advanced → Developer Mode**
7. Right-click your server name → **Copy Server ID** → `DISCORD_GUILD_ID` secret
8. Right-click your approval channel → **Copy Channel ID** → `DISCORD_CHANNEL_ID` secret

**Finding your member ID (to add to quorum-config.json):**
Developer Mode on → right-click your username anywhere → **Copy User ID**

---

### 3.2 MS Teams

1. In Teams, navigate to your approval channel → **•••** → **Connectors** → **Incoming Webhook** → **Configure**
2. Name it `OSS Trust Quorum`, optionally add a logo → **Create**
3. Copy the webhook URL → `TEAMS_WEBHOOK_URL` secret
4. Deploy a vote callback endpoint (one of):
   - **Azure Function** (recommended): Create an HTTP-triggered function that receives `POST {quorum_id, vote, member_id, member_name}` and responds `{ "type": "message", "text": "Vote recorded" }`. Set the URL as `TEAMS_VOTE_WEBHOOK_URL`.
   - **Logic App**: Use the HTTP Request trigger with the same request/response contract.
   - **ngrok** (testing only): Run `ngrok http 3000` on the Actions runner and set the ngrok URL as `TEAMS_VOTE_WEBHOOK_URL`.

**Finding Azure AD Object IDs (for quorum members):**
Azure Portal → **Azure Active Directory → Users** → click user → **Object ID**

---

### 3.3 Slack

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App → From scratch**
2. Name: `OSS Trust Bot`, select your workspace
3. Left sidebar → **OAuth & Permissions → Scopes → Bot Token Scopes** → add:
   - `chat:write`
   - `chat:write.public`
   - `users:read`
4. **Install to Workspace** → copy the **Bot User OAuth Token** → `SLACK_BOT_TOKEN` secret
5. Left sidebar → **Interactivity & Shortcuts** → toggle **On** → set **Request URL** to `SLACK_VOTE_WEBHOOK_URL`
6. Save Changes
7. In Slack, invite the bot to your approval channel: `/invite @your-bot-name`
8. Right-click the channel name → **Copy Link** → the ID is the `C...` portion at the end → `SLACK_CHANNEL_ID` secret

**Finding your Slack member ID (for quorum members):**
Click any user's profile → **•••** (More actions) → **Copy member ID**

---

## Part 4 — Google Sheets audit log

The audit log records every quorum vote in full detail — 33+ columns per event.

1. **Enable the Sheets API:**
   Go to [console.cloud.google.com](https://console.cloud.google.com) → **APIs & Services → Enable APIs & Services** → search "Google Sheets API" → **Enable**

2. **Create a service account:**
   **IAM & Admin → Service Accounts → Create Service Account**
   - Name: `oss-trust-audit`
   - Role: **Editor** (or a custom role with only `spreadsheets.values.append`)
   - Click **Done**

3. **Generate a JSON key:**
   Click the service account → **Keys** → **Add Key → Create new key → JSON** → **Create**
   A JSON file downloads automatically.

4. **Base64-encode the key:**
   ```bash
   # Linux / macOS
   base64 -w0 service-account.json

   # macOS (if -w0 not available)
   base64 -i service-account.json | tr -d '\n'
   ```
   Copy the output → `SHEETS_CREDENTIALS` secret

5. **Create the spreadsheet:**
   Open [sheets.google.com](https://sheets.google.com) → **Blank spreadsheet**
   Copy the ID from the URL:
   ```
   https://docs.google.com/spreadsheets/d/THIS_IS_THE_ID/edit
   ```
   → `SHEETS_SPREADSHEET_ID` secret

6. **Share the sheet:**
   Click **Share** → paste the service account email (from the JSON file, field `client_email`) → set role to **Editor** → **Share**

7. **Add the header row:**
   Rename the first tab to `QuorumAuditLog`, then paste this into row 1 (one value per cell, A1 through AH1):

   ```
   quorum_id | package | version | ecosystem | source_repository |
   platform | notification_message_id |
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

## Part 5 — Public trust registry

The registry lives in this GitHub repo — no external server required.

1. Confirm the `registry/` directory and `registry-ingest.yml` workflow are committed (Part 2.1)
2. Confirm workflow write permissions are set (Part 2.2)
3. Confirm the four labels are created (Part 2.3)
4. In `config/pipeline.yaml`, set `public_registry.enabled: true`
5. Commit the config change to main

The registry is now active. When a package clears quorum, the engine automatically opens a `[registry-contribution]` issue. The `registry-ingest.yml` workflow processes it within ~30 seconds.

To verify the read path is working, the raw URLs below should return JSON without any authentication:

```
https://raw.githubusercontent.com/chrisgillham/oss-trust-framework/main/registry/index.json
https://raw.githubusercontent.com/chrisgillham/oss-trust-framework/main/registry/SCHEMA.md
```

---

## Part 6 — Quorum member configuration

The framework uses a **three-tier quorum model**. The right people vote on each decision — the engineers and ops staff who know the dependency are the first line, with security and legal stepping in only when the risk profile warrants it.

### The three tiers

**Tier 1 — Team Quorum (day-to-day)**

These are the people closest to the code. For routine `QUARANTINE` and `BLOCKED` outcomes in standard-criticality applications, they vote alone with no centralized security or legal involvement required. Aim for 3–7 people per application team.

Who to add:
- Lead developer or tech lead for the application
- At least one senior engineer
- DevOps or platform engineer responsible for the pipeline
- Product owner or engineering manager (optional — adds business context)

Who NOT to add: Do not put CISO or Legal in the day-to-day team quorum. Their involvement is triggered automatically by policy rules when the risk profile warrants it, not by default.

**Tier 2 — AppSec Escalation**

Application Security team members are added to the quorum pool — not replacing the team — when risk signals exceed team-level thresholds. Prior team votes are retained when escalation occurs. AppSec members can also join voluntarily when team members @mention them.

Triggers (automatic, via `policy.yaml`):
- Trust score < 40
- Behavior change or author reputation flags
- SLSA level 0 on auth/crypto/TLS dependency
- Team quorum expires without majority

**Tier 3 — Enterprise Escalation (CISO and Legal)**

Reserved for mission-critical applications, copyleft or commercial license changes, AI hallucination attacks, and runtime anomaly revocations. They are also in the **reporting visibility** list for all quorum events in their scope — so they have full portfolio awareness without needing to vote on every routine decision.

### Setting up each tier

**Step 1: Set the team tier members** in `.github/quorum-config.json`:

```json
{
  "platform": "discord",
  "tiers": {
    "team": {
      "members": [
        "your-lead-dev-id",
        "your-senior-engineer-id",
        "your-devops-engineer-id"
      ],
      "threshold": 0.5,
      "deadline_hours": 24
    },
    "appsec": {
      "members": [
        "your-appsec-lead-id",
        "your-security-engineer-id"
      ],
      "threshold": 0.5,
      "deadline_hours": 12
    },
    "enterprise": {
      "named_roles": {
        "CISO":               "your-ciso-id",
        "SECURITY_ARCH":      "your-security-architect-id",
        "LEGAL_COUNSEL":      "your-legal-counsel-id",
        "COMPLIANCE_OFFICER": "your-compliance-officer-id"
      }
    }
  },
  "reporting_visibility": {
    "always_notify": {
      "members": ["your-ciso-id"]
    },
    "notify_on_elevated_and_above": {
      "members": ["your-security-architect-id", "your-compliance-officer-id"]
    },
    "notify_on_mission_critical_only": {
      "members": ["your-legal-counsel-id"]
    }
  }
}
```

**Step 2: Set the application criticality class** — this controls which tier starts the quorum and when escalation is mandatory. Add this as a GitHub secret (`APP_CRITICALITY`) or set it in `config/pipeline.yaml`:

| Class | Who votes | When |
|---|---|---|
| `standard` | Team only | Internal tools, developer tooling |
| `elevated` | Team + AppSec lead required | Customer-facing, PII/PHI, external APIs |
| `mission_critical` | Team + AppSec + Security Architect required, CISO notified | Financial, healthcare, authentication |
| `critical_infrastructure` | All tiers, unanimous, CISO + Legal + Compliance required | SCADA, safety systems |

**Step 3: Add GitHub secrets** for each named role so policy.yaml can reference them:

| Secret | Who it identifies |
|---|---|
| `APPSEC_LEAD_ID` | Primary AppSec approver (Tier 2) |
| `APPSEC_MEMBER_IDS` | Comma-separated additional AppSec members |
| `CISO_DISCORD_ID` | CISO (Tier 3, required for high-severity rules) |
| `DEPUTY_CISO_ID` | Deputy CISO (backup for CISO rules) |
| `SECURITY_ARCH_DISCORD_ID` | Security Architect |
| `LEGAL_DISCORD_ID` | Legal Counsel |
| `LEGAL_TECH_ID` | Legal technology contact |
| `COMPLIANCE_OFFICER_ID` | Compliance Officer |

**Member ID format by platform:**

| Platform | Format | How to find |
|---|---|---|
| Discord | 18-19 digit number e.g. `123456789012345678` | Developer Mode → right-click username → Copy User ID |
| Teams | GUID e.g. `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Azure Portal → Azure AD → Users → user → Object ID |
| Slack | Starts with `U` e.g. `U0123ABCDE` | Profile → ••• → Copy member ID |

### Reporting visibility for senior stakeholders

The `reporting_visibility` section in `quorum-config.json` controls who receives a summary notification after every quorum verdict — regardless of whether they voted. This gives CISO, Legal, and Compliance full portfolio awareness without requiring their participation in every routine decision.

**Always notify** (`always_notify.members`): Receives a summary of every quorum event across all applications. Add the CISO here.

**Elevated and above** (`notify_on_elevated_and_above.members`): Notified for elevated and mission-critical application events only. Add Security Architects and Compliance Officers here.

**Mission-critical only** (`notify_on_mission_critical_only.members`): Notified only for mission-critical and critical-infrastructure events. Add Legal Counsel here.

**Weekly digest**: Enable `reporting_visibility.digest.enabled: true` and set `channel_id` to a `#security-quorum-digest` channel visible to security leadership. The digest summarizes all quorum events in the past 7 days across the portfolio.

### Escalation flow

```
PR opened → team quorum posts to #approvals-{team}
                │
                ├─ Team reaches majority → APPROVED or DENIED
                │
                └─ Trust score < 40 or behavior flags → AppSec escalation
                            │
                            ├─ AppSec + team reach majority → APPROVED or DENIED
                            │
                            └─ AI hallucination / typosquatting / mission-critical
                                        │
                                        └─ CISO + Legal enterprise quorum
                                                    │
                                                    └─ Expires → DENIED + incident record
```


---

## Part 7a — SBOM management

Gate 6 (SBOM Delta) generates a complete, up-to-date CycloneDX 1.6 SBOM as a side-effect of every pipeline run. The SBOM covers all direct and transitive dependencies discovered during the trust evaluation — not just the packages listed in your manifest files.

### What gets generated

After every PR that modifies a dependency file, Gate 6 writes:

```
sbom/
├── manifest.json              ← Index of all SBOM files with component counts
├── sbom-npm.cdx.json          ← CycloneDX 1.6 JSON for npm dependencies
├── sbom-pypi.cdx.json         ← CycloneDX 1.6 JSON for PyPI dependencies
├── sbom-cargo.cdx.json        ← CycloneDX 1.6 JSON for Cargo dependencies
└── sbom-go.cdx.json           ← etc.
```

Each SBOM file contains:
- Every package in the full transitive dependency tree (not just direct dependencies)
- Package URL (purl) for each component
- SHA-256 hash where available from deps.dev
- SLSA level observed during the trust evaluation
- Dependency graph (root → all transitive)
- Metadata linking back to the OSS Trust Framework run ID

### SBOM artifact upload

Every validate job run uploads the `sbom/` directory as a GitHub Actions artifact (`sbom-{ecosystem}`) retained for 90 days. You can download SBOMs for any PR run from the Actions tab without needing to merge the PR.

### SBOM commit on merge

When a PR merges to main, the `runtime-monitor-register` job commits the updated SBOM files directly to the repository. This keeps the repo's `sbom/` directory always in sync with the actual deployed dependency state.

To enable this, ensure the workflow has `contents: write` permission (already set in `dep-trust-check.yml`).

### Configuring SBOM output

In `config/pipeline.yaml`:

```yaml
sbom:
  generate_sbom: true          # Enable SBOM generation (default: true)
  sbom_formats: ["json"]       # json | xml | both
  sbom_output_dir: "sbom"      # Output directory
  commit_sbom: false           # Auto-commit (handled by runtime-monitor-register job)
```

### Consuming the SBOM

The generated SBOMs are standard CycloneDX 1.6 and can be consumed by:
- **Dependency-Track** — upload `sbom-{ecosystem}.cdx.json` to your Dependency-Track instance for continuous vulnerability tracking
- **GitHub Dependency Graph** — submit via the GitHub Dependency Submission API (see below)
- **SIEM / GRC tools** — parse `manifest.json` for component inventory reporting
- **Legal / procurement** — export component list with license information for open-source review

### Submitting to GitHub Dependency Graph

Add this step to the `runtime-monitor-register` job to keep GitHub's Dependency Graph accurate:

```yaml
- name: Submit SBOM to GitHub Dependency Graph
  uses: advanced-security/spdx-dependency-submission-action@v0.0.1
  with:
    filePath: "sbom/"
    filePattern: "*.cdx.json"
```

Or use the GitHub Dependency Submission API directly with the generated CycloneDX JSON.

---

## Part 7 — SIEM / runtime telemetry

Skip this part if you don't have a SIEM. The pipeline runs fully without it — telemetry events are silently dropped if the HEC endpoint is not configured.

**Splunk:**

1. In Splunk: **Settings → Data Inputs → HTTP Event Collector → New Token**
2. Name: `oss-trust-framework`, Source type: `oss_trust:pipeline`
3. Copy the token → `SIEM_HEC_TOKEN` secret
4. Set `SIEM_HEC_ENDPOINT` to your HEC URL, e.g.:
   ```
   https://splunk.yourorg.com:8088/services/collector
   ```
5. Import the correlation search:
   - **Settings → Searches, Reports, and Alerts → New Search**
   - Paste contents of `correlation-rules/splunk/oss_trust_runtime_anomaly.spl`
   - Schedule: Real-time, rolling 5-minute window

**Elastic / Sentinel:**

Import the detection rule JSON from `correlation-rules/elastic/` or `correlation-rules/sentinel/` using your SIEM's rule import interface. Replace the `{{PLACEHOLDER}}` values with your environment's specifics before importing.

**Anomaly webhook:**

When your SIEM fires the correlation rule, it should POST to `ANOMALY_WEBHOOK_URL`. The expected payload is:

```json
{
  "package":             "lodash",
  "version":             "4.17.21",
  "quorum_id":           "QR-1748441234-A3F9C1",
  "anomaly_type":        "sensitive_file_access",
  "severity":            "high",
  "days_since_approval": 3,
  "environment":         "production"
}
```

The engine's `oss-trust anomaly` CLI command can be used to simulate this:

```bash
oss-trust anomaly \
  --package lodash \
  --version 4.17.21 \
  --quorum-id QR-1748441234-A3F9C1 \
  --anomaly-type sensitive_file_access \
  --severity high \
  --days-since-approval 3
```

---

## Part 8 — End-to-end test

Work through these tests in order. Each one validates a larger slice of the system.

### 8.1 Test the registry ingest workflow

This verifies the `registry-ingest.yml` workflow, issue parsing, validation, file merge, and git commit.

1. In your repo, go to **Issues → New issue**
2. Set the title exactly:
   ```
   [registry-contribution] pypi/requests@2.32.3
   ```
3. Paste this body:
   ````
   ```json
   {
     "schema_version": "1.0",
     "package": "requests",
     "version": "2.32.3",
     "ecosystem": "pypi",
     "evaluated_at": "2026-05-28T14:00:00Z",
     "trust_band": "HIGH",
     "slsa_level": 2,
     "verdict": "APPROVED",
     "signals_fired": {
       "typosquatting": false,
       "behavior_change": false,
       "author_reputation": false,
       "provenance_activity": false,
       "ai_hallucination": false,
       "no_signature": false,
       "weak_signature": false,
       "no_checksum": false
     },
     "contribution_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
     "framework_version": "2.0.0"
   }
   ```
   ````
4. Add the label `registry-contribution`
5. Submit the issue
6. Go to **Actions** → click the `Registry contribution ingest` run

**Expected results:**
- Workflow completes in < 60 seconds
- `registry/packages/pypi/requests.json` is created in the repo
- `registry/index.json` is updated with a `pypi/requests` entry
- A commit appears: `"registry: ingest contribution from issue #N"`
- The issue is closed with a ✅ acceptance comment

**Test a rejection (bad schema):**

Open another issue titled `[registry-contribution] npm/lodash@4.17.21` with this body:

```json
{ "schema_version": "2.0", "package": "lodash" }
```

Expected: workflow rejects it, posts an ❌ comment listing the validation errors, closes the issue with label `rejected-validation`.

---

### 8.2 Test the full pipeline locally

```bash
# Test an old, well-known package — should APPROVE
oss-trust check \
  --package requests \
  --version 2.32.3 \
  --ecosystem pypi \
  --output table

# Test with JSON output and check all fields are present
oss-trust check \
  --package click \
  --version 8.1.7 \
  --ecosystem pypi \
  --output json | jq '{
    outcome,
    trust_score,
    trust_level,
    policy_applied,
    gates: [.gate_results[].gate]
  }'

# Test zero-day request CLI
oss-trust zeroday request \
  --cve CVE-2024-99999 \
  --package requests \
  --version 2.32.4 \
  --requester test@example.com
# Expected: approved: false (CVE not confirmed by 2+ sources — this is a fake CVE)

# Test anomaly CLI
oss-trust anomaly \
  --package requests \
  --version 2.32.3 \
  --quorum-id QR-TEST-000001 \
  --anomaly-type test_anomaly \
  --severity low \
  --days-since-approval 1
# Expected: JSON response with action: "logged" or "quorum_reopened"
```

---

### 8.3 Test the quorum workflow in GitHub Actions

This requires a target repository (can be a test repo) that has `dep-trust-check.yml` installed and the secrets configured.

1. In the target repo, create a test branch:
   ```bash
   git checkout -b test/oss-trust-quorum-test
   ```

2. Create a `requirements-test.txt` with a pinned dependency that will trigger the age gate:
   ```bash
   echo "requests==2.32.3" > requirements-test.txt
   git add requirements-test.txt
   git commit -m "test: trigger OSS Trust pipeline"
   git push origin test/oss-trust-quorum-test
   ```

3. Open a pull request from this branch

4. Go to **Actions** and watch `Dependency trust validation` run

5. The `detect-changes` job should detect `requests==2.32.3` in `requirements-test.txt`

6. The `validate` job should run the nine gates

**To test the quorum flow specifically**, you need a package that will be flagged. The easiest way without waiting for an actual new release is to temporarily lower the age gate threshold:

```yaml
# In config/pipeline.yaml (temporarily for testing)
age_gate:
  hard_block_hours: 99999   # Block almost everything to force quorum
```

Commit this change to your test branch. The validate job will exit 1, triggering `quorum-override`, which will post to your configured notification platform.

**Expected quorum flow:**
1. A vote request appears in your Discord channel / Teams channel / Slack
2. React or click ✅ (or wait for the deadline to expire as DENIED to test the denial path)
3. The quorum engine detects the reaction/click within 30 seconds
4. The Discord embed / Teams card / Slack message updates with the verdict
5. An audit row appears in Google Sheets
6. A PR comment is posted with the verdict table
7. The GitHub Actions check goes green (APPROVED) or stays red (DENIED)

Restore `pipeline.yaml` after testing.

---

### 8.4 Test the zero-day expedited lane

The zero-day lane validates CVEs against NVD, OSV, and GHSA. For testing, use a real CVE that exists in multiple sources:

```bash
# CVE-2022-42969 is real, affects py (npm), and exists in OSV + NVD
oss-trust zeroday request \
  --cve CVE-2022-42969 \
  --package py \
  --version 1.11.0 \
  --requester security@yourorg.com \
  --ticket https://github.com/your-org/your-repo/issues/1

# Expected: approved: true (or false depending on CVE source availability)
# The response includes which sources confirmed the CVE

# Validate the token that was issued
TOKEN=$(oss-trust zeroday request \
  --cve CVE-2022-42969 --package py --version 1.11.0 \
  --requester test@test.com 2>/dev/null | jq -r .token)

oss-trust zeroday validate-token --token "$TOKEN" --package py
# Expected: {"valid": true}
```

---

## Part 9 — Optional integrations

### 9.1 Reachability analysis (Endor Labs)

Reachability analysis (Gate 4.5) reduces false positives by downgrading QUARANTINE → HOLD when flagged code is unreachable in your application.

1. Sign up at [endorlabs.com](https://endorlabs.com) and create a project
2. Copy the API key and project UUID
3. Add secrets: `ENDOR_LABS_API_KEY`, `ENDOR_LABS_PROJECT_UUID`
4. In `config/pipeline.yaml`:
   ```yaml
   reachability:
     enabled: true
     adapter: endor_labs
     on_unreachable: hold
   ```
5. Install the optional extra:
   ```bash
   pip install -e ".[reachability-endor]"
   ```

For Snyk reachability, use `adapter: snyk` and set `SNYK_TOKEN` + `SNYK_ORG_ID`.

---

### 9.2 Socket.dev behavioral analysis

Socket.dev provides behavioral analysis in Gate 4 (OOB Trust), flagging packages that make unexpected network connections during install.

1. Sign up at [socket.dev](https://socket.dev) and generate an API key
2. Add secret: `SOCKET_API_KEY`
3. The Gate 4 OOB trust aggregator will automatically include Socket signals — no config change needed

---

### 9.3 gVisor sandbox

Gate 7 runs package installs in an isolated sandbox. By default it uses Docker. For stronger isolation with gVisor:

1. Install gVisor on your build runners:
   ```bash
   # Ubuntu
   curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
   sudo apt-get update && sudo apt-get install -y runsc
   sudo runsc install
   sudo systemctl restart docker
   ```

2. Update `config/pipeline.yaml`:
   ```yaml
   sandbox:
     runtime: gvisor
     network: none
   ```

3. For GitHub-hosted runners, gVisor is not pre-installed. Use a self-hosted runner with gVisor, or keep `runtime: docker` for cloud CI.

---

## Troubleshooting

**`oss-trust` command not found after install:**
```bash
# Ensure your virtual environment is active
source .venv/bin/activate
# Verify the package installed
pip show oss-trust-framework
# Reinstall if needed
pip install -e .
```

**`registry-ingest.yml` workflow doesn't trigger:**
- Confirm the workflow file is on the default branch (`main`)
- Confirm the issue has the label `registry-contribution` OR the title starts with `[registry-contribution]`
- Check **Actions** is enabled: **Settings → Actions → General → Allow all actions**

**Quorum engine exits immediately with "no quorum required":**
The `trust-result.json` outcome is not `blocked` or `quarantined`. Check the validate job logs — the package may have passed all gates, or the outcome may be `rejected` (which bypasses quorum).

**Discord reactions not being counted:**
- Confirm **Message Content Intent** is enabled in the Discord Developer Portal for your bot
- Verify the voter's numeric user ID in `quorum-config.json` — not their username or display name
- Check that the bot has not been rate-limited (Discord allows ~5 requests/second)

**Teams vote not registering:**
- The `TEAMS_VOTE_WEBHOOK_URL` must be publicly reachable from the internet — the Teams backend POSTs to it when a card button is clicked
- Verify the endpoint responds with `{ "type": "message", "text": "..." }` within 5 seconds or Teams will show an error to the voter

**Slack button click shows error:**
- Confirm **Interactivity & Shortcuts** is enabled in your Slack app settings
- Confirm the **Request URL** matches `SLACK_VOTE_WEBHOOK_URL` exactly (Slack validates with a challenge request on save)
- The engine's local HTTP server on port `3000` must be reachable from Slack's servers

**Google Sheets append fails with 403:**
- Confirm the spreadsheet has been shared with the service account email (`client_email` in the JSON key file) with **Editor** access
- Verify `SHEETS_CREDENTIALS` is the full base64-encoded JSON with no line breaks or spaces
- Confirm the Google Sheets API is enabled in the same Google Cloud project as the service account

**`dep-trust-check.yml` fails with "Invalid workflow file":**
- Ensure there is no duplicate `env:` block on any step (the previous bug on line 260 is fixed in the current zip)
- Validate the YAML locally: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/dep-trust-check.yml'))"`

---

## Verification checklist

Use this checklist to confirm your installation is complete before going live.

**Local setup:**
- [ ] `oss-trust --help` shows the CLI commands
- [ ] `oss-trust check --package requests --version 2.32.3 --ecosystem pypi --output json` returns `"outcome": "approved"`
- [ ] All 71 tests pass: `pytest tests/ -v`
- [ ] Linter passes: `ruff check src/ scripts/ tests/`

**GitHub repository:**
- [ ] All source files committed to main
- [ ] `registry/index.json` exists and is valid JSON
- [ ] `registry-ingest.yml` workflow appears in **Actions → Workflows**
- [ ] `dep-trust-check.yml` workflow appears in **Actions → Workflows**
- [ ] Four issue labels created (`registry-contribution`, `accepted`, `rejected-validation`, `rejected-rate-limit`)
- [ ] Workflow permissions set to Read and write
- [ ] All required secrets added

**Notification platform:**
- [ ] `QUORUM_PLATFORM` secret set to `discord`, `teams`, or `slack`
- [ ] Platform-specific secrets added and verified
- [ ] Bot/app invited to the approval channel
- [ ] At least one quorum member ID added to `.github/quorum-config.json`

**Google Sheets:**
- [ ] Spreadsheet created and shared with service account
- [ ] Tab named `QuorumAuditLog`
- [ ] Header row populated
- [ ] `SHEETS_CREDENTIALS` and `SHEETS_SPREADSHEET_ID` secrets set

**Registry:**
- [ ] Test contribution issue opened, processed, and closed
- [ ] `registry/packages/pypi/requests.json` exists after test
- [ ] Raw content URL returns JSON in browser

**Quorum members:**
- [ ] Team tier members added to `.github/quorum-config.json` `tiers.team.members`
- [ ] AppSec tier members added to `tiers.appsec.members`
- [ ] Enterprise named roles set in `tiers.enterprise.named_roles`
- [ ] Reporting visibility members configured
- [ ] `APP_CRITICALITY` secret set per-repo
- [ ] `APPSEC_LEAD_ID` secret set
- [ ] All enterprise role secrets set (`CISO_DISCORD_ID`, `SECURITY_ARCH_DISCORD_ID`, etc.)

**SBOM:**
- [ ] `sbom/` directory exists in repo root (committed as empty with `.gitkeep`)
- [ ] After a test pipeline run, `sbom/sbom-{ecosystem}.cdx.json` is generated
- [ ] SBOM artifact visible in Actions run under `sbom-{ecosystem}`
- [ ] After merge to main, SBOM committed to repo by `runtime-monitor-register` job

**End-to-end:**
- [ ] Test PR opened in target repo
- [ ] `detect-changes` job runs and detects at least one package
- [ ] `validate` job runs all nine gates
- [ ] SBOM artifact uploaded successfully
- [ ] Quorum notification appears in approval channel (if a package was flagged)
- [ ] Correct tier fires (team for standard, AppSec added for elevated)
- [ ] Audit row appears in Google Sheets after quorum resolves
- [ ] Reporting visibility members receive post-verdict notification
- [ ] PR comment posted with verdict table
