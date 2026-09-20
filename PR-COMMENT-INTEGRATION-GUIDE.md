# OSS Trust Framework — PR Comment Formatter Integration Guide

## What This Does

Instead of just showing ✅/⚠️/🚫 in the workflow logs, this formatter creates **clear, actionable PR comments** that tell users:
- What each package status is (APPROVED/QUARANTINE/BLOCKED)
- Why it has that status
- What to do about it

### Example Output

```
## ✅ OSS Trust Framework — APPROVED

Summary: 7 approved, 0 need review, 0 blocked (of 7 dependencies)

---

### ✅ cryptography==48.0.0

Outcome: APPROVED

**Passed:**
  ✅ Gate 1 — Age (24h+ threshold)
  ✅ Gate 3 — Out-of-Band Trust (OpenSSF Scorecard, CVEs)

✓ All gates passed. Safe to merge from a supply chain perspective.
```

Or if quarantined:

```
### ⚠️ some-package==1.0.0

Outcome: QUARANTINE

Details: OOB trust score 30/100 — threshold not met

**Needs Review:**
  ⚠️ Gate 3 — Out-of-Band Trust → Score 30/100 (threshold: 70)

⚠️ Manual review recommended.

This package passed age and provenance gates but has concerns:
- Very new release (< 24 hours old)
- Low OpenSSF Scorecard score (maintenance concerns)

Action:
1. Check the details above
2. Review the package's GitHub repo (if concerns exist)
3. If satisfied, merge this PR
4. If concerned, request an older or better-maintained version
```

---

## Integration Steps

### Step 1: Add the Formatter Script to Your Repo

```bash
# Create scripts directory
mkdir -p .github/scripts

# Copy the formatter
cp format_trust_check_pr_comment.py .github/scripts/format_trust_check.py

# Commit
git add .github/scripts/format_trust_check.py
git commit -m "feat: Add PR comment formatter for dependency trust checks"
git push origin main
```

### Step 2: Update Your Workflow

Replace `.github/workflows/oss-trust-check.yml` with `oss-trust-check-PRODUCTION.yml`:

```bash
# Copy the new workflow
cp oss-trust-check-PRODUCTION.yml .github/workflows/oss-trust-check.yml

# Commit
git add .github/workflows/oss-trust-check.yml
git commit -m "feat(ci): Add formatted PR comments to dependency trust checks"
git push origin main
```

### Step 3: Test It

Create a test PR that updates a dependency:

```bash
# Create a feature branch
git checkout -b test/dependency-update

# Update pyproject.toml or requirements.txt
# (e.g., bump a version)
git commit -am "test: Bump a dependency"
git push origin test/dependency-update
```

Then go to GitHub and create a PR. Within 30 seconds, you should see a comment like:

```
## ✅ OSS Trust Framework — APPROVED
...
```

---

## How It Works

1. **Run Trust Check:** `oss-trust check-all --output json` → `trust_report.json`
2. **Format Results:** Python script reads JSON and creates human-readable comment
3. **Post to PR:** GitHub Actions posts the comment automatically
4. **Gate Pass/Fail:** Workflow fails if any packages are blocked

---

## Customizing the Formatter

The formatter is a Python script in `.github/scripts/format_trust_check.py`. You can customize:

- **Guidance text** for QUARANTINE/BLOCKED outcomes
- **Gate descriptions** (what each gate checks)
- **Emoji/icons** (currently ✅/⚠️/🚫)
- **Comment structure** (add headers, links, etc.)

Example customizations:

```python
# In format_trust_check.py, change gate names:
gate_names = {
    "age": "Gate 1 — Must be 24h+ old",
    "oob_trust": "Gate 3 — Scorecard & CVEs",
    # ... add your own
}

# Change guidance text:
if outcome == "quarantined":
    comment += "\nYour custom quarantine guidance here..."
```

---

## Integration with GitHub Rulesets

Once you have PR comments working, you can make the trust check a **required status check**:

1. Go to **Settings → Rulesets → main**
2. Click **"+ Add checks"**
3. Search for: `Gate 1 — Dependency Trust Check`
4. Toggle it **ON** (required)
5. Save

Now PRs can't merge without the trust check passing! ✅

---

## Troubleshooting

### Comment Not Appearing

1. Check if workflow ran: **Actions tab → latest workflow run**
2. Check permissions: PR must have `pull-requests: write`
3. Check output: Look for error in "Post comment to PR" step

### Formatter Errors

If the Python script fails:

```bash
# Test locally
python .github/scripts/format_trust_check.py trust_report.json

# If it fails, check the error message
```

### JSON Not Being Generated

Make sure `oss-trust` is installed and working:

```bash
oss-trust check-all --manifest pyproject.toml --output json
```

---

## Next Steps (P0 Backlog)

1. ✅ **PR Comment Formatter** ← You're building this now
2. ⬜ **Slash Commands** — `/approve-quarantine` to override
3. ⬜ **Audit Trail** — Log who approved what and when
4. ⬜ **Scorecard API** — Live integration for gate 3
5. ⬜ **User Guidance Docs** — "Dependency Review Workflow" guide

---

## Testing the Example

You already have a great test case: **PR #70** (cryptography bump)

After deploying this, that PR should show:

```
## ⚠️ OSS Trust Framework — REVIEW NEEDED

Summary: 6 approved, 1 need review, 0 blocked (of 7 dependencies)

---

### ⚠️ cryptography==48.0.0

Outcome: QUARANTINE

Details: OOB trust score 30/100 — threshold not met

Gate 3 has concerns about the package's maintenance score.

Action: Review, then merge if satisfied.
```

Much better than just `FAILED: ['cryptography']`! 🎉
