# Commit instructions for this update

## Step 1 — Delete stale file that is triggering CodeQL alerts
The file `src/check_all.py` was created in an earlier commit and is a stale
duplicate. It is not part of the intended source layout and contains the
CWE-20 URL substring sanitization vulnerability. Delete it:

```bash
git rm src/check_all.py
```

## Step 2 — Stage all changes
```bash
git add oss_trust_framework/check_all.py   # CWE-20 fix: _extract_github_repo()
git add scripts/check_all.py               # CWE-20 fix: _extract_github_repo()
git add oss_trust_framework/cli.py         # registers check-all command
git add pyproject.toml                     # bumped min versions for all Dependabot alerts
git add requirements.txt                   # pinned to patched versions
git add framework_deps.txt                 # pinned to patched versions
```

## Step 3 — Commit
```bash
git commit -m "fix: resolve all CodeQL + Dependabot security alerts

CodeQL CWE-20 (Incomplete URL substring sanitization) — 14 alerts:
- Added _extract_github_repo() using urllib.parse hostname validation
- Fixes oss_trust_framework/check_all.py lines 215,226,238,249
- Fixes scripts/check_all.py lines 189,201,211,222,236
- Deletes stale src/check_all.py (unfixed duplicate, not in package layout)

Dependabot — 5 alerts in requirements.txt:
- cryptography: bumped >=44.0.1 (OpenSSL wheel CVE, subgroup attack, DNS constraints)
- python-dotenv: bumped >=1.2.2 (symlink following arbitrary file overwrite)
- pyproject.toml dependency floor raised to match
"
```

## Step 4 — Verify
After pushing, check Security > Code scanning — all 5 open alerts should
auto-close within ~10 minutes once CodeQL re-scans the branch.
The Dependabot PR can then be closed as resolved manually.
