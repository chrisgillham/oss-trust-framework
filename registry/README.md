# OSS Trust Public Registry

This directory is the community trust registry for the OSS Trust Framework.
It contains anonymized, aggregated verdict data contributed by participating
organizations across all ecosystems.

**Author:** Chris Gillham

---

## What this is

When `public_registry.enabled: true` is set in `config/pipeline.yaml`, the
OSS Trust Framework automatically contributes anonymized signal data each time
a package is evaluated through a quorum vote. This data accumulates here,
creating a crowd-sourced reputation score that benefits every organization
running the framework.

**What IS stored (anonymized aggregates only):**
- Package name, version, ecosystem
- Trust score band (HIGH / MEDIUM / LOW) — not the raw numeric score
- Verdict (APPROVED / DENIED / EXPIRED) — not voter identities
- Which signal categories fired — not their values
- SLSA level observed
- Contribution count (how many organizations have evaluated this package)

**What is NEVER stored:**
- Organization identity
- PR content or commit messages
- Quorum member names or IDs
- Internal package names
- Raw trust scores
- Voter decisions

---

## Directory structure

```
registry/
├── README.md                        ← this file
├── index.json                       ← fast-lookup index (package → file path → band)
├── SCHEMA.md                        ← full data schema documentation
└── packages/
    ├── npm/
    │   └── lodash.json              ← aggregated verdict history for lodash (npm)
    ├── pypi/
    │   └── requests.json
    ├── cargo/
    ├── go/
    ├── maven/
    ├── nuget/
    └── rubygems/
```

---

## How contributions work

The OSS Trust Framework engine contributes via a **GitHub Issue** on this
repository with the label `registry-contribution`. A GitHub Actions workflow
(`registry-ingest.yml`) validates the payload, merges it into the appropriate
package file, updates `index.json`, and closes the issue.

**Contribution issue format:**

```
Title: [registry-contribution] npm/lodash@4.17.21
Body:  (JSON payload — see SCHEMA.md)
```

Contributions are rate-limited to one per package per organization per 24 hours
to prevent ballot stuffing. The ingest workflow validates:
- JSON schema compliance
- Package name / ecosystem format
- No PII in any field
- Verdict is one of: APPROVED, DENIED, EXPIRED

---

## How scores are consumed

The framework reads the registry during pipeline evaluation. A package with a
community score band of LOW receives a −10 modifier on its trust score before
any local signal deductions are applied.

```yaml
public_registry:
  enabled: true
  repo: chrisgillham/oss-trust-framework   # This repo
  branch: main
  contribute_verdicts: true
  consume_community_scores: true
  community_score_weight: 0.15
```

Reads use the GitHub raw content API — no authentication required for the
public repo. Contributions use the GitHub Issues API with a PAT or the
repo's `GITHUB_TOKEN` from Actions.

---

## Community norms

- Contributions are welcome from any organization running the framework
- Do not submit fabricated or test data to the production registry
  (use `registry_mode: test` in `pipeline.yaml` to target the test branch)
- Contributions are irreversible — once merged they are part of the git history
- Maintainers may remove contributions that appear to be manipulated or invalid
