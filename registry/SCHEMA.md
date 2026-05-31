# Registry Data Schema

## Package file schema

Each package has one JSON file at `registry/packages/{ecosystem}/{package-name}.json`.
For scoped npm packages, `@` and `/` are replaced with `__` (e.g. `@scope/pkg` → `__scope__pkg.json`).

```json
{
  "package":   "lodash",
  "ecosystem": "npm",
  "updated_at": "2026-05-28T15:30:00Z",
  "contribution_count": 14,

  "aggregate": {
    "approved_count":   9,
    "denied_count":     4,
    "expired_count":    1,
    "band_votes": {
      "HIGH":   3,
      "MEDIUM": 7,
      "LOW":    4
    },
    "community_band": "MEDIUM",
    "slsa_levels_observed": [0, 1, 2],
    "signal_fire_counts": {
      "typosquatting":      0,
      "behavior_change":    2,
      "author_reputation":  1,
      "provenance_activity": 3,
      "ai_hallucination":   0,
      "no_signature":       4,
      "weak_signature":     6,
      "no_checksum":        2
    }
  },

  "versions": {
    "4.17.21": {
      "contribution_count": 8,
      "approved_count":  6,
      "denied_count":    2,
      "expired_count":   0,
      "community_band":  "MEDIUM",
      "slsa_levels_observed": [1, 2],
      "signal_fire_counts": {
        "behavior_change":     1,
        "weak_signature":      4,
        "no_checksum":         1
      },
      "first_seen":  "2026-01-10T09:00:00Z",
      "last_updated": "2026-05-28T15:30:00Z"
    }
  }
}
```

### Community band calculation

The `community_band` is computed from the `band_votes` distribution:

```
LOW    if denied_count / contribution_count > 0.5   → "LOW"  (majority denied)
LOW    if band_votes.LOW / contribution_count > 0.5  → "LOW"  (majority low trust)
MEDIUM if band_votes.LOW / contribution_count > 0.25 → "MEDIUM"
HIGH   otherwise
```

Version-level `community_band` uses the same logic scoped to that version's contributions.

---

## Contribution payload schema

Submitted as the body of a GitHub Issue titled:
`[registry-contribution] {ecosystem}/{package}@{version}`

```json
{
  "schema_version": "1.0",
  "package":        "lodash",
  "version":        "4.17.21",
  "ecosystem":      "npm",
  "evaluated_at":   "2026-05-28T14:00:00Z",

  "trust_band":     "MEDIUM",
  "slsa_level":     1,
  "verdict":        "APPROVED",

  "signals_fired": {
    "typosquatting":       false,
    "behavior_change":     true,
    "author_reputation":   false,
    "provenance_activity": false,
    "ai_hallucination":    false,
    "no_signature":        false,
    "weak_signature":      true,
    "no_checksum":         false
  },

  "contribution_id": "sha256-of-quorum-id-plus-timestamp",
  "framework_version": "2.0.0"
}
```

### Validation rules enforced by the ingest workflow

| Field | Rule |
|---|---|
| `schema_version` | Must be `"1.0"` |
| `package` | Alphanumeric, `-`, `_`, `.`, `/`, `@` only; max 200 chars |
| `version` | Semver or semver-like; max 50 chars |
| `ecosystem` | One of: npm, pypi, cargo, go, maven, nuget, rubygems |
| `trust_band` | One of: HIGH, MEDIUM, LOW |
| `slsa_level` | Integer 0–4 |
| `verdict` | One of: APPROVED, DENIED, EXPIRED |
| `signals_fired` | All values must be boolean; no extra keys |
| `contribution_id` | SHA-256 hex string; used for deduplication |
| `evaluated_at` | ISO 8601 datetime |
| No PII | Ingest workflow rejects any field containing email, IP, username patterns |

---

## Index file schema

`registry/index.json` is a lightweight lookup table rebuilt on every ingest:

```json
{
  "generated_at": "2026-05-28T15:30:00Z",
  "entry_count":  342,
  "entries": {
    "npm/lodash": {
      "path":               "registry/packages/npm/lodash.json",
      "community_band":     "MEDIUM",
      "contribution_count": 14,
      "last_updated":       "2026-05-28T15:30:00Z"
    },
    "pypi/requests": {
      "path":               "registry/packages/pypi/requests.json",
      "community_band":     "HIGH",
      "contribution_count": 31,
      "last_updated":       "2026-05-27T10:00:00Z"
    }
  }
}
```

The engine fetches `index.json` first (one HTTP request), checks whether the
package is present, then fetches the specific package file only if needed.
Both files are served via the GitHub raw content API.
