# OSS Trust Framework — Development Backlog

> **Current version:** v0.5.0 — All gates fully operational.
> This document tracks planned improvements, known gaps, and contributor opportunities.
> See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

---

## Status overview

| Gate | Status | Notes |
|---|---|---|
| 0 — Name similarity | ✅ Complete | 3 algorithms: Levenshtein, prefix, char-swap |
| 1 — Age hold | ✅ Complete | Configurable thresholds |
| 2 — Provenance attestation | ✅ Complete | PyPI + npm Sigstore; GPG fallback needs keyring |
| 2.5a — Orphan commits | ✅ Complete | BFS graph walk, 180-day filter, trusted repos allowlist |
| 2.5b — Workflow permissions | ✅ Complete | Environment protection credit, 403-safe |
| 2.5c — PR provenance | ✅ Complete | 10+ tag formats, graceful degradation |
| 3 — OOB trust | ✅ Complete | OpenSSF, OSV, GHSA, deps.dev |
| 4 — SBOM delta | ✅ Complete | syft active, cross-platform, baselines pinned, CI workflow updated |
| 5 — Behavioral sandbox | ✅ Complete | strace active on Linux CI; gVisor for strongest isolation |
| Zero-day lane | ✅ Complete | 2-of-3 MFA quorum, 6h TTL, circuit breakers |

---

## Backlog items

### `cli.py` consolidation
**Priority:** Low — cosmetic, no behavior change
**Effort:** 15 minutes

The framework has two `cli.py` files that both need updating on every version bump:

- `oss_trust_framework/cli.py` — entry point called by the `.exe` launcher
- `oss_trust_framework/pipeline/cli.py` — full command implementation

The fix is to make the top-level file a thin re-export wrapper:

```python
# oss_trust_framework/cli.py
from oss_trust_framework.pipeline.cli import main

__all__ = ["main"]
```

After this change, version string, commands, and all logic live only in `pipeline/cli.py`.
Version bumps require editing one file instead of two.

---

### Gate 2 — GPG keyring population
**Priority:** Low — only needed for packages using GPG instead of Sigstore
**Effort:** 30 minutes per package

The GPG verification code in `oss_trust_framework/signature/gpg.py` is complete.
To activate it for a specific package:

1. Obtain the maintainer's public key from a trusted source (project README, verified Keybase profile)
2. Verify the fingerprint independently
3. Import: `gpg --import maintainer.asc`
4. Add the fingerprint to `TRUSTED_FINGERPRINTS` in `gpg.py`
5. Export the keyring: `gpg --export > config/trusted_keys/keyring.gpg`
6. Commit `config/trusted_keys/` to version control

> **Critical:** Never fetch keys from keyservers at verification time.

Most modern packages use PyPI Trusted Publishing via Sigstore, making GPG verification unnecessary.

---

### Gate 0 — Future algorithm improvements
**Priority:** Low
**Effort:** Varies

Current implementation uses three string similarity algorithms. Potential additions:

- **Soundex / phonetic similarity** — catches homophone-based attacks
- **Unicode homoglyph detection** — catches `rеquests` (Cyrillic `е`) vs `requests`
- **Semantic similarity** — embedding-based matching for semantically deceptive names
- **socket.dev integration** — external package reputation scoring as an additional signal

---

### Gate 5 — gVisor upgrade
**Priority:** Low — strace is functional; gVisor adds kernel-level isolation
**Effort:** 30 minutes

Gate 5 is active via strace. gVisor provides stronger isolation — IronWorm's eBPF
rootkit cannot escape the gVisor kernel boundary, whereas strace only captures
syscall events without preventing execution.

See [docs/gate5_gvisor_setup.md](docs/gate5_gvisor_setup.md) for full setup instructions.

---

## Scope boundary — not on the backlog by design

| Threat | Why out of scope | Recommended control |
|---|---|---|
| Runtime behavioral monitoring | Framework validates at install time only | Falco, Tetragon, eBPF runtime tools |
| Semantic package impersonation (low string similarity) | Gate 0 requires string similarity | socket.dev, manual allowlist review |
| Production application security | Different problem domain | SAST, DAST, RASP |
| MCP server runtime behavior | Post-install, not detectable at install time | Runtime monitoring |

See [docs/index.html#scope](https://chrisgillham.github.io/oss-trust-framework/#scope) for the full scope boundary table.

---

## OWASP CI/CD Top 10 coverage

All 10 risks fully addressed as of v0.5.0.

| Risk | Gate(s) |
|---|---|
| CICD-SEC-1: Insufficient Flow Control | Gate 1 age hold + zero-day quorum |
| CICD-SEC-2: Inadequate IAM | Gates 2.5b, 2.5c, zero-day separation of duties |
| CICD-SEC-3: Dependency Chain Abuse | Gates 0–5 (primary threat) |
| CICD-SEC-4: Poisoned Pipeline Execution | Gates 2.5a, 2.5b, 2.5c |
| CICD-SEC-5: Insufficient PBAC | Gate 2.5b — `id-token: write` audit |
| CICD-SEC-6: Insufficient Credential Hygiene | Gates 2, 5 behavioral patterns |
| CICD-SEC-7: Insecure System Configuration | Gate 2.5b — publisher repo config audit |
| CICD-SEC-8: Ungoverned 3rd Party Services | Gates 3, 4 — OOB trust + SBOM delta |
| CICD-SEC-9: Improper Artifact Integrity | Gates 2, 2.5a, 4 |
| CICD-SEC-10: Insufficient Logging | Every gate emits structured events |

---

*Last updated: 2026-06-07 · v0.5.0*
