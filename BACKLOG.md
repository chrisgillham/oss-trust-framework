# OSS Trust Framework — Development Backlog

> **Current version:** v0.4.0 — All gates operational.
> This document tracks planned improvements, known gaps, and contributor opportunities.
> See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

---

## Status overview

| Gate | Status | Notes |
|---|---|---|
| 0 — Name similarity | ✅ Complete | 3 algorithms: Levenshtein, prefix, char-swap |
| 1 — Age hold | ✅ Complete | Configurable thresholds |
| 2 — Provenance attestation | ✅ Complete | PyPI + npm; GPG fallback needs keyring |
| 2.5a — Orphan commits | ✅ Complete | BFS graph walk, 180-day filter, trusted repos allowlist |
| 2.5b — Workflow permissions | ✅ Complete | Environment protection credit, 403-safe |
| 2.5c — PR provenance | ✅ Complete | 10+ tag formats, graceful degradation |
| 3 — OOB trust | ✅ Complete | OpenSSF, OSV, GHSA, deps.dev |
| 4 — SBOM delta | ✅ Complete | Logic complete; syft binary required on runner |
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

The fix is to make the top-level file a thin re-export wrapper so there is only one real implementation:

```python
# oss_trust_framework/cli.py
from oss_trust_framework.pipeline.cli import main

__all__ = ["main"]
```

After this change, version string, commands, and all logic live only in `pipeline/cli.py`. Version bumps require editing one file instead of two.

---

### Gate 2 — GPG keyring population
**Priority:** Low — only needed for packages that use GPG instead of Sigstore
**Effort:** 30 minutes per package

The GPG verification code in `oss_trust_framework/signature/gpg.py` is complete. To activate it for a package:

1. Obtain the maintainer's public key from a trusted source (project README, verified Keybase profile)
2. Verify the fingerprint independently
3. Import: `gpg --import maintainer.asc`
4. Add the fingerprint to `TRUSTED_FINGERPRINTS` in `gpg.py`
5. Export the keyring: `gpg --export > config/trusted_keys/keyring.gpg`
6. Commit `config/trusted_keys/` to version control

> **Critical:** Never fetch keys from keyservers at verification time — this is itself an attack surface.

Most modern packages (httpx, cryptography, pydantic, rich, click, pyyaml) now use PyPI Trusted Publishing via Sigstore, making GPG verification unnecessary for them.

---

### Gate 4 — syft on CI runner
**Priority:** Medium — activates SBOM delta checking with no code changes
**Effort:** 5 minutes

The SBOM diff logic in `oss_trust_framework/sbom/differ.py` is complete. Gate 4 activates automatically once `syft` is installed on the runner. Add to your workflow:

```yaml
- name: Install syft (Gate 4 SBOM backend)
  run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

First run: automatically pins a baseline SBOM and returns PASS.
Subsequent runs: diffs against the pinned baseline — any unexpected transitive dependency triggers quarantine.

Commit `config/sbom-baselines/` to version control to track dependency graph changes over time.

---

### Gate 5 — gVisor upgrade
**Priority:** Low — strace is functional; gVisor adds kernel-level isolation
**Effort:** 30 minutes

Gate 5 is currently active via strace on Linux CI. gVisor provides stronger isolation — IronWorm's eBPF rootkit cannot escape the gVisor kernel boundary, whereas strace only captures syscall events without preventing execution.

See [docs/gate5_gvisor_setup.md](docs/gate5_gvisor_setup.md) for full setup instructions.

Add to your workflow before the `oss-trust check` steps:

```yaml
- name: Install gVisor
  run: |
    curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor \
      -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] \
      https://storage.googleapis.com/gvisor/releases release main" \
      | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
    sudo apt-get update && sudo apt-get install -y runsc
    sudo tee /etc/docker/daemon.json > /dev/null \
      <<< '{"runtimes":{"runsc":{"path":"/usr/local/sbin/runsc"}}}'
    sudo systemctl restart docker
```

Gate 5 auto-detects gVisor and uses it in preference to strace when available.

---

### Gate 0 — Future algorithm improvements
**Priority:** Low
**Effort:** Varies

Current implementation uses three string similarity algorithms. Potential additions:

- **Soundex / phonetic similarity** — catches homophone-based attacks
- **Unicode homoglyph detection** — catches `rеquests` (Cyrillic `е`) vs `requests`
- **Semantic similarity** — embedding-based matching for semantically deceptive names like `secure-requests` impersonating `requests`
- **socket.dev integration** — external package reputation scoring as an additional signal

---

## Scope boundary — not on the backlog by design

These are intentionally outside this framework's scope:

| Threat | Out-of-scope reason | Recommended control |
|---|---|---|
| Runtime behavioral monitoring | Framework validates at install time only | Falco, Tetragon, eBPF runtime tools |
| Semantic package impersonation (low string similarity) | Gate 0 requires string similarity | socket.dev, manual allowlist review |
| Production application security | Different problem domain | SAST, DAST, RASP |
| MCP server runtime behavior (e.g. BCC'ing outbound email) | Post-install, not detectable at install time | Runtime monitoring |

See [docs/index.html#scope](https://chrisgillham.github.io/oss-trust-framework/#scope) for the full scope boundary table.

---

## OWASP CI/CD Top 10 coverage

All 10 risks fully addressed as of v0.4.0.

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

*Last updated: 2026-06-07 · v0.4.0*
