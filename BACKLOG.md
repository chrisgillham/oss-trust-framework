# OSS Trust Framework — Development Backlog

> **Current version:** v0.5.1 — All gates fully operational for PyPI and npm.
> This document tracks planned improvements, known gaps, and contributor opportunities.
> See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

---

## Status overview

| Gate | Status | Notes |
|---|---|---|
| 0 — Name similarity | ✅ Complete | 3 algorithms: Levenshtein, prefix, char-swap |
| 1 — Age hold | ✅ Complete | Configurable thresholds; all 7 ecosystems |
| 2 — Provenance attestation | ✅ PyPI + npm · ⚠️ Cargo stub · ❌ Go/Maven/NuGet/RubyGems | Sigstore native on PyPI + npm; others return "not implemented" |
| 2.5a — Orphan commits | ✅ Complete | BFS graph walk, 180-day filter, trusted repos allowlist |
| 2.5b — Workflow permissions | ✅ Complete | Environment protection credit, 403-safe |
| 2.5c — PR provenance | ✅ Complete | 10+ tag formats, graceful degradation |
| 3 — OOB trust | ✅ Complete | OpenSSF, OSV, GHSA, deps.dev |
| 4 — SBOM delta | ✅ Complete | syft active, cross-platform, baselines pinned, CI workflow updated |
| 5 — Behavioral sandbox | ✅ Complete | strace active on Linux CI; gVisor for strongest isolation |
| Zero-day lane | ✅ Complete | 2-of-3 MFA quorum, 6h TTL, circuit breakers |

---

## Ecosystem registry coverage

### Current gate coverage by ecosystem

| Ecosystem | Gate 0 | Gate 1 | Gate 2 | Gate 2.5 | Gate 3 | Gate 4 | Gate 5 | Manifest parser |
|-----------|--------|--------|--------|----------|--------|--------|--------|----------------|
| **PyPI** | ✅ | ✅ | ✅ Sigstore | ✅ | ✅ | ✅ syft | ✅ | ✅ `requirements.txt` |
| **npm** | ✅ | ✅ | ✅ Sigstore | ✅ | ✅ | ✅ syft | ✅ | ✅ `package.json` |
| **Cargo** | ✅ | ✅ | ⚠️ stub | ✅ | ✅ | ✅ syft | ⚠️ no hooks | ✅ `Cargo.toml` |
| **RubyGems** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ✅ `Gemfile.lock` |
| **NuGet** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ✅ `packages.config` |
| **Go** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ❌ no hooks | ❌ no manifest parser |
| **Maven** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ❌ no manifest parser |

> **Legend:** ✅ = fully implemented · ⚠️ = partial or best-effort · ❌ = not yet implemented

### Notes on partial coverage

**Gate 2 (Provenance attestation):** PyPI Trusted Publishing and npm provenance are both Sigstore-native as of 2023/npm v9.5. Cargo, RubyGems, NuGet, Go, and Maven do not yet have end-to-end Sigstore pipelines with the same registry-level integration; Gate 2 falls back to the trusted publishers allowlist for these ecosystems.

**Gate 2.5 (CI/CD audit):** Works for all ecosystems once a GitHub repo is resolved from the package registry metadata. Repo discovery quality varies — PyPI and npm expose rich `project_urls`/`repository` fields; Go module paths encode the repo by convention; Maven metadata is inconsistent.

**Gate 5 (Behavioral sandbox):** Hooks to intercept at install time (`preinstall`/`postinstall` in npm, build scripts in Cargo) are ecosystem-specific. Go does not run install hooks. Maven plugins can run arbitrary code during build but are not captured by the current sandbox.

---

## Ecosystem backlog — prioritized by download volume and supply chain attack surface

Ecosystems are ordered by: (1) documented attack campaigns in the wild, (2) weekly download volume, (3) enterprise prevalence.

---

### 🔴 P1 — npm (Node.js) · *Baseline complete; deepen coverage*

**Priority:** High — npm is the largest registry by package count and the most-attacked ecosystem in 2025–2026 (IronWorm, TanStack, Miasma, Bitwarden CLI campaigns all targeted npm).

**Current state:** Gate 1 ✅ · Gate 2 ✅ · Gates 2.5 ✅ · Manifest parser ✅ (`package.json`)

**Remaining gaps:**

| Gap | Effort | Notes |
|-----|--------|-------|
| `package-lock.json` parser | 30 min | Resolves transitive deps, not just direct. More complete picture than `package.json`. |
| `yarn.lock` parser | 45 min | Yarn v1 format; distinct from npm lockfile. ~30% of Node projects use Yarn. |
| `pnpm-lock.yaml` parser | 45 min | pnpm growing share in monorepos. |
| Scoped package (`@org/pkg`) name-similarity tuning | 1 hr | Gate 0 currently strips `@scope/` prefix; a typosquat on scope is a real attack vector. |
| `npm audit` CVE integration into Gate 3 | 2 hr | `npm audit --json` output can augment OSV results. |

---

### 🔴 P1 — Go modules · *Age check only; needs manifest parser and Gate 2*

**Priority:** High — Go is #3 by enterprise adoption. GOPROXY supply chain attacks are documented. `go.sum` is a cryptographic lockfile that should be a first-class trust signal.

**Current state:** Gate 1 ✅ (via proxy.golang.org) · Gate 2 ❌ · Manifest parser ❌

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| `go.sum` parser | 1 hr | Line format: `module version h1:hash`. Extract module paths + versions. |
| `go.mod` parser | 45 min | `require` directives; less complete than `go.sum` but more human-readable. |
| Go module repo resolution | 1 hr | Module path IS the import path (e.g. `github.com/gin-gonic/gin`). Parse directly — no registry lookup needed. |
| Gate 2: `go.sum` hash verification | 2 hr | `h1:` is a SHA-256 of module zip. Compare against `go mod download -json` output. No Sigstore yet but GOPROXY checksum database (`sum.golang.org`) is an equivalent. |
| GOPROXY checksum DB integration | 2 hr | `sum.golang.org` provides module hash transparency log. Equivalent to Sigstore for Go. |

---

### 🟠 P2 — Maven (Java/JVM) · *Age check only; needs manifest parser*

**Priority:** High — Java dominates enterprise backends. Maven Central is one of the oldest package ecosystems and has seen several notable supply chain attacks (2022 ctx/phpass, Log4Shell amplified via transitive Maven deps).

**Current state:** Gate 1 ✅ (via Maven Central REST) · Gate 2 ❌ · Manifest parser ❌

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| `pom.xml` parser | 2 hr | XML; `<dependencies>` section. Handle `${property}` variable references (common in Spring projects). |
| `pom.xml` property resolution | 1 hr | Many version strings are `${spring.version}` — need to resolve from `<properties>` block. |
| Gradle (`build.gradle`) parser | 3 hr | Groovy DSL; regex-based. Two distinct dependency syntaxes: `'group:artifact:version'` and `group = "..." version = "..."`. |
| `gradle.lockfile` parser | 1 hr | Structured lockfile; simpler than `build.gradle`. |
| Maven artifact signing via Maven Central | 2 hr | Maven Central requires GPG signing for all uploads. PGP key verification is feasible via `keys.openpgp.org`. |
| Gate 2: Maven Central validation | 1 hr | Verify `groupId:artifactId:version` exists in Maven Central and was not yanked. |

---

### 🟠 P2 — Cargo (Rust) · *Mostly complete; Gate 2 stub needs implementation*

**Priority:** Medium — Rust is growing fast; IronWorm itself is written in Rust. Cargo.io has Sigstore-style attestations via `cargo-vet` but not registry-level provenance yet.

**Current state:** Gate 1 ✅ · Gate 2 ⚠️ stub · Gates 2.5 ✅ · Manifest parser ✅

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| `Cargo.lock` parser | 30 min | More complete than `Cargo.toml`; includes transitive deps. |
| Gate 2: `cargo-vet` integration | 3 hr | `cargo vet` generates audit records for crates. Can be read as a trust signal alongside the allowlist. |
| Gate 2: crates.io owner verification | 1 hr | crates.io API exposes crate owners. Verify against allowlist `owner` field. |
| Gate 5: build script detection | 1 hr | `build.rs` is the cargo equivalent of npm `preinstall`. Flag crates with `build.rs` for heightened scrutiny. |

---

### 🟡 P3 — NuGet (.NET) · *Age check + manifest parser complete; Gate 2 missing*

**Priority:** Medium — .NET ecosystem is large in enterprise Windows environments. NuGet.org introduced signed packages in 2018; verification is feasible.

**Current state:** Gate 1 ✅ · Gate 2 ❌ · Manifest parser ✅ (`packages.config`) · Gate 2.5 ✅

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| `packages.lock.json` parser | 30 min | Modern SDK-style lockfile; supersedes `packages.config` in most new projects. |
| `*.csproj` parser | 1 hr | `<PackageReference>` elements; no lockfile needed for basic audit. |
| Gate 2: NuGet package signature verification | 2 hr | NuGet.org signs packages via Authenticode. `dotnet nuget verify` is the CLI surface. |
| Gate 2: author signing vs repository signing | 1 hr | NuGet has two signing modes; repository-signed (by nuget.org) is weaker than author-signed. |

---

### 🟡 P3 — RubyGems · *Age check + manifest parser complete; Gate 2 missing*

**Priority:** Medium — Ruby is widely used in web backends and DevOps tooling (Chef, Puppet, Vagrant, Jekyll). `Gemfile.lock` is a rich lockfile.

**Current state:** Gate 1 ✅ · Gate 2 ❌ · Manifest parser ✅ (`Gemfile.lock`) · Gate 2.5 ✅

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| Gate 2: RubyGems MFA enforcement check | 1 hr | RubyGems API exposes whether maintainers have MFA enabled. Low-bar provenance signal. |
| Gate 2: gem signature verification | 2 hr | Gems can be signed with GPG; `gem cert` provides the mechanism. Coverage is inconsistent — most gems are unsigned. |
| Gate 5: gem `extconf.rb` / native extension detection | 1 hr | Native extension compilation is the Ruby equivalent of a build script. Flag gems with `ext/` directories. |

---

### 🟢 P4 — PyPI lockfile formats · *Core complete; expand lockfile coverage*

**Priority:** Low-Medium — PyPI support is the most complete, but Python projects use multiple lockfile formats beyond `requirements.txt`.

**Current state:** `requirements.txt` ✅ · `framework_deps.txt` ✅

**Work required:**

| Item | Effort | Notes |
|------|--------|-------|
| `pyproject.toml` parser | 1 hr | PEP 621; `[project.dependencies]` section. Common in new projects using hatch, flit, or Poetry. |
| `poetry.lock` parser | 1 hr | TOML; `[[package]]` sections with `name`, `version`, `source`. |
| `Pipfile.lock` parser | 45 min | JSON; `default` and `develop` sections. Pipenv lockfile. |
| `uv.lock` parser | 1 hr | New uv lockfile format (TOML); rapidly growing adoption. |
| `setup.cfg` / `setup.py` parser | 2 hr | Legacy; fragile to parse reliably. Lower priority than the above. |

---

### 🔵 P5 — Future ecosystems (not yet scheduled)

These ecosystems have meaningful supply chain risk but lower enterprise prevalence or smaller attack surface in the observed threat landscape. Contributions welcome.

| Ecosystem | Registry | Download volume | Notable risk | Estimated effort |
|-----------|----------|----------------|-------------|-----------------|
| **Dart / Flutter Pub** | pub.dev | High (mobile) | Growing; Flutter adoption surging | 3–4 days |
| **Swift Package Manager** | swiftpackageindex.com / GitHub | Medium | Xcode build system integration; binary targets | 4–5 days |
| **Hex (Elixir/Erlang)** | hex.pm | Low-Medium | Telecom/distributed systems niche; limited attacks observed | 2–3 days |
| **Hackage (Haskell)** | hackage.haskell.org | Low | Academic/functional; low attack surface | 2–3 days |
| **CRAN (R)** | cran.r-project.org | Medium (data science) | Data pipeline poisoning risk; no package signing | 3–4 days |
| **Conda / Anaconda** | anaconda.org | High (ML/data science) | Multiple documented attack campaigns; binary package surface | 5–7 days |
| **Composer (PHP)** | packagist.org | High (web) | Laravel/WordPress ecosystem; documented attacks | 3–4 days |
| **CPAN (Perl)** | cpan.org | Low-Medium | Legacy; primarily ops/sysadmin tooling | 2–3 days |
| **CocoaPods** | cocoapods.org | Medium (mobile) | 2023 RepoJacking attack affected 3M apps | 3–4 days |
| **vcpkg / Conan (C++)** | vcpkg.io / conan.io | Medium (systems) | Binary build system; difficult to sandbox | 5–7 days |

---

## Other backlog items

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

All 10 risks fully addressed as of v0.5.1 for PyPI and npm. Partial for other ecosystems where Gate 2 is incomplete.

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

*Last updated: 2026-06-14 · v0.5.1*
