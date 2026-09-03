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
| 2 — Provenance attestation | ✅ PyPI + npm + Cargo · ❌ Go/Maven/NuGet/RubyGems | Sigstore native on PyPI + npm; Cargo via crates.io Trusted Publishing (OIDC); others return "not implemented" |
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
| **Cargo** | ✅ | ✅ | ✅ Trusted Publishing¹ | ✅ | ✅ | ✅ syft | ⚠️ no hooks | ✅ `Cargo.toml` |
| **RubyGems** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ✅ `Gemfile.lock` |
| **NuGet** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ✅ `packages.config` |
| **Go** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ❌ no hooks | ❌ no manifest parser |
| **Maven** | ✅ | ✅ | ❌ not impl. | ✅ | ✅ | ✅ syft | ⚠️ limited | ❌ no manifest parser |

> **Legend:** ✅ = fully implemented · ⚠️ = partial or best-effort · ❌ = not yet implemented
> ¹ Verified via `trustpub_data` on the crates.io version API, not Sigstore — see notes below. Coverage is conditional on the crate having adopted crates.io Trusted Publishing; most crates today still publish via long-lived API token, which is treated as INFO/pass (not a failure) unless the crate is in `require_attestation`.

### Notes on partial coverage

**Gate 2 (Provenance attestation):** PyPI Trusted Publishing and npm provenance are both Sigstore-native as of 2023/npm v9.5. Cargo is now covered via crates.io's own OIDC-based Trusted Publishing (RFC #3691, GitHub Actions since mid-2025, GitLab CI/CD since Jan 2026) — implemented in `oss_trust_framework/signature/provenance.py::_verify_cargo_provenance`, reading the `trustpub_data.repository` field and comparing it against the trusted publisher allowlist exactly like npm's `sourceRepositoryURI` check. This is not Sigstore, but it serves the same purpose: it proves which repo/workflow produced the published crate. A `cargo-vet` audit entry, if present locally, is surfaced as an advisory note only — it never overrides the Trusted Publishing check, since it answers a different question (was the source reviewed) than who published this specific version. RubyGems, NuGet, Go, and Maven do not yet have any end-to-end verifiable publish-time signal; Gate 2 falls back to the trusted publishers allowlist alone for these ecosystems.

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

### 🟠 P2 — Cargo (Rust) · *Gate 2 implemented via Trusted Publishing; parser + Gate 5 remain*

**Priority:** Medium — Rust is growing fast; IronWorm itself is written in Rust. crates.io shipped its own OIDC-based Trusted Publishing (RFC #3691) in 2025, with GitLab CI/CD support added January 2026 — this is now wired up as Gate 2.

**Current state:** Gate 1 ✅ · Gate 2 ✅ (Trusted Publishing, conditional on adoption — see coverage note above) · Gates 2.5 ✅ · Manifest parser ✅ (`Cargo.toml`)

**Done (2026-08 draft, needs review/merge):**

| Item | Notes |
|------|-------|
| Gate 2: crates.io Trusted Publishing verification | Reads `trustpub_data.repository` from `GET /api/v1/crates/{crate}/{version}`; compares against the allowlist; CRITICAL/block on mismatch, same Miasma-pattern handling as npm/PyPI. Missing `trustpub_data` is INFO/pass unless the crate is in `require_attestation` (most crates still use a long-lived token — that's not itself a red flag). |
| Gate 2: `cargo-vet` integration | Implemented as an **advisory-only** note appended to the Gate 2 message when Trusted Publishing data is absent — deliberately does not pass/fail the gate on its own, since a source audit doesn't prove who published *this* version. |
| `tests/test_gate2_cargo_provenance.py` | 6 tests: repo match, repo mismatch (block), no-trustpub not-required (pass), no-trustpub required (hold), advisory vet note, registry-lookup failure (fails open). |

**Remaining work:**

| Item | Effort | Notes |
|------|--------|-------|
| `Cargo.lock` parser | 30 min | More complete than `Cargo.toml`; includes transitive deps. |
| Gate 2: crates.io owner verification (secondary signal) | 1 hr | crates.io API exposes crate owners (`/owners` endpoint). Worth adding as a *second* advisory signal alongside Trusted Publishing for crates that haven't adopted it yet — flag an owner change since last-known-good rather than trusting it outright. |
| Gate 5: build script detection | 1 hr | `build.rs` is the cargo equivalent of npm `preinstall`. Flag crates with `build.rs` for heightened scrutiny. |
| `config/trusted_publishers.yaml` — expand Cargo allowlist | ongoing | Currently 5 crates (`serde`, `tokio`, `reqwest`, `rustls`, `ring`). Worth adding crates confirmed on Trusted Publishing (e.g. `uv`, `wasm-bindgen`, `cargo-binstall`, `starship`, `zoxide`) so Gate 2 has something to actually verify against in testing/demos. |

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

*Last updated: 2026-08-31 · Cargo Gate 2 (Trusted Publishing) added in draft — see [P2 — Cargo](#-p2--cargo-rust--gate-2-implemented-via-trusted-publishing-parser--gate-5-remain) above.*
<!-- Note: this file's version pin (v0.5.1) predates the README/CLI (v0.6.1) and
     the v0.7.0 npm improvements already shipped -- worth a pass to sync all
     three before the next release, same class of issue as the earlier
     README ecosystem-coverage correction. -->

---

## Emerging threat backlog — 2026 Q3 attack pattern analysis

The following items were added based on five supply chain attack patterns observed or escalating in 2026 Q3 that expose gaps in current gate coverage. Each entry maps the attack to the gates it evades, then describes the proposed code enhancement.

---

### 🔴 P1 — TeamPCP / CI Pipeline Credential Theft · *Gate 2.5 gap: stolen service-account token reuse*

**Attack pattern:** Threat actors exploited a misconfigured CI/CD workflow in Aqua Security's Trivy scanner to steal service-account tokens mid-run. The stolen tokens were subsequently used to push a poisoned release across distribution channels. The attack is distinct from Miasma in that the stolen credential is a *service account token* (e.g., a GCP/AWS workload identity or GitHub App installation token) rather than a personal OIDC identity — meaning the publishing identity may legitimately appear in the allowlist even though the publish was not initiated by a legitimate workflow run.

**Current gate coverage:**
- Gate 2.5b detects `id-token: write` misuse and dangerous workflow permissions.
- Gate 2.5c detects direct pushes and missing PR review.
- Gate 2 detects `sourceRepositoryURI` mismatch.

**Gap:** None of the above catch a legitimate service-account token stolen *from inside a valid CI run* and reused externally. The publish may come from the correct repository and workflow — the only anomalous signals are the timing (outside a scheduled release window), the triggering event (a push to a non-release branch or manual dispatch), and the runner context (the token was used from an IP or runner that differs from the registered workflow environment).

**Proposed enhancements:**

| Item | Gate | Effort | Notes |
|------|------|--------|-------|
| Gate 2.5b: build trigger allowlist | 2.5b | 2 hr | Extend workflow permissions audit to flag publishes triggered by `workflow_dispatch` or `push` to non-release branches when the expected trigger is `release`. Configurable per-package in `trusted_publishers.yaml` as `expected_trigger: release`. |
| Gate 2.5b: runner environment cross-check | 2.5b | 3 hr | For packages with Trusted Publishing configured, compare the `run_id` from `trustpub_data` (Cargo) or the attestation (npm/PyPI) against the GitHub Actions API to verify the triggering event and actor match the expected release workflow. Flag `workflow_dispatch` initiators who are not in a named approver list. |
| Gate 3: anomalous publish-time signal | 3 | 2 hr | Add a publish-outside-release-window check: if a new version appears outside the project's historical release cadence (e.g., midnight UTC for a project that always releases Mon–Fri 09:00–17:00), surface as MEDIUM advisory signal alongside OOB trust score. Requires building a per-package release cadence baseline from registry version history. |
| New behavioral pattern: TEAMCP-001 | 5 | 1 hr | Gate 5: detect access to GCP/AWS metadata IMDS endpoints (`metadata.google.internal`, `169.254.169.254`) from install-time hooks — these are the service credential sources Trivy's pipeline attacker harvested. MIASMA-001/002 cover these but only flag them as Miasma-specific; promote to a general `CLOUD_IMDS` category so coverage applies to TeamPCP-style attacks without requiring the Miasma label. |

**Reference:** TeamPCP campaign targeting Aqua Security Trivy (2026)

---

### 🔴 P1 — Mini Shai-Hulud Self-Replicating Worm · *Gate 5 gap: cross-package propagation velocity*

**Attack pattern:** A successor worm to IronWorm and Shai-Hulud targeting JavaScript ecosystems (TanStack, UiPath, MistralAI adjacent tooling). Unlike IronWorm, which propagated by reusing stolen npm OIDC tokens, Mini Shai-Hulud actively enumerates all packages the compromised account has publish rights to and publishes trojanized versions of each in rapid succession — a *blast radius amplification* step that the current framework has no signal for.

**Current gate coverage:**
- Gate 5 `IRONWORM-006/006b` detect `.npmrc` reads and `NPM_AUTH_TOKEN` harvesting.
- Gate 5 `PUBLISH-001` detects a single outbound PUT to the npm registry.

**Gap:** The framework evaluates packages individually. Cross-package propagation — where one compromised account is the trigger for N poisoned packages published within minutes — produces no correlated signal across package evaluations. The worm also specifically targets packages owned by accounts that maintain popular adjacent tooling (not just the directly attacked package), which the current owner-check logic doesn't model.

**Proposed enhancements:**

| Item | Gate | Effort | Notes |
|------|------|--------|-------|
| New behavioral pattern: MINISHAI-001 | 5 | 1 hr | Detect rapid sequential registry publish attempts within a single install-time execution: if Gate 5 observes more than one outbound PUT to a registry endpoint within the same sandbox session, escalate from BLOCK to CRITICAL and emit a worm-propagation alert. Currently `PUBLISH-001` fires on the first PUT; add `MINISHAI-001` for the second-or-more case. |
| New behavioral pattern: MINISHAI-002 | 5 | 2 hr | Detect npm registry ownership enumeration: `GET /api/v1/packages?maintainer=<user>` or equivalent calls to list all packages an account can publish to. This is the reconnaissance step preceding propagation. |
| Gate 3: publisher cross-package blast-radius check | 3 | 3 hr | For each package being checked, query the registry API for the full list of packages owned by the same publisher account. Surface a MEDIUM advisory if the publisher owns >25 packages and any of those packages have had a version published in the last 24 hours — indicating a possible worm propagation event in progress. Configurable threshold in `config/pipeline.yaml`. |
| Gate 2: publisher account publish-rate anomaly | 2 | 2 hr | If the registry API shows that the publishing account has published more than N packages in the past hour (configurable, default 3), treat the attestation as suspicious even if the repo URI matches. Surface as HIGH/quarantine rather than pass. |

**Reference:** Mini Shai-Hulud self-replicating worm targeting npm (2026)

---

### 🔴 P1 — AI Model & Dataset Artifact Supply Chain · *New attack surface: no current gate coverage*

**Attack pattern:** Attackers uploaded malicious dataset artifacts to Hugging Face designed to exploit code-execution flaws in data-processing worker nodes (e.g., Python `pickle` deserialization in `torch.load`, `pandas` Parquet readers, and similar). Successful exploitation allowed internal node execution, credential harvesting, and access to internal ML pipelines. AI models and datasets are now a *de facto executable code path* — loading them triggers arbitrary code in a way directly analogous to running an npm `preinstall` script.

**Current gate coverage:** None. The framework validates package registries (PyPI, npm, Cargo, etc.). It has no concept of ML model registries, Hugging Face Hub artifacts, or serialized model formats.

**Gap:** This is a new attack surface category. The threat model — malicious artifact → execution at load time → credential harvest → lateral movement — is structurally identical to the IronWorm install-hook pattern, but the artifact type and registry are different.

**Proposed enhancements (new P1 track):**

| Item | Gate | Effort | Notes |
|------|------|--------|-------|
| Gate 0: Hugging Face model/dataset name-similarity check | 0 | 2 hr | Extend the name-similarity checker to cover Hugging Face Hub model IDs (`org/model-name` format). Typosquats on `mistralai/Mistral-7B-Instruct-v0.2` are already observed in the wild. |
| Gate 1: HF Hub artifact age hold | 1 | 2 hr | Query the Hugging Face Hub API for model/dataset card metadata and apply the same 24h/72h age gate currently applied to PyPI/npm versions. A newly uploaded model revision with no community downloads or discussion is a red flag. |
| Gate 2: HF Hub model provenance check | 2 | 3 hr | Hugging Face Hub exposes commit history and author identity on model repos. Verify the author identity matches the expected org (e.g., `mistralai`, `meta-llama`, `google`) against an allowlist extension in `trusted_publishers.yaml`. Flag model cards that link to no canonical paper or project URL. |
| Gate 5: unsafe deserialization detection | 5 | 4 hr | Add a new behavioral pattern category `MLARTIFACT` for sandbox detection of unsafe deserialization calls at model-load time: `torch.load` without `weights_only=True`, `pickle.loads` on untrusted input, and `pandas.read_parquet` from an untrusted source. These are the execution vectors used in the Hugging Face attack. Requires sandbox instrumentation of Python import/call events, not just syscalls. |
| `config/trusted_publishers.yaml`: HF Hub allowlist section | config | 1 hr | Add `HuggingFace:` section to the trusted publishers allowlist, covering canonical org IDs for the major model families (mistralai, meta-llama, google, microsoft, Qwen, deepseek-ai, etc.). |

**Reference:** Hugging Face infrastructure and artifact exploit campaign (2026)

---

### 🔴 P1 — Slopsquatting & Trojanized AI Developer Tooling · *Gate 0 gap: LLM hallucination frequency signal*

**Attack pattern:** Two distinct but related sub-threats:

1. **Slopsquatting:** Attackers register package names that are frequently *hallucinated* by AI coding assistants (ChatGPT, Claude, Copilot) as import suggestions — names that don't exist but sound plausible. Developers auto-installing LLM-suggested dependencies without verification install the attacker-registered package instead.

2. **Trojanized AI tooling:** Threat groups distribute trojanized versions of AI developer tools (Claude Code clones, malicious MCP skills/extensions, Cursor plugins labeled "OpenClaw") that exfiltrate credentials and code from developer workstations. These arrive as packages in npm/PyPI under names that impersonate legitimate tools.

**Current gate coverage:**
- Gate 0 catches typosquats on *known* packages via string similarity against the trusted publishers allowlist — but only if the legitimate package is in the allowlist. A hallucinated name by definition has no legitimate counterpart in the allowlist, so Gate 0 produces no signal.
- Gate 3 checks OpenSSF Scorecard and CVE databases, but a freshly registered package with zero history scores near-zero on Scorecard without triggering a block.

**Gap (Slopsquatting):** Gate 0's allowlist-anchored approach is blind to hallucinated names. The signal needed is not similarity to a known package, but rather whether the package name appears on known LLM hallucination frequency lists or exhibits the statistical profile of a slopsquat (registered recently, zero prior versions, sparse README, no GitHub stars, no reverse dependencies).

**Gap (Trojanized tooling):** Package names impersonating AI tools (e.g., `claude-code-cli`, `@anthropic/claude-code-unofficial`, `cursor-mcp-plugin`) are a Gate 0 problem but require the legitimate tool names to be in the allowlist. Many AI tools are distributed outside registries (direct download, Homebrew, etc.) and may not have a canonical registry presence to anchor similarity against.

**Proposed enhancements:**

| Item | Gate | Effort | Notes |
|------|------|--------|-------|
| Gate 0: slopsquat heuristic detection | 0 | 3 hr | Add a `SlopsquatChecker` alongside the existing similarity algorithms. Red flags: package registered <30 days ago, zero versions prior to current, README under 200 words with no GitHub link, zero reverse dependencies (packages that depend on it), no OpenSSF Scorecard entry. Any 3-of-5 → WARN; 5-of-5 → BLOCK. Threshold configurable in `config/pipeline.yaml`. |
| Gate 0: LLM hallucination frequency list integration | 0 | 2 hr | Maintain a curated `config/hallucination_watchlist.txt` of package names documented as LLM hallucinations (community-sourced; refs: Socket.dev slopsquatting reports, existing research). Gate 0 checks incoming package names against this list before the similarity check — an exact match on the watchlist is an immediate WARN regardless of age or provenance. |
| Gate 0: AI tooling impersonation allowlist | 0 | 1 hr | Add a dedicated section to `trusted_publishers.yaml` for canonical AI tool package names (`@anthropic/claude-code`, `cursor`, `@modelcontextprotocol/sdk`, etc.) so Gate 0's similarity check fires on near-matches to these names, even if the legitimate packages aren't traditional registry packages. |
| Gate 3: zero-history package scoring | 3 | 2 hr | Add a low-history penalty to the OOB trust score: packages with zero reverse dependencies, no Scorecard entry, and first published in the last 72 hours receive a synthetic floor score of 0 rather than being excluded from scoring. Currently packages with no Scorecard data pass Gate 3 with an INFO message; this change makes them QUARANTINE candidates when combined with other low signals. |

**Reference:** Slopsquatting attack campaigns on npm/PyPI (2026); trojanized Claude Code and MCP tool distribution (2026)

---

### 🟠 P2 — High-Impact Maintainer Takeover · *Gate 2 / Gate 3 gap: sudden publisher identity change*

**Attack pattern:** Targeted spear-phishing and credential-stuffing against core maintainers of foundational packages (`chalk`, `debug`, and similar utilities with 50M+ weekly downloads) result in attacker account access. The attacker publishes a malicious version with a cryptominer or credential stealer payload. The attack window is the gap between publish time and when downstream automated tools (Dependabot, Renovate, `npm update`) ingest the new version — often measured in minutes. Gate 1's age hold is the primary defense, but the attack also exploits the fact that no current gate checks whether the *publishing identity has changed* relative to historical versions.

**Current gate coverage:**
- Gate 1 (age hold) blocks for 24h — the strongest existing defense.
- Gate 2 checks `sourceRepositoryURI` against the allowlist — but if the attacker publishes via the legitimate account (post-takeover), the repo URI may still match.
- Gate 3 checks OpenSSF Scorecard — but a just-taken-over account won't yet have lowered the score.

**Gap:** No gate currently checks whether the publishing identity (GitHub login, npm account, PyPI user) has *changed* relative to prior versions of the same package. A sudden publisher identity change on a high-download package is a strong pre-attack signal in the maintainer takeover pattern.

**Proposed enhancements:**

| Item | Gate | Effort | Notes |
|------|------|--------|-------|
| Gate 2: publisher identity continuity check | 2 | 3 hr | For npm: compare `_npmUser.name` on the new version against the `_npmUser.name` on the previous N versions via the registry API. For PyPI: compare `uploaded_via` / `author` metadata. For Cargo: compare `published_by.login` via the crates.io version API (this field is already fetched in the Cargo provenance check). A publisher identity change on any package → WARN; on a package with >1M weekly downloads → QUARANTINE. Configurable download threshold in `config/pipeline.yaml`. |
| Gate 2: account age check on new publisher identity | 2 | 2 hr | If a publisher identity change is detected, query the registry/GitHub API for the account's creation date. An account that took over a high-download package and was created <90 days ago is a strong takeover signal → escalate to HIGH. |
| Gate 3: maintainer MFA status check | 3 | 2 hr | npm and PyPI both expose whether a package's maintainers have MFA enabled (npm: `/-/npm/v1/security/advisories/bulk`; PyPI: `two_factor_requirement_enabled` on the project API). A core maintainer account without MFA on a high-download package is a standing vulnerability — surface as MEDIUM advisory in the Gate 3 OOB trust score even when no active exploit is occurring. |
| `config/trusted_publishers.yaml`: high-value package tagging | config | 1 hr | Add an optional `high_value: true` tag to trusted publisher entries for packages above a configurable download threshold. This tag activates the stricter publisher-continuity and account-age checks above without requiring all packages to pay the extra API call cost. |
| Attack coverage table update | docs | 30 min | Add maintainer takeover (`chalk`/`debug` vector) row to the Attack Coverage table in `README.md`, documenting which gates provide partial vs. full coverage and what the residual risk window is (Gate 1 age hold closes the window for automated ingestion; human-triggered `npm install` of a specific version remains unprotected). |

**Reference:** `chalk`, `debug`, and similar foundational package maintainer takeover campaigns (2026)

---

## Attack coverage table — updated

The following rows are added to the Attack Coverage table in `README.md` based on the above analysis. The existing table covers Miasma, IronWorm, TanStack, Bitwarden CLI, and XZ Utils.

| Attack | Date | Packages | Vector | Gates covering | Residual gap |
|--------|------|----------|--------|----------------|--------------|
| **TeamPCP / Trivy** | 2026 | CI pipelines (multi-ecosystem) | Stolen service-account token from compromised CI run | 2.5a, 2.5b (partial) | Stolen token used from inside legitimate workflow context evades current checks — see P1 above |
| **Mini Shai-Hulud** | 2026 | npm (TanStack, UiPath, MistralAI adjacent) | Self-replicating worm; cross-account publish propagation | 5 (PUBLISH-001, IRONWORM-006) | Single-package evaluation misses cross-package propagation velocity — see P1 above |
| **Hugging Face artifact exploit** | 2026 | HF Hub (ML models/datasets) | Malicious pickle/Parquet artifact → worker node RCE | None | New attack surface; no current gate covers ML artifact registries — see P1 above |
| **Slopsquatting** | 2026 | npm, PyPI (LLM-hallucinated names) | Registering package names hallucinated by AI coding assistants | 0 (partial — only catches similarity to known packages) | Hallucinated names have no allowlist anchor; blind spot in current Gate 0 design — see P1 above |
| **Trojanized AI tooling** | 2026 | npm, PyPI (Claude Code clones, MCP plugins) | Impersonation packages for AI dev tools | 0 (partial) | AI tool names need explicit allowlist entries — see P1 above |
| **Maintainer takeover** | 2026 | npm (chalk, debug class) | Credential stuffing / spear-phishing → silent publish | 1 (age hold) | Publisher identity change not detected; Gate 1 is the only current defense — see P2 above |

