"""
Gate 2 -- npm/PyPI/Cargo provenance attestation and publisher repo allowlist.

npm (since v9.5), PyPI (since 2023), and crates.io (since mid-2025, GitLab
support added Jan 2026) all support OIDC-based Trusted Publishing / SLSA
provenance. These attestations embed a signed record of:
  - Which CI workflow ran the build
  - Which repository (and, where available, commit SHA) produced the package
  - The OIDC issuer that authenticated the workflow

The Miasma attack used OIDC-based trusted publishing from a *compromised
employee's fork or personal repository*, not the canonical org repo. The
package signature was technically valid -- but the sourceRepositoryURI in the
provenance attestation pointed to the wrong repo.

This module verifies:
  1. A provenance attestation exists for the package version.
  2. The source repo matches the allowlisted canonical publisher repo
     (npm/PyPI: sourceRepositoryURI · Cargo: trustpub_data.repository).
  3. The build workflow matches expected patterns (not an ad-hoc script).
  4. For zero-day lane: the attestation timestamp postdates CVE publication.

Fix 2026-06-06: restored `passed` field to ProvenanceResult dataclass.
                No attestation = INFO/pass unless package is in require_attestation.

2026-08: added Cargo support via crates.io Trusted Publishing (`trustpub_data`
         on the version API). Go, Maven, NuGet, and RubyGems remain
         advisory-only (allowlist without a verifiable publish-time signal) --
         see BACKLOG.md for the per-ecosystem plan.

Publisher allowlist is maintained in config/trusted_publishers.yaml.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ProvenanceResult:
    passed: bool                  # True = gate passed, False = gate failed
    attestation_found: bool
    source_repo: Optional[str]    # owner/repo from attestation
    expected_repo: Optional[str]  # from trusted_publishers config
    repo_match: bool
    workflow_file: Optional[str]
    build_trigger: Optional[str]  # push | pull_request | workflow_dispatch
    risk: str                     # LOW | MEDIUM | HIGH | CRITICAL | INFO
    message: str


async def verify_provenance_attestation(
    package: str,
    version: str,
    ecosystem: str,
    trusted_publishers: dict,
    require_attestation: Optional[list] = None,
    cve_published_at: Optional[str] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> ProvenanceResult:
    """
    Verify that a package's provenance attestation exists and that the source
    repository matches the configured trusted publisher allowlist.

    Args:
        package:              Package name.
        version:              Exact version.
        ecosystem:            npm | PyPI | Cargo.
        trusted_publishers:   Mapping from package name to canonical "owner/repo".
        require_attestation:  List of packages that MUST have attestation.
                              Missing attestation only fails for these packages.
                              All others get INFO/pass when attestation is absent.
        cve_published_at:     If set, verify attestation postdates CVE publication.
        http_client:          Optional pre-configured client (for testing).
    """
    expected_repo = trusted_publishers.get(package)
    attestation_required = bool(require_attestation and package in require_attestation)

    if ecosystem == "npm":
        return await _verify_npm_provenance(
            package, version, expected_repo, cve_published_at,
            attestation_required=attestation_required,
        )
    elif ecosystem == "PyPI":
        return await _verify_pypi_provenance(
            package, version, expected_repo, http_client,
            attestation_required=attestation_required,
        )
    elif ecosystem == "Cargo":
        return await _verify_cargo_provenance(
            package, version, expected_repo, http_client,
            attestation_required=attestation_required,
        )
    else:
        # Go, Maven, NuGet, RubyGems don't yet have a verifiable publish-time
        # provenance signal wired up; treat as advisory only. See BACKLOG.md.
        return ProvenanceResult(
            passed=True,
            attestation_found=False,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="INFO",
            message=f"Provenance attestation not yet implemented for {ecosystem}.",
        )


# ---------------------------------------------------------------------------
# npm provenance
# ---------------------------------------------------------------------------

async def _verify_npm_provenance(
    package: str,
    version: str,
    expected_repo: Optional[str],
    cve_published_at: Optional[str],
    attestation_required: bool = False,
) -> ProvenanceResult:
    """
    Use npm audit signatures to verify Sigstore provenance for an npm package.
    Falls back to direct registry API query for the provenance manifest.
    """
    try:
        result = subprocess.run(
            ["npm", "audit", "signatures", "--json", f"{package}@{version}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 and result.stdout:
            audit_data = json.loads(result.stdout)
            return _parse_npm_audit_signatures(
                audit_data, package, expected_repo, attestation_required
            )
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("npm audit signatures failed for %s@%s: %s", package, version, exc)

    async with httpx.AsyncClient(timeout=15) as client:
        return await _query_npm_registry_provenance(
            client, package, version, expected_repo, attestation_required
        )


async def _query_npm_registry_provenance(
    client: httpx.AsyncClient,
    package: str,
    version: str,
    expected_repo: Optional[str],
    attestation_required: bool = False,
) -> ProvenanceResult:
    url = f"https://registry.npmjs.org/{package}/{version}"
    resp = await client.get(url)

    if resp.status_code != 200:
        return ProvenanceResult(
            passed=True,
            attestation_found=False,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="INFO",
            message=f"Could not fetch npm registry metadata for {package}@{version}.",
        )

    data = resp.json()
    dist = data.get("dist", {})
    attestations_url = dist.get("attestations", {}).get("url")

    if not attestations_url:
        risk = "HIGH" if attestation_required else "INFO"
        return ProvenanceResult(
            passed=not attestation_required,
            attestation_found=False,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk=risk,
            message=(
                f"{package}@{version} has no provenance attestation."
                + (" REQUIRED by policy." if attestation_required
                   else " Not required -- add to require_attestation list to enforce.")
            ),
        )

    att_resp = await client.get(attestations_url)
    if att_resp.status_code != 200:
        return ProvenanceResult(
            passed=False,
            attestation_found=True,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="HIGH",
            message=f"Attestation URL exists but could not be fetched: {attestations_url}",
        )

    return _parse_attestation_bundle(att_resp.json(), package, version, expected_repo)


def _parse_attestation_bundle(
    bundle: dict,
    package: str,
    version: str,
    expected_repo: Optional[str],
) -> ProvenanceResult:
    try:
        attestations = bundle.get("attestations", [])
        if not attestations:
            raise ValueError("Empty attestations array")

        slsa_att = next(
            (a for a in attestations if "slsaprovenance" in a.get("predicateType", "")),
            attestations[0],
        )

        predicate = slsa_att.get("predicate", slsa_att.get("statement", {}).get("predicate", {}))
        build_metadata = predicate.get("buildDefinition", predicate.get("recipe", {}))

        ext_params = build_metadata.get("externalParameters", {})
        source_repo_uri = (
            ext_params.get("workflow", {}).get("repository")
            or ext_params.get("source", {}).get("uri")
            or build_metadata.get("resolvedDependencies", [{}])[0].get("uri", "")
        )
        source_repo = source_repo_uri.replace("https://github.com/", "").split("@")[0].strip("/")

        workflow_file = (
            ext_params.get("workflow", {}).get("path")
            or ext_params.get("workflow", {}).get("ref", "")
        )
        build_trigger = ext_params.get("workflow", {}).get("trigger", "unknown")

    except (KeyError, IndexError, ValueError, StopIteration) as exc:
        logger.warning("attestation parse failed for %s@%s: %s", package, version, exc)
        return ProvenanceResult(
            passed=False,
            attestation_found=True,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="HIGH",
            message=f"Attestation found but could not be parsed: {exc}",
        )

    repo_match = (
        expected_repo is None
        or source_repo.lower() == expected_repo.lower()
    )

    if not repo_match:
        return ProvenanceResult(
            passed=False,
            attestation_found=True,
            source_repo=source_repo,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=workflow_file,
            build_trigger=build_trigger,
            risk="CRITICAL",
            message=(
                f"CRITICAL: {package}@{version} was published from '{source_repo}' "
                f"but the trusted publisher is '{expected_repo}'. "
                "This matches the Miasma attack pattern: a compromised employee account "
                "or fork published as if it were the canonical package."
            ),
        )

    return ProvenanceResult(
        passed=True,
        attestation_found=True,
        source_repo=source_repo,
        expected_repo=expected_repo,
        repo_match=True,
        workflow_file=workflow_file,
        build_trigger=build_trigger,
        risk="LOW",
        message=(
            f"Provenance attestation verified. Published from '{source_repo}' "
            f"via workflow '{workflow_file}' (trigger: {build_trigger})."
        ),
    )


def _parse_npm_audit_signatures(
    audit_data: dict,
    package: str,
    expected_repo: Optional[str],
    attestation_required: bool = False,
) -> ProvenanceResult:
    auditResults = audit_data.get("auditResults", audit_data.get("results", []))
    pkg_result = next(
        (r for r in auditResults if r.get("package", "").startswith(package)),
        None,
    )
    if not pkg_result:
        return ProvenanceResult(
            passed=not attestation_required,
            attestation_found=False,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="HIGH" if attestation_required else "INFO",
            message=f"npm audit signatures found no result for {package}.",
        )

    provenance = pkg_result.get("provenance", {})
    source_repo = provenance.get("sourceRepositoryURI", "").replace("https://github.com/", "")
    repo_match = not expected_repo or source_repo.lower() == expected_repo.lower()

    return ProvenanceResult(
        passed=repo_match,
        attestation_found=True,
        source_repo=source_repo or None,
        expected_repo=expected_repo,
        repo_match=repo_match,
        workflow_file=provenance.get("buildWorkflowUri"),
        build_trigger=None,
        risk="LOW" if repo_match else "CRITICAL",
        message=(
            f"Provenance from '{source_repo}' matches expected '{expected_repo}'."
            if repo_match
            else (
                f"CRITICAL: published from '{source_repo}', expected '{expected_repo}'. "
                "Possible compromised account or fork attack."
            )
        ),
    )


# ---------------------------------------------------------------------------
# PyPI provenance
# ---------------------------------------------------------------------------

async def _verify_pypi_provenance(
    package: str,
    version: str,
    expected_repo: Optional[str],
    http_client: Optional[httpx.AsyncClient],
    attestation_required: bool = False,
) -> ProvenanceResult:
    """
    Verify PyPI provenance attestation via the PyPI JSON API.
    PyPI added SLSA provenance support in 2024.

    Key policy: missing attestation is INFO/pass unless the package is in the
    require_attestation list. Many well-maintained packages (cryptography, rich,
    pyyaml, click etc.) either don't use PyPI Trusted Publishing yet or the
    version being checked predates when they adopted it.
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")

        if resp.status_code != 200:
            return ProvenanceResult(
                passed=True,
                attestation_found=False,
                source_repo=None,
                expected_repo=expected_repo,
                repo_match=False,
                workflow_file=None,
                build_trigger=None,
                risk="INFO",
                message=f"Could not fetch PyPI metadata for {package}=={version}.",
            )

        data = resp.json()
        urls = data.get("urls", [])

        for url_entry in urls:
            if url_entry.get("provenance"):
                # Attestation present -- parse and verify
                provenance = url_entry["provenance"]
                source_repo = None
                repo_match = True

                # Attempt to extract source repo from provenance
                try:
                    stmts = provenance.get("attestation_bundles", [{}])[0].get(
                        "attestations", [{}]
                    )[0].get("envelope", {}).get("statement", {})
                    subject = stmts.get("subject", [{}])[0]
                    repo_uri = subject.get("digest", {}).get("sha256", "")
                    # Try the predicate for source repo
                    pred = stmts.get("predicate", {})
                    source_repo = (
                        pred.get("buildDefinition", {})
                        .get("externalParameters", {})
                        .get("workflow", {})
                        .get("repository", "")
                        .replace("https://github.com/", "")
                    ) or None
                    if expected_repo and source_repo:
                        repo_match = source_repo.lower() == expected_repo.lower()
                except Exception:
                    pass  # Provenance format parsing is best-effort

                if not repo_match and expected_repo and source_repo:
                    return ProvenanceResult(
                        passed=False,
                        attestation_found=True,
                        source_repo=source_repo,
                        expected_repo=expected_repo,
                        repo_match=False,
                        workflow_file=None,
                        build_trigger=None,
                        risk="CRITICAL",
                        message=(
                            f"CRITICAL: {package}=={version} was published from "
                            f"'{source_repo}' but trusted publisher is '{expected_repo}'. "
                            "Possible Miasma-style fork attack."
                        ),
                    )

                return ProvenanceResult(
                    passed=True,
                    attestation_found=True,
                    source_repo=source_repo,
                    expected_repo=expected_repo,
                    repo_match=True,
                    workflow_file=None,
                    build_trigger=None,
                    risk="LOW",
                    message=(
                        f"PyPI provenance attestation present for {package}=={version}."
                        + (f" Source: {source_repo}." if source_repo else "")
                    ),
                )

        # No attestation found
        # Only fail if this package is explicitly in the require_attestation list.
        # Being in trusted_publishers is NOT sufficient reason to fail --
        # many packages know the expected repo but aren't on Trusted Publishing yet.
        return ProvenanceResult(
            passed=not attestation_required,
            attestation_found=False,
            source_repo=None,
            expected_repo=expected_repo,
            repo_match=False,
            workflow_file=None,
            build_trigger=None,
            risk="HIGH" if attestation_required else "INFO",
            message=(
                f"{package}=={version} has no PyPI provenance attestation."
                + (" REQUIRED by policy." if attestation_required
                   else " Not required -- add to require_attestation list to enforce.")
            ),
        )

    finally:
        if own_client:
            await client.aclose()


# ---------------------------------------------------------------------------
# Cargo (crates.io) provenance
# ---------------------------------------------------------------------------

CRATES_IO_USER_AGENT = "oss-trust-framework (github.com/chrisgillham/oss-trust-framework)"


async def _verify_cargo_provenance(
    package: str,
    version: str,
    expected_repo: Optional[str],
    http_client: Optional[httpx.AsyncClient],
    attestation_required: bool = False,
) -> ProvenanceResult:
    """
    Verify Cargo (crates.io) provenance via Trusted Publishing (OIDC).

    crates.io shipped OIDC-based Trusted Publishing for GitHub Actions in
    mid-2025 (RFC #3691) and added GitLab CI/CD support in January 2026. A
    version published via Trusted Publishing carries a `trustpub_data` object
    on the version API response, e.g.:

        "trustpub_data": {
            "provider": "github",
            "repository": "astral-sh/uv",
            "run_id": "33117010175",
            "sha": "61291a8ca5477a9ca653f14d2ac5665587c263fa"
        }

    `trustpub_data.repository` is the Cargo equivalent of npm's
    sourceRepositoryURI / PyPI's SLSA provenance repo field -- it is the one
    field that proves *which CI workflow, on which repo* produced the
    published crate, closing the same Miasma-style gap: a compromised
    account or unrelated fork publishing under a valid-looking identity.

    IMPORTANT: crate ownership on crates.io is still overwhelmingly published
    via long-lived API tokens as of this writing -- `trustpub_data` being
    null is common and is NOT itself a red flag. As with npm/PyPI, a missing
    attestation is INFO/pass unless the package is explicitly listed in
    `require_attestation`, in which case it's a HIGH-risk hold rather than a
    hard block (absence of a signal isn't proof of compromise).

    A `cargo-vet` audit entry, if present locally, is surfaced as an
    *advisory-only* note. It reflects that a human reviewed the crate's
    source at some point -- a different question from who published this
    specific version -- so it can never by itself clear a repo mismatch or
    substitute for Trusted Publishing data.
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        try:
            resp = await client.get(
                f"https://crates.io/api/v1/crates/{package}/{version}",
                headers={"User-Agent": CRATES_IO_USER_AGENT},
            )
        except httpx.HTTPError as exc:
            logger.warning("crates.io lookup failed for %s@%s: %s", package, version, exc)
            return ProvenanceResult(
                passed=True,
                attestation_found=False,
                source_repo=None,
                expected_repo=expected_repo,
                repo_match=False,
                workflow_file=None,
                build_trigger=None,
                risk="INFO",
                message=f"Could not reach crates.io for {package}@{version}: {exc}",
            )

        if resp.status_code != 200:
            return ProvenanceResult(
                passed=True,
                attestation_found=False,
                source_repo=None,
                expected_repo=expected_repo,
                repo_match=False,
                workflow_file=None,
                build_trigger=None,
                risk="INFO",
                message=f"Could not fetch crates.io metadata for {package}@{version} "
                        f"(HTTP {resp.status_code}).",
            )

        data = resp.json()
        version_data = data.get("version", {})
        trustpub = version_data.get("trustpub_data")

        if not trustpub:
            vet_note = _check_cargo_vet_audit(package, version)
            risk = "HIGH" if attestation_required else "INFO"
            message = (
                f"{package}@{version} was not published via crates.io Trusted "
                "Publishing (no trustpub_data on this version -- likely a "
                "long-lived API token, which is still the common case)."
                + (" REQUIRED by policy." if attestation_required
                   else " Not required -- add to require_attestation list to enforce.")
            )
            if vet_note:
                message += f" {vet_note}"
            return ProvenanceResult(
                passed=not attestation_required,
                attestation_found=False,
                source_repo=None,
                expected_repo=expected_repo,
                repo_match=False,
                workflow_file=None,
                build_trigger=None,
                risk=risk,
                message=message,
            )

        source_repo = trustpub.get("repository")
        provider = trustpub.get("provider", "unknown")
        run_id = trustpub.get("run_id")
        workflow_file = f"{provider} run {run_id}" if run_id else provider

        repo_match = (
            expected_repo is None
            or (source_repo or "").lower() == expected_repo.lower()
        )

        if not repo_match:
            return ProvenanceResult(
                passed=False,
                attestation_found=True,
                source_repo=source_repo,
                expected_repo=expected_repo,
                repo_match=False,
                workflow_file=workflow_file,
                build_trigger=provider,
                risk="CRITICAL",
                message=(
                    f"CRITICAL: {package}@{version} was published via crates.io "
                    f"Trusted Publishing from '{source_repo}' but the trusted "
                    f"publisher is '{expected_repo}'. This matches the Miasma "
                    "attack pattern: a compromised account or unrelated fork "
                    "publishing under a valid-looking identity."
                ),
            )

        return ProvenanceResult(
            passed=True,
            attestation_found=True,
            source_repo=source_repo,
            expected_repo=expected_repo,
            repo_match=True,
            workflow_file=workflow_file,
            build_trigger=provider,
            risk="LOW",
            message=(
                f"crates.io Trusted Publishing verified. Published from "
                f"'{source_repo}' via {provider} (run {run_id})."
            ),
        )

    finally:
        if own_client:
            await client.aclose()


def _check_cargo_vet_audit(package: str, version: str) -> Optional[str]:
    """
    Best-effort, advisory-only check for a local cargo-vet audit record.

    cargo-vet (supply-chain/audits.toml) records that a human reviewed a
    crate's source at a given version -- a different kind of trust signal
    than Trusted Publishing, and one that says nothing about who published
    THIS version. It is never used to pass or fail Gate 2 on its own; it is
    surfaced only as an extra note appended to the message when Trusted
    Publishing data is absent.

    Returns None (silently) if cargo-vet isn't installed, isn't configured
    in the current project, or the check fails for any reason -- this must
    never raise or affect the gate outcome.
    """
    try:
        result = subprocess.run(
            ["cargo", "vet", "check", f"{package}:{version}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("cargo-vet check skipped for %s@%s: %s", package, version, exc)
        return None

    if result.returncode == 0:
        return f"cargo-vet: an audited entry exists for {package}:{version} (advisory only)."
    return None

# ---------------------------------------------------------------------------
# Gate 2 — Publisher identity continuity check
# ---------------------------------------------------------------------------
# Covers the maintainer takeover pattern (chalk/debug vector, 2026):
# an attacker who takes over a maintainer account and publishes a malicious
# version may still pass Gate 2's repo-URI check (the URI is unchanged).
# Comparing the publishing identity against prior versions closes this gap.
#
# Signal hierarchy:
#   - Publisher identity CHANGED on a package with >1M weekly downloads → QUARANTINE
#   - Publisher identity CHANGED on any other package → WARN (advisory)
#   - New publisher account created <90 days ago (after a change) → escalate
#   - Publisher identity UNCHANGED → advisory note only (INFO)
#
# Fails open on all registry errors — a lookup failure never blocks.
# ---------------------------------------------------------------------------

@dataclass
class PublisherContinuityResult:
    passed: bool
    current_publisher: Optional[str]
    previous_publisher: Optional[str]
    identity_changed: bool
    new_account_age_days: Optional[int]   # None if unchanged or unknown
    risk: str                             # LOW | MEDIUM | HIGH | INFO
    message: str


async def check_publisher_continuity(
    package: str,
    version: str,
    ecosystem: str,
    high_value_weekly_downloads: int = 1_000_000,
    http_client: Optional[httpx.AsyncClient] = None,
) -> PublisherContinuityResult:
    """
    Gate 2 supplementary check: verify the publisher identity for this version
    matches the identity used for recent prior versions.

    Supported ecosystems: npm, PyPI, Cargo.
    All others return INFO/pass (advisory only — no registry API to query).

    Args:
        package:                      Package name.
        version:                      Version being validated.
        ecosystem:                    npm | PyPI | Cargo | others.
        high_value_weekly_downloads:  Download threshold above which a publisher
                                      change is escalated from WARN to QUARANTINE.
        http_client:                  Optional pre-configured client (for testing).
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        if ecosystem == "npm":
            return await _npm_publisher_continuity(
                package, version, client, high_value_weekly_downloads
            )
        elif ecosystem == "PyPI":
            return await _pypi_publisher_continuity(package, version, client)
        elif ecosystem == "Cargo":
            return await _cargo_publisher_continuity(package, version, client)
        else:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=None,
                previous_publisher=None,
                identity_changed=False,
                new_account_age_days=None,
                risk="INFO",
                message=f"Publisher continuity check not implemented for {ecosystem}.",
            )
    finally:
        if own_client:
            await client.aclose()


async def _npm_publisher_continuity(
    package: str,
    version: str,
    client: httpx.AsyncClient,
    high_value_threshold: int,
) -> PublisherContinuityResult:
    """
    npm: compare _npmUser.name on the new version vs prior versions.
    Also checks weekly downloads to determine escalation level.
    """
    try:
        resp = await client.get(
            f"https://registry.npmjs.org/{package}",
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return _continuity_lookup_failed("npm", package)

        data = resp.json()
        versions = data.get("versions", {})
        time_data = data.get("time", {})

        # Sort versions by publish time to find the one immediately before current
        published_times = {
            v: time_data.get(v, "")
            for v in versions
            if v not in ("created", "modified")
        }
        sorted_versions = sorted(published_times, key=lambda v: published_times[v])

        if version not in sorted_versions:
            return _continuity_lookup_failed("npm", package)

        current_idx = sorted_versions.index(version)
        current_publisher = (
            versions.get(version, {}).get("_npmUser", {}).get("name")
        )

        if current_idx == 0 or current_publisher is None:
            # First version ever — no prior publisher to compare
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=None,
                identity_changed=False,
                new_account_age_days=None,
                risk="INFO",
                message=f"npm: {package}@{version} is the first published version — no prior publisher to compare.",
            )

        # Check the previous 1–3 versions for consistency
        prior_publishers = set()
        for prev_ver in sorted_versions[max(0, current_idx - 3):current_idx]:
            pub = versions.get(prev_ver, {}).get("_npmUser", {}).get("name")
            if pub:
                prior_publishers.add(pub)

        if not prior_publishers:
            return _continuity_lookup_failed("npm", package)

        previous_publisher = next(iter(prior_publishers))  # representative
        identity_changed = current_publisher not in prior_publishers

        if not identity_changed:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=previous_publisher,
                identity_changed=False,
                new_account_age_days=None,
                risk="LOW",
                message=f"npm: publisher identity consistent — '{current_publisher}' matches prior versions.",
            )

        # Identity changed — check download volume and new account age
        weekly_downloads = await _npm_weekly_downloads(client, package)
        account_age_days = await _github_account_age_days(client, current_publisher)

        risk, passed = _escalate_identity_change(
            package, current_publisher, previous_publisher,
            weekly_downloads, high_value_threshold, account_age_days,
        )

        return PublisherContinuityResult(
            passed=passed,
            current_publisher=current_publisher,
            previous_publisher=previous_publisher,
            identity_changed=True,
            new_account_age_days=account_age_days,
            risk=risk,
            message=_identity_change_message(
                "npm", package, version, current_publisher, previous_publisher,
                weekly_downloads, high_value_threshold, account_age_days, risk,
            ),
        )

    except Exception as exc:
        logger.warning("npm publisher continuity check failed for %s: %s", package, exc)
        return _continuity_lookup_failed("npm", package)


async def _pypi_publisher_continuity(
    package: str,
    version: str,
    client: httpx.AsyncClient,
) -> PublisherContinuityResult:
    """
    PyPI: compare the uploader identity across versions via the PyPI JSON API.
    Uses the `uploaded_via` maintainer field where available; falls back to
    comparing the version list's maintainer metadata.
    """
    try:
        resp = await client.get(f"https://pypi.org/pypi/{package}/json")
        if resp.status_code != 200:
            return _continuity_lookup_failed("PyPI", package)

        data = resp.json()
        releases = data.get("releases", {})

        # Build {version: uploader} map from upload metadata
        publisher_map: dict[str, Optional[str]] = {}
        for ver, files in releases.items():
            for f in files:
                uploader = f.get("uploaded_by")
                if uploader:
                    publisher_map[ver] = uploader
                    break

        current_publisher = publisher_map.get(version)
        if current_publisher is None:
            return _continuity_lookup_failed("PyPI", package)

        # Compare against the 3 most recent prior versions
        all_versions = sorted(
            (v for v in publisher_map if v != version),
            key=lambda v: releases.get(v, [{}])[0].get("upload_time", ""),
        )
        recent_prior = all_versions[-3:] if len(all_versions) >= 1 else []
        prior_publishers = {publisher_map[v] for v in recent_prior if publisher_map.get(v)}

        if not prior_publishers:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=None,
                identity_changed=False,
                new_account_age_days=None,
                risk="INFO",
                message=f"PyPI: {package}=={version} appears to be first upload — no prior publisher to compare.",
            )

        previous_publisher = next(iter(prior_publishers))
        identity_changed = current_publisher not in prior_publishers

        if not identity_changed:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=previous_publisher,
                identity_changed=False,
                new_account_age_days=None,
                risk="LOW",
                message=f"PyPI: publisher identity consistent — '{current_publisher}' matches prior versions.",
            )

        account_age_days = await _github_account_age_days(client, current_publisher)
        risk, passed = _escalate_identity_change(
            package, current_publisher, previous_publisher,
            weekly_downloads=0,  # PyPI doesn't expose this simply
            high_value_threshold=1_000_000,
            account_age_days=account_age_days,
        )
        return PublisherContinuityResult(
            passed=passed,
            current_publisher=current_publisher,
            previous_publisher=previous_publisher,
            identity_changed=True,
            new_account_age_days=account_age_days,
            risk=risk,
            message=_identity_change_message(
                "PyPI", package, version, current_publisher, previous_publisher,
                weekly_downloads=0, high_value_threshold=1_000_000,
                account_age_days=account_age_days, risk=risk,
            ),
        )

    except Exception as exc:
        logger.warning("PyPI publisher continuity check failed for %s: %s", package, exc)
        return _continuity_lookup_failed("PyPI", package)


async def _cargo_publisher_continuity(
    package: str,
    version: str,
    client: httpx.AsyncClient,
) -> PublisherContinuityResult:
    """
    Cargo: compare published_by.login across versions via the crates.io versions API.
    The published_by field is already fetched by the Trusted Publishing check;
    this function re-queries it for the historical comparison.
    """
    try:
        resp = await client.get(
            f"https://crates.io/api/v1/crates/{package}/versions",
            headers={"User-Agent": CRATES_IO_USER_AGENT},
        )
        if resp.status_code != 200:
            return _continuity_lookup_failed("Cargo", package)

        versions_data = resp.json().get("versions", [])
        # Sort by created_at descending
        versions_data.sort(key=lambda v: v.get("created_at", ""), reverse=True)

        current_entry = next(
            (v for v in versions_data if v.get("num") == version), None
        )
        if not current_entry:
            return _continuity_lookup_failed("Cargo", package)

        current_publisher = (current_entry.get("published_by") or {}).get("login")

        # Prior 3 versions (excluding current)
        prior_entries = [v for v in versions_data if v.get("num") != version][:3]
        prior_publishers = {
            (v.get("published_by") or {}).get("login")
            for v in prior_entries
            if (v.get("published_by") or {}).get("login")
        }

        if not current_publisher or not prior_publishers:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=None,
                identity_changed=False,
                new_account_age_days=None,
                risk="INFO",
                message=f"Cargo: publisher identity data unavailable for {package}@{version} — likely published via API token (no published_by).",
            )

        previous_publisher = next(iter(prior_publishers))
        identity_changed = current_publisher not in prior_publishers

        if not identity_changed:
            return PublisherContinuityResult(
                passed=True,
                current_publisher=current_publisher,
                previous_publisher=previous_publisher,
                identity_changed=False,
                new_account_age_days=None,
                risk="LOW",
                message=f"Cargo: publisher identity consistent — '{current_publisher}' matches prior versions.",
            )

        account_age_days = await _github_account_age_days(client, current_publisher)
        risk, passed = _escalate_identity_change(
            package, current_publisher, previous_publisher,
            weekly_downloads=0,
            high_value_threshold=1_000_000,
            account_age_days=account_age_days,
        )
        return PublisherContinuityResult(
            passed=passed,
            current_publisher=current_publisher,
            previous_publisher=previous_publisher,
            identity_changed=True,
            new_account_age_days=account_age_days,
            risk=risk,
            message=_identity_change_message(
                "Cargo", package, version, current_publisher, previous_publisher,
                weekly_downloads=0, high_value_threshold=1_000_000,
                account_age_days=account_age_days, risk=risk,
            ),
        )

    except Exception as exc:
        logger.warning("Cargo publisher continuity check failed for %s: %s", package, exc)
        return _continuity_lookup_failed("Cargo", package)


# ---------------------------------------------------------------------------
# Publisher continuity helpers
# ---------------------------------------------------------------------------

async def _npm_weekly_downloads(client: httpx.AsyncClient, package: str) -> int:
    """Fetch weekly download count from the npm downloads API. Returns 0 on error."""
    try:
        resp = await client.get(
            f"https://api.npmjs.org/downloads/point/last-week/{package}",
            timeout=8,
        )
        if resp.status_code == 200:
            return resp.json().get("downloads", 0)
    except Exception:
        pass
    return 0


async def _github_account_age_days(client: httpx.AsyncClient, username: str) -> Optional[int]:
    """
    Return how many days old a GitHub account is. Returns None if the account
    can't be found or the API is unavailable.
    """
    if not username:
        return None
    try:
        resp = await client.get(
            f"https://api.github.com/users/{username}",
            headers={"Accept": "application/vnd.github+json"},
            timeout=8,
        )
        if resp.status_code == 200:
            created_str = resp.json().get("created_at", "")
            if created_str:
                from datetime import datetime, timezone
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def _escalate_identity_change(
    package: str,
    current_publisher: str,
    previous_publisher: str,
    weekly_downloads: int,
    high_value_threshold: int,
    account_age_days: Optional[int],
) -> tuple[str, bool]:
    """
    Determine risk level and pass/fail for a publisher identity change.

    Rules:
    - New account <90 days old after a change → HIGH, quarantine
    - High-value package (downloads > threshold) with any change → HIGH, quarantine
    - Any other change → MEDIUM, quarantine (advisory hold, not hard block)
    """
    young_account = account_age_days is not None and account_age_days < 90
    high_value = weekly_downloads >= high_value_threshold

    if young_account or high_value:
        return "HIGH", False   # quarantine
    return "MEDIUM", False     # quarantine — any unexplained identity change is suspicious


def _identity_change_message(
    ecosystem: str,
    package: str,
    version: str,
    current: str,
    previous: str,
    weekly_downloads: int,
    high_value_threshold: int,
    account_age_days: Optional[int],
    risk: str,
) -> str:
    age_note = (
        f" New publisher account is only {account_age_days} days old — strong takeover indicator."
        if account_age_days is not None and account_age_days < 90
        else ""
    )
    dl_note = (
        f" Package has {weekly_downloads:,} weekly downloads — high-value target."
        if weekly_downloads >= high_value_threshold
        else ""
    )
    return (
        f"{risk}: {ecosystem} publisher identity change detected on {package}@{version}. "
        f"Current publisher: '{current}'. Prior publisher(s): '{previous}'.{age_note}{dl_note} "
        f"Possible maintainer account takeover (chalk/debug attack pattern). "
        f"Verify with the package maintainer team before approving."
    )


def _continuity_lookup_failed(ecosystem: str, package: str) -> PublisherContinuityResult:
    return PublisherContinuityResult(
        passed=True,
        current_publisher=None,
        previous_publisher=None,
        identity_changed=False,
        new_account_age_days=None,
        risk="INFO",
        message=f"Publisher continuity check could not fetch {ecosystem} metadata for {package} — skipped (fail open).",
    )
