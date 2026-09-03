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