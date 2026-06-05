"""
Gate 3 — Out-of-band trust aggregation.

Queries multiple independent sources that are structurally separate from the
package repository. A compromised repo cannot manipulate these signals, making
a simultaneous compromise of all sources required to defeat this gate.

Sources:
  - OpenSSF Scorecard   (security hygiene score)
  - OSV.dev             (cross-ecosystem CVE database)
  - deps.dev            (Google dependency graph + advisories)
  - GitHub Advisories   (manually reviewed, high signal)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Composite score out of 100. Gate passes if score >= threshold AND
# no active vulnerabilities against the requested version.
DEFAULT_MIN_SCORE = 60
SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com/{repo}"
OSV_API = "https://api.osv.dev/v1/query"
DEPS_DEV_API = "https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{package}/versions/{version}"


@dataclass
class TrustCheckResult:
    passed: bool
    composite_score: float          # 0–100
    scorecard_score: float | None   # 0–10 from OpenSSF
    known_vulns: int
    vuln_ids: list[str]
    deps_metadata: dict
    github_advisories: int
    recommendation: str
    details: dict = field(default_factory=dict)


async def aggregate_trust_score(
    package: str,
    version: str,
    ecosystem: str,
    github_repo: str | None = None,
    github_token: str | None = None,
    min_score: int = DEFAULT_MIN_SCORE,
    http_client: httpx.AsyncClient | None = None,
) -> TrustCheckResult:
    """
    Concurrently query all out-of-band trust sources and compute a composite
    score. Returns a TrustCheckResult with a pass/fail recommendation.

    Args:
        package:      Package name.
        version:      Exact version to evaluate.
        ecosystem:    PyPI | npm | Cargo | Go | Maven.
        github_repo:  "owner/repo" for Scorecard lookup (optional but preferred).
        github_token: GitHub PAT for advisory API (optional, avoids rate limits).
        min_score:    Minimum composite score to pass (0–100).
        http_client:  Optional pre-configured client (for testing).
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        scorecard_task = (
            _fetch_scorecard(client, github_repo)
            if github_repo
            else asyncio.sleep(0, result=None)
        )
        osv_task = _fetch_osv_vulns(client, package, version, ecosystem)
        deps_task = _fetch_deps_dev(client, package, version, ecosystem)
        ghsa_task = _fetch_github_advisories(client, package, github_token)

        scorecard, osv_result, deps_data, ghsa_count = await asyncio.gather(
            scorecard_task, osv_task, deps_task, ghsa_task,
            return_exceptions=True,
        )
    finally:
        if own_client:
            await client.aclose()

    # --- Resolve results, tolerating individual source failures ---
    scorecard_score: float | None = None
    if isinstance(scorecard, float):
        scorecard_score = scorecard
    elif isinstance(scorecard, Exception):
        logger.warning("Scorecard fetch failed: %s", scorecard)

    vulns: list[str] = []
    if isinstance(osv_result, list):
        vulns = osv_result
    elif isinstance(osv_result, Exception):
        logger.warning("OSV fetch failed: %s", osv_result)

    deps: dict = {}
    if isinstance(deps_data, dict):
        deps = deps_data
    elif isinstance(deps_data, Exception):
        logger.warning("deps.dev fetch failed: %s", deps_data)

    ghsa: int = 0
    if isinstance(ghsa_count, int):
        ghsa = ghsa_count
    elif isinstance(ghsa_count, Exception):
        logger.warning("GHSA fetch failed: %s", ghsa_count)

    # --- Composite scoring ---
    # Scorecard: up to 40 points (scorecard is 0–10, scale to 0–40)
    scorecard_contribution = (scorecard_score * 4) if scorecard_score is not None else 20  # default neutral
    # OSV: up to 35 points (deduct per vulnerability, cap deduction at 35)
    vuln_deduction = min(len(vulns) * 20, 35)
    osv_contribution = 35 - vuln_deduction
    # deps.dev: up to 25 points (presence + no advisories)
    deps_contribution = 25 if deps and not deps.get("advisoryKeys") else 10

    composite = round(scorecard_contribution + osv_contribution + deps_contribution, 1)
    composite = max(0.0, min(100.0, composite))

    passed = composite >= min_score and len(vulns) == 0

    recommendation = "PASS" if passed else "QUARANTINE"

    logger.info(
        "trust_check recommendation=%s package=%s version=%s score=%.1f vulns=%d",
        recommendation, package, version, composite, len(vulns),
    )

    return TrustCheckResult(
        passed=passed,
        composite_score=composite,
        scorecard_score=scorecard_score,
        known_vulns=len(vulns),
        vuln_ids=vulns,
        deps_metadata=deps,
        github_advisories=ghsa,
        recommendation=recommendation,
        details={
            "scorecard_contribution": scorecard_contribution,
            "osv_contribution": osv_contribution,
            "deps_contribution": deps_contribution,
        },
    )


async def _fetch_scorecard(client: httpx.AsyncClient, repo: str) -> float:
    url = SCORECARD_API.format(repo=repo)
    resp = await client.get(url)
    if resp.status_code == 404:
        return 5.0  # Unknown repo: neutral score
    resp.raise_for_status()
    return float(resp.json().get("score", 0))


async def _fetch_osv_vulns(
    client: httpx.AsyncClient, package: str, version: str, ecosystem: str
) -> list[str]:
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }
    resp = await client.post(OSV_API, json=payload)
    resp.raise_for_status()
    vulns = resp.json().get("vulns", [])
    return [v["id"] for v in vulns]


async def _fetch_deps_dev(
    client: httpx.AsyncClient, package: str, version: str, ecosystem: str
) -> dict:
    eco_map = {"PyPI": "PyPI", "npm": "npm", "Cargo": "Go", "Go": "Go", "Maven": "Maven"}
    eco = eco_map.get(ecosystem, ecosystem)
    url = DEPS_DEV_API.format(ecosystem=eco, package=package, version=version)
    resp = await client.get(url)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json()


async def _fetch_github_advisories(
    client: httpx.AsyncClient, package: str, token: str | None
) -> int:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = await client.get(
        "https://api.github.com/advisories",
        params={"affects": package, "per_page": 10},
        headers=headers,
    )
    if resp.status_code in (401, 403):
        logger.warning("GitHub advisory API: auth required for higher limits")
        return 0
    resp.raise_for_status()
    return len(resp.json())
