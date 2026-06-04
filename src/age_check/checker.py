"""
Gate 1 — Release age validation.

Checks the publication timestamp of a package release against configurable
hard-block and hold thresholds. The zero-day bypass path is handled by the
pipeline orchestrator before this gate is reached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

import httpx

logger = logging.getLogger(__name__)

REGISTRY_APIS = {
    "PyPI": "https://pypi.org/pypi/{package}/{version}/json",
    "npm": "https://registry.npmjs.org/{package}/{version}",
    "Cargo": "https://crates.io/api/v1/crates/{package}/{version}",
    "Maven": "https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}+AND+v:{version}&rows=1&wt=json",
    "Go": "https://proxy.golang.org/{package}/@v/{version}.info",
}


class AgeDecision(str, Enum):
    PASS = "pass"
    HOLD = "hold"                    # 24–72 h: human approval needed
    BLOCK = "block"                  # < 24 h: auto-blocked
    ZERO_DAY_ELIGIBLE = "zd_eligible"  # < 24 h but CVE exists — pipeline routes to ZD lane


@dataclass
class AgeCheckResult:
    decision: AgeDecision
    age_hours: float
    release_time: datetime
    package: str
    version: str
    ecosystem: str
    message: str


async def check_release_age(
    package: str,
    version: str,
    ecosystem: str,
    hard_block_hours: int = 24,
    hold_hours: int = 72,
    http_client: httpx.AsyncClient | None = None,
) -> AgeCheckResult:
    """
    Fetch the canonical release timestamp for a package version and evaluate
    it against the configured age thresholds.

    Args:
        package:          Package name (e.g. "requests", "express").
        version:          Exact version string (e.g. "2.32.3").
        ecosystem:        One of: PyPI, npm, Cargo, Maven, Go.
        hard_block_hours: Releases younger than this are auto-blocked.
        hold_hours:       Releases younger than this (but older than hard_block)
                          require human approval before proceeding.
        http_client:      Optional pre-configured httpx.AsyncClient (for testing).

    Returns:
        AgeCheckResult with the decision and supporting metadata.
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=15)

    try:
        release_time = await _fetch_release_time(client, package, version, ecosystem)
    finally:
        if own_client:
            await client.aclose()

    now = datetime.now(timezone.utc)
    age = now - release_time
    age_hours = age.total_seconds() / 3600

    if age < timedelta(hours=hard_block_hours):
        decision = AgeDecision.BLOCK
        message = (
            f"{package}@{version} is only {age_hours:.1f}h old — "
            f"hard block threshold is {hard_block_hours}h. "
            "File a CVE reference to route through the zero-day expedited lane."
        )
    elif age < timedelta(hours=hold_hours):
        decision = AgeDecision.HOLD
        message = (
            f"{package}@{version} is {age_hours:.1f}h old — "
            f"within the {hold_hours}h hold window. Human approval required."
        )
    else:
        decision = AgeDecision.PASS
        message = f"{package}@{version} is {age_hours:.1f}h old — age gate cleared."

    logger.info(
        "age_check decision=%s package=%s version=%s age_hours=%.2f",
        decision.value,
        package,
        version,
        age_hours,
    )

    return AgeCheckResult(
        decision=decision,
        age_hours=age_hours,
        release_time=release_time,
        package=package,
        version=version,
        ecosystem=ecosystem,
        message=message,
    )


async def _fetch_release_time(
    client: httpx.AsyncClient,
    package: str,
    version: str,
    ecosystem: str,
) -> datetime:
    """Dispatch to the appropriate registry API and return the release datetime."""

    if ecosystem == "PyPI":
        return await _pypi_release_time(client, package, version)
    elif ecosystem == "npm":
        return await _npm_release_time(client, package, version)
    elif ecosystem == "Cargo":
        return await _cargo_release_time(client, package, version)
    elif ecosystem == "Go":
        return await _go_release_time(client, package, version)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem!r}")


async def _pypi_release_time(
    client: httpx.AsyncClient, package: str, version: str
) -> datetime:
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    resp = client.get(url)
    resp = await resp
    resp.raise_for_status()
    data = resp.json()

    upload_times = [
        datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
        for f in data["urls"]
    ]
    if not upload_times:
        raise ValueError(f"No upload records found for {package}=={version} on PyPI")
    return min(upload_times)


async def _npm_release_time(
    client: httpx.AsyncClient, package: str, version: str
) -> datetime:
    url = f"https://registry.npmjs.org/{package}"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()

    time_str = data.get("time", {}).get(version)
    if not time_str:
        raise ValueError(f"No time record for {package}@{version} on npm")
    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))


async def _cargo_release_time(
    client: httpx.AsyncClient, package: str, version: str
) -> datetime:
    url = f"https://crates.io/api/v1/crates/{package}/{version}"
    resp = await client.get(url, headers={"User-Agent": "oss-trust-framework/0.1"})
    resp.raise_for_status()
    data = resp.json()

    time_str = data.get("version", {}).get("created_at")
    if not time_str:
        raise ValueError(f"No created_at for {package}@{version} on crates.io")
    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))


async def _go_release_time(
    client: httpx.AsyncClient, package: str, version: str
) -> datetime:
    url = f"https://proxy.golang.org/{package}/@v/{version}.info"
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.json()

    time_str = data.get("Time")
    if not time_str:
        raise ValueError(f"No Time field for {package}@{version} from Go proxy")
    return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
