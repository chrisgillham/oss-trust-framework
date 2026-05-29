"""
Gate 1 — Age Check
Validates release timestamp against configurable block/hold thresholds.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

PYPI_META_URL   = "https://pypi.org/pypi/{package}/{version}/json"
NPM_META_URL    = "https://registry.npmjs.org/{package}/{version}"
CARGO_META_URL  = "https://crates.io/api/v1/crates/{package}/{version}"
GO_META_URL     = "https://proxy.golang.org/{package}/@v/{version}.info"


class AgeGate:
    def __init__(self, cfg: dict) -> None:
        self.hard_block_hours = cfg.get("hard_block_hours", 24)
        self.hold_hours       = cfg.get("hold_hours", 72)

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        try:
            published_at = await self._fetch_publish_time(package, version, ecosystem)
        except Exception as exc:
            log.warning(f"[age] Could not fetch publish time for {package}@{version}: {exc}")
            return GateResult(
                gate="Gate 1: Age",
                outcome=Outcome.HOLD,
                message="Publish timestamp unavailable — treating as HOLD",
                details={"error": str(exc)},
            )

        now = datetime.now(timezone.utc)
        age_hours = (now - published_at).total_seconds() / 3600

        if age_hours < self.hard_block_hours:
            return GateResult(
                gate="Gate 1: Age",
                outcome=Outcome.BLOCKED,
                message=(
                    f"Package published {age_hours:.1f}h ago — "
                    f"below hard block threshold of {self.hard_block_hours}h"
                ),
                details={"published_at": published_at.isoformat(), "age_hours": age_hours},
            )

        if age_hours < self.hold_hours:
            return GateResult(
                gate="Gate 1: Age",
                outcome=Outcome.HOLD,
                message=(
                    f"Package published {age_hours:.1f}h ago — "
                    f"within hold window ({self.hard_block_hours}–{self.hold_hours}h)"
                ),
                details={"published_at": published_at.isoformat(), "age_hours": age_hours},
            )

        return GateResult(
            gate="Gate 1: Age",
            outcome=Outcome.APPROVED,
            message=f"Package age {age_hours:.0f}h — above hold threshold",
            details={"published_at": published_at.isoformat(), "age_hours": age_hours},
        )

    async def _fetch_publish_time(
        self, package: str, version: str, ecosystem: str
    ) -> datetime:
        eco = ecosystem.lower()
        async with httpx.AsyncClient(timeout=10) as client:
            if eco == "pypi":
                r = await client.get(PYPI_META_URL.format(package=package, version=version))
                r.raise_for_status()
                ts = r.json()["urls"][0]["upload_time_iso_8601"]
                return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)

            if eco == "npm":
                r = await client.get(NPM_META_URL.format(package=package, version=version))
                r.raise_for_status()
                ts = r.json().get("time", {}).get(version, "")
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))

            if eco == "cargo":
                r = await client.get(CARGO_META_URL.format(package=package, version=version))
                r.raise_for_status()
                ts = r.json()["version"]["created_at"]
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))

            if eco == "go":
                pkg_encoded = package.replace("/", "%2F")
                r = await client.get(
                    GO_META_URL.format(package=pkg_encoded, version=version)
                )
                r.raise_for_status()
                ts = r.json()["Time"]
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))

        raise ValueError(f"Unsupported ecosystem for age check: {ecosystem}")
