"""
Gate 5 — License Compliance
Validates SPDX identifier against allowlist, detects license changes
between versions, and flags copyleft escalation or commercial restrictions.
"""
from __future__ import annotations

import logging

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

# SPDX identifiers that indicate strong copyleft
COPYLEFT_LICENSES = frozenset({
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "OSL-3.0", "EUPL-1.2",
})

# Licenses with commercial-use restrictions (non-SPDX or hybrid)
COMMERCIAL_RESTRICT = frozenset({
    "Commons-Clause", "SSPL-1.0", "BSL-1.1", "BUSL-1.1",
    "Elastic-2.0", "Confluent-Community-1.0",
})

# SPDX identifiers that are permissive (not copyleft)
PERMISSIVE = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "0BSD", "Unlicense", "CC0-1.0",
    "MPL-2.0",   # Weak copyleft — file-level only
    "CDDL-1.0",  # Weak copyleft
})


class LicenseGate:
    def __init__(self, cfg: dict) -> None:
        self.allowlist               = set(cfg.get("allowlist", list(PERMISSIVE)))
        self.warn_on_change          = cfg.get("warn_on_change", True)
        self.block_copyleft          = cfg.get("block_copyleft", True)
        self.block_commercial        = cfg.get("block_commercial_restrict", True)
        self.on_unlicensed           = cfg.get("on_unlicensed", "block")
        self.on_allowlist_violation  = cfg.get("on_allowlist_violation", "quarantine")

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        current_license, prior_license = await self._fetch_licenses(
            package, version, ecosystem
        )

        changed  = bool(prior_license) and current_license != prior_license
        copyleft = self._is_copyleft(current_license)
        commercial_restricted = self._is_commercial_restricted(current_license)
        on_allowlist = current_license in self.allowlist

        license_details = {
            "license": {
                "current":             current_license,
                "prior":               prior_license,
                "changed":             changed,
                "copyleft":            copyleft,
                "commercial_restrict": commercial_restricted,
                "on_allowlist":        on_allowlist,
                "not_on_allowlist":    not on_allowlist,
            }
        }

        # Unlicensed
        if not current_license or current_license in ("UNKNOWN", "NOASSERTION"):
            return GateResult(
                gate="Gate 5: License",
                outcome=self._outcome(self.on_unlicensed),
                message=f"No license identifier found for {package}@{version}",
                details={**license_details, "license_changed": False, "license_copyleft": False},
            )

        # Copyleft escalation
        if copyleft and self.block_copyleft:
            return GateResult(
                gate="Gate 5: License",
                outcome=Outcome.BLOCKED,
                message=(
                    f"{package}@{version} uses copyleft license {current_license} "
                    f"— organizational policy blocks copyleft"
                ),
                details={
                    **license_details,
                    "license_changed": changed,
                    "license_copyleft": True,
                },
            )

        # Commercial restriction
        if commercial_restricted and self.block_commercial:
            return GateResult(
                gate="Gate 5: License",
                outcome=Outcome.BLOCKED,
                message=(
                    f"{package}@{version} contains commercial-use restriction "
                    f"({current_license})"
                ),
                details={
                    **license_details,
                    "license_changed": changed,
                    "license_copyleft": False,
                },
            )

        # Not on allowlist
        if not on_allowlist:
            return GateResult(
                gate="Gate 5: License",
                outcome=self._outcome(self.on_allowlist_violation),
                message=(
                    f"{package}@{version} license '{current_license}' "
                    f"is not on the organizational allowlist"
                ),
                details={
                    **license_details,
                    "license_changed": changed,
                    "license_copyleft": False,
                },
            )

        # License changed (warn, but pass)
        if changed and self.warn_on_change:
            return GateResult(
                gate="Gate 5: License",
                outcome=Outcome.HOLD,
                message=(
                    f"License changed for {package}: "
                    f"{prior_license} → {current_license} — legal review recommended"
                ),
                details={
                    **license_details,
                    "license_changed": True,
                    "license_copyleft": False,
                },
            )

        return GateResult(
            gate="Gate 5: License",
            outcome=Outcome.APPROVED,
            message=f"{package}@{version} license {current_license} approved",
            details={
                **license_details,
                "license_changed": changed,
                "license_copyleft": False,
            },
        )

    async def _fetch_licenses(
        self, package: str, version: str, ecosystem: str
    ) -> tuple[str, str]:
        """Return (current_license, prior_license). Prior may be empty string."""
        current = await self._fetch_single(package, version, ecosystem)
        # Fetch prior version license for change detection
        prior_version = await self._fetch_prior_version(package, version, ecosystem)
        prior = ""
        if prior_version:
            try:
                prior = await self._fetch_single(package, prior_version, ecosystem)
            except Exception:
                pass
        return current, prior

    async def _fetch_single(self, package: str, version: str, ecosystem: str) -> str:
        eco = ecosystem.lower()
        async with httpx.AsyncClient(timeout=10) as client:
            if eco == "pypi":
                r = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
                r.raise_for_status()
                return r.json().get("info", {}).get("license", "") or "UNKNOWN"

            if eco == "npm":
                r = await client.get(f"https://registry.npmjs.org/{package}/{version}")
                r.raise_for_status()
                lic = r.json().get("license", "")
                if isinstance(lic, dict):
                    lic = lic.get("type", "")
                return lic or "UNKNOWN"

            if eco in ("cargo",):
                r = await client.get(
                    f"https://crates.io/api/v1/crates/{package}/{version}"
                )
                r.raise_for_status()
                return r.json().get("version", {}).get("license", "") or "UNKNOWN"

        # Fallback: query deps.dev
        eco_map = {"pypi": "PYPI", "npm": "NPM", "cargo": "CARGO",
                   "go": "GO", "maven": "MAVEN", "nuget": "NUGET"}
        eco_key = eco_map.get(eco, eco.upper())
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.deps.dev/v3alpha/systems/{eco_key}"
                f"/packages/{package}/versions/{version}"
            )
            if r.status_code == 200:
                licenses = (
                    r.json().get("version", {})
                     .get("licenses", [])
                )
                if licenses:
                    return licenses[0]
        return "UNKNOWN"

    async def _fetch_prior_version(
        self, package: str, version: str, ecosystem: str
    ) -> str | None:
        """Attempt to find the most recent release before the current version."""
        eco = ecosystem.lower()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if eco == "pypi":
                    r = await client.get(f"https://pypi.org/pypi/{package}/json")
                    r.raise_for_status()
                    releases = sorted(r.json().get("releases", {}).keys())
                    idx = releases.index(version) if version in releases else -1
                    return releases[idx - 1] if idx > 0 else None

                if eco == "npm":
                    r = await client.get(f"https://registry.npmjs.org/{package}")
                    r.raise_for_status()
                    versions = sorted(r.json().get("versions", {}).keys())
                    idx = versions.index(version) if version in versions else -1
                    return versions[idx - 1] if idx > 0 else None
        except Exception:
            pass
        return None

    def _is_copyleft(self, spdx: str) -> bool:
        return any(
            spdx.startswith(c) or spdx == c
            for c in COPYLEFT_LICENSES
        )

    def _is_commercial_restricted(self, spdx: str) -> bool:
        return any(r in spdx for r in COMMERCIAL_RESTRICT)

    def _outcome(self, action: str) -> str:
        return {
            "block":      Outcome.BLOCKED,
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
            "warn":       Outcome.HOLD,
        }.get(action, Outcome.QUARANTINE)
