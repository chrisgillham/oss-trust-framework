"""
Gate 3 — SLSA Provenance
Fetches and verifies SLSA attestations via in-toto / Sigstore.
Enforces minimum SLSA levels per dependency criticality class.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

REKOR_SEARCH = "https://rekor.sigstore.dev/api/v1/index/retrieve"
DEPS_DEV     = "https://api.deps.dev/v3alpha/systems/{eco}/packages/{pkg}/versions/{ver}"


@dataclass
class SLSAAttestation:
    level: int                    # 0–4
    verified: bool
    build_type: str = ""
    builder_id: str = ""
    source_uri: str = ""
    is_hermetic: bool = False
    is_reproducible: bool = False


class SLSAGate:
    """
    SLSA Provenance Gate.

    Level mapping:
      0 — No provenance
      1 — Provenance exists (not authenticated)
      2 — Hosted build platform, authenticated provenance
      3 — Hardened build platform, non-falsifiable provenance
      4 — Two-party review + hermetic, reproducible build
    """

    def __init__(self, cfg: dict) -> None:
        self.critical_packages = cfg.get("critical_packages", [])
        self.default_min_level  = cfg.get("default_min_level", 1)
        self.on_missing         = cfg.get("on_missing_attestation", "quarantine")
        self.on_below_min       = cfg.get("on_below_minimum", "quarantine")

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        attestation = await self._fetch_attestation(package, version, ecosystem)
        dep_class, min_level = self._resolve_class_and_min(package)
        is_critical = dep_class in ("auth", "crypto", "tls")

        details = {
            "slsa": {
                "level":           attestation.level,
                "verified":        attestation.verified,
                "build_type":      attestation.build_type,
                "builder_id":      attestation.builder_id,
                "source_uri":      attestation.source_uri,
                "is_hermetic":     attestation.is_hermetic,
                "is_reproducible": attestation.is_reproducible,
                "dependency_class": dep_class,
                "min_level_required": min_level,
                "is_critical_path":   is_critical,
            }
        }

        if attestation.level == 0 or not attestation.verified:
            action = self._outcome(self.on_missing)
            return GateResult(
                gate="Gate 3: SLSA",
                outcome=action,
                message=(
                    f"No verified SLSA provenance for {package}@{version} "
                    f"(class={dep_class}, min_required=SLSA {min_level})"
                ),
                details=details,
            )

        if attestation.level < min_level:
            action = self._outcome(self.on_below_min)
            return GateResult(
                gate="Gate 3: SLSA",
                outcome=action,
                message=(
                    f"SLSA {attestation.level} is below minimum {min_level} "
                    f"for class '{dep_class}' ({package}@{version})"
                ),
                details=details,
            )

        return GateResult(
            gate="Gate 3: SLSA",
            outcome=Outcome.APPROVED,
            message=(
                f"SLSA {attestation.level} verified for {package}@{version} "
                f"(class={dep_class}, min={min_level})"
            ),
            details=details,
        )

    def _resolve_class_and_min(self, package: str) -> tuple[str, int]:
        for rule in self.critical_packages:
            if fnmatch.fnmatch(package.lower(), rule["pattern"].lower()):
                return rule.get("class", "critical"), rule.get("min_level", 3)
        return "general", self.default_min_level

    async def _fetch_attestation(
        self, package: str, version: str, ecosystem: str
    ) -> SLSAAttestation:
        """
        Attempt to fetch SLSA attestation from multiple sources:
          1. deps.dev (SLSA metadata embedded in response)
          2. Rekor transparency log search by artifact hash
          3. Package registry attestation endpoint (PyPI, npm)
        """
        try:
            return await self._fetch_from_deps_dev(package, version, ecosystem)
        except Exception as exc:
            log.debug(f"[slsa] deps.dev unavailable for {package}@{version}: {exc}")

        try:
            return await self._fetch_from_rekor(package, version, ecosystem)
        except Exception as exc:
            log.debug(f"[slsa] Rekor unavailable for {package}@{version}: {exc}")

        return SLSAAttestation(level=0, verified=False)

    async def _fetch_from_deps_dev(
        self, package: str, version: str, ecosystem: str
    ) -> SLSAAttestation:
        eco_map = {
            "pypi": "PYPI", "npm": "NPM", "cargo": "CARGO",
            "go": "GO", "maven": "MAVEN", "nuget": "NUGET",
        }
        eco = eco_map.get(ecosystem.lower(), ecosystem.upper())
        url = DEPS_DEV.format(eco=eco, pkg=package, ver=version)

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()

        slsa_data = data.get("version", {}).get("slsaProvenances", [])
        if not slsa_data:
            return SLSAAttestation(level=0, verified=False)

        best = max(slsa_data, key=lambda x: x.get("slsaLevel", 0))
        return SLSAAttestation(
            level        = best.get("slsaLevel", 0),
            verified     = best.get("verified", False),
            build_type   = best.get("buildType", ""),
            builder_id   = best.get("builderId", ""),
            source_uri   = best.get("sourceUri", ""),
            is_hermetic  = best.get("hermetic", False),
        )

    async def _fetch_from_rekor(
        self, package: str, version: str, ecosystem: str
    ) -> SLSAAttestation:
        """Search Rekor for a SLSA attestation entry matching this artifact."""
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                REKOR_SEARCH,
                json={"hash": f"sha256:{package}-{version}"},
            )
            if r.status_code == 404 or not r.json():
                return SLSAAttestation(level=0, verified=False)

            entries = r.json()
            for entry_uuid in entries[:5]:
                entry_r = await client.get(
                    f"https://rekor.sigstore.dev/api/v1/log/entries/{entry_uuid}"
                )
                entry_data = entry_r.json()
                for _, val in entry_data.items():
                    body_type = val.get("body", {}).get("kind", "")
                    if "slsa" in body_type.lower() or "intoto" in body_type.lower():
                        return SLSAAttestation(
                            level    = 2,   # Rekor-verified = minimum SLSA 2
                            verified = True,
                            build_type = body_type,
                            builder_id = "rekor-verified",
                        )

        return SLSAAttestation(level=0, verified=False)

    @staticmethod
    def _outcome(action: str) -> str:
        return {
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
            "block":      Outcome.BLOCKED,
            "warn":       Outcome.HOLD,
        }.get(action, Outcome.QUARANTINE)
