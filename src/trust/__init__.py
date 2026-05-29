"""
Gate 4 — Out-of-Band Trust
Queries OpenSSF Scorecard, OSV, deps.dev, GitHub Advisories, and Socket.dev.
Aggregates weighted scores and surfaces advisory IDs for reachability analysis.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)


@dataclass
class TrustSignal:
    source: str
    score: float        # 0.0–10.0 normalised
    weight: float
    advisories: list[str] = field(default_factory=list)
    flags: dict[str, bool] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


class OOBTrustGate:
    def __init__(self, sources_cfg: dict, scoring_cfg: dict) -> None:
        self.sources     = sources_cfg.get("sources", self._default_sources())
        self.min_score   = scoring_cfg.get("min_score", 60)
        self.require_zero_vulns = scoring_cfg.get("require_zero_vulns", True)

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        signals = await self._fetch_all(package, version, ecosystem)

        composite = self._composite_score(signals)
        advisory_ids = list({a for s in signals for a in s.advisories})
        flags: dict[str, bool] = {}
        for s in signals:
            flags.update(s.flags)

        active_vulns = len(advisory_ids)

        if self.require_zero_vulns and active_vulns > 0:
            return GateResult(
                gate="Gate 4: OOB Trust",
                outcome=Outcome.QUARANTINE,
                message=(
                    f"{active_vulns} active vulnerabilit{'y' if active_vulns == 1 else 'ies'} "
                    f"against {package}@{version}: {', '.join(advisory_ids[:5])}"
                ),
                details={
                    "composite_score": composite,
                    "advisory_ids": advisory_ids,
                    "signals": [s.__dict__ for s in signals],
                    "flags": flags,
                },
            )

        normalised = composite * 10   # 0–10 → 0–100 for consistency
        if normalised < self.min_score:
            return GateResult(
                gate="Gate 4: OOB Trust",
                outcome=Outcome.QUARANTINE,
                message=(
                    f"Composite OOB trust score {normalised:.0f}/100 below "
                    f"minimum {self.min_score} for {package}@{version}"
                ),
                details={
                    "composite_score": composite,
                    "normalised_score": normalised,
                    "advisory_ids": advisory_ids,
                    "signals": [s.__dict__ for s in signals],
                    "flags": flags,
                },
            )

        return GateResult(
            gate="Gate 4: OOB Trust",
            outcome=Outcome.APPROVED,
            message=(
                f"OOB trust score {normalised:.0f}/100, "
                f"{active_vulns} advisories for {package}@{version}"
            ),
            details={
                "composite_score": composite,
                "normalised_score": normalised,
                "advisory_ids": advisory_ids,
                "signals": [s.__dict__ for s in signals],
                "flags": flags,
            },
        )

    async def _fetch_all(
        self, package: str, version: str, ecosystem: str
    ) -> list[TrustSignal]:
        import asyncio
        tasks = [
            self._openssf_scorecard(package, ecosystem),
            self._osv(package, version, ecosystem),
            self._deps_dev(package, version, ecosystem),
            self._github_advisories(package, version, ecosystem),
            self._socket(package, version, ecosystem),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        signals = []
        for r in results:
            if isinstance(r, Exception):
                log.warning(f"[oob] Signal fetch error: {r}")
            else:
                signals.append(r)
        return signals

    def _composite_score(self, signals: list[TrustSignal]) -> float:
        total_weight = sum(s.weight for s in signals)
        if not total_weight:
            return 5.0   # Neutral when no signals available
        return sum(s.score * s.weight for s in signals) / total_weight

    # ── Individual source fetchers ────────────────────────────────────────────

    async def _openssf_scorecard(self, package: str, ecosystem: str) -> TrustSignal:
        eco_map = {"npm": "npm", "pypi": "pypi", "go": "golang",
                   "cargo": "crates.io", "maven": "maven"}
        eco = eco_map.get(ecosystem.lower(), ecosystem.lower())
        url = f"https://api.securityscorecards.dev/projects/{eco}/{package}"

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 404:
                return TrustSignal(source="openssf_scorecard", score=5.0, weight=0.30,
                                   raw={"error": "not found"})
            r.raise_for_status()
            data = r.json()

        score = float(data.get("score", 5.0))
        checks = {c["name"]: c["score"] for c in data.get("checks", [])}

        flags = {
            "author_reputation": checks.get("Maintained", 10) < 3,
            "provenance_activity": checks.get("Signed-Releases", 10) < 3,
        }

        return TrustSignal(
            source="openssf_scorecard",
            score=score,
            weight=0.30,
            flags=flags,
            raw={"score": score, "checks": checks},
        )

    async def _osv(self, package: str, version: str, ecosystem: str) -> TrustSignal:
        eco_map = {"npm": "npm", "pypi": "PyPI", "go": "Go",
                   "cargo": "crates.io", "maven": "Maven", "nuget": "NuGet"}
        eco = eco_map.get(ecosystem.lower(), ecosystem)

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={"version": version, "package": {"name": package, "ecosystem": eco}},
            )
            r.raise_for_status()
            data = r.json()

        vulns = data.get("vulns", [])
        advisory_ids = [v["id"] for v in vulns]
        score = max(0.0, 10.0 - len(vulns) * 2)

        return TrustSignal(
            source="osv",
            score=score,
            weight=0.25,
            advisories=advisory_ids,
            raw={"vuln_count": len(vulns), "advisories": advisory_ids[:10]},
        )

    async def _deps_dev(self, package: str, version: str, ecosystem: str) -> TrustSignal:
        eco_map = {"pypi": "PYPI", "npm": "NPM", "cargo": "CARGO",
                   "go": "GO", "maven": "MAVEN", "nuget": "NUGET"}
        eco = eco_map.get(ecosystem.lower(), ecosystem.upper())
        url = (
            f"https://api.deps.dev/v3alpha/systems/{eco}"
            f"/packages/{package}/versions/{version}"
        )

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 404:
                return TrustSignal(source="deps_dev", score=5.0, weight=0.20)
            r.raise_for_status()
            data = r.json()

        advisories = [
            a.get("advisoryKey", {}).get("id", "")
            for a in data.get("version", {}).get("advisoryKeys", [])
        ]
        is_default   = data.get("version", {}).get("isDefault", True)
        project_count = data.get("version", {}).get("dependentCount", 0)
        score = 8.0 if is_default else 5.0
        score -= len(advisories) * 2

        return TrustSignal(
            source="deps_dev",
            score=max(0.0, score),
            weight=0.20,
            advisories=advisories,
            raw={"is_default": is_default, "dependent_count": project_count},
        )

    async def _github_advisories(
        self, package: str, version: str, ecosystem: str
    ) -> TrustSignal:
        eco_map = {"npm": "NPM", "pypi": "PIP", "go": "GO",
                   "cargo": "RUST", "maven": "MAVEN", "nuget": "NUGET"}
        eco = eco_map.get(ecosystem.lower())
        if not eco:
            return TrustSignal(source="github_advisories", score=7.0, weight=0.15)

        token = os.environ.get("GITHUB_TOKEN", "")
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        async with httpx.AsyncClient(timeout=10, headers=headers) as client:
            r = await client.get(
                "https://api.github.com/advisories",
                params={
                    "ecosystem": eco,
                    "package":   package,
                    "per_page":  20,
                },
                headers={"X-GitHub-Api-Version": "2022-11-28", **headers},
            )
            if r.status_code in (401, 403):
                return TrustSignal(source="github_advisories", score=7.0, weight=0.15,
                                   raw={"error": "auth_required"})
            r.raise_for_status()
            data = r.json()

        # Filter to advisories covering the specific version
        relevant = [
            a for a in data
            if any(
                p.get("package", {}).get("name", "").lower() == package.lower()
                for p in a.get("vulnerabilities", [])
            )
        ]
        advisory_ids = [a["ghsa_id"] for a in relevant]
        score = max(0.0, 10.0 - len(advisory_ids) * 2.5)

        return TrustSignal(
            source="github_advisories",
            score=score,
            weight=0.15,
            advisories=advisory_ids,
            raw={"advisory_count": len(relevant)},
        )

    async def _socket(self, package: str, version: str, ecosystem: str) -> TrustSignal:
        api_key = os.environ.get("SOCKET_API_KEY", "")
        if not api_key:
            return TrustSignal(source="socket", score=7.0, weight=0.10,
                               raw={"error": "no_api_key"})

        eco_map = {"npm": "npm", "pypi": "pypi"}
        eco = eco_map.get(ecosystem.lower())
        if not eco:
            return TrustSignal(source="socket", score=7.0, weight=0.10)

        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://api.socket.dev/v0/packages/{eco}/{package}/{version}/score",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if r.status_code == 404:
                return TrustSignal(source="socket", score=5.0, weight=0.10)
            r.raise_for_status()
            data = r.json()

        score_data = data.get("score", {})
        supply_chain = score_data.get("supplyChain", 1.0)
        malware      = score_data.get("malware", 1.0)

        # Socket returns 0–1 per category; convert to 0–10
        composite = ((supply_chain + malware) / 2) * 10

        flags = {
            "behavior_change":  data.get("alerts", {}).get("networkAccess", False),
            "author_reputation": data.get("alerts", {}).get("newAuthor", False),
            "typosquatting":    data.get("alerts", {}).get("typosquat", False),
        }

        return TrustSignal(
            source="socket",
            score=composite,
            weight=0.10,
            flags=flags,
            raw=score_data,
        )

    @staticmethod
    def _default_sources() -> list[dict]:
        return [
            {"name": "openssf_scorecard", "weight": 0.30},
            {"name": "osv",               "weight": 0.25},
            {"name": "deps_dev",          "weight": 0.20},
            {"name": "github_advisories", "weight": 0.15},
            {"name": "socket",            "weight": 0.10},
        ]
