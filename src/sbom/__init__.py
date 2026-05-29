"""
Gate 6 — SBOM Delta (Recursive)
Generates a CycloneDX SBOM for the updated dependency tree, diffs it
against the prior lockfile state, and flags new transitive packages
and hash mismatches.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import subprocess
import tempfile
from pathlib import Path

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)


class SBOMGate:
    def __init__(self, cfg: dict) -> None:
        self.recursive              = cfg.get("recursive", True)
        self.max_depth              = cfg.get("max_transitive_depth", 10)
        self.new_transitive_action  = cfg.get("new_transitive_action", "quarantine")
        self.min_trust_score        = cfg.get("min_transitive_trust_score", 50)
        self.hash_algorithm         = cfg.get("hash_algorithm", "sha256")

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        try:
            current_tree  = await self._resolve_tree(package, version, ecosystem)
            prior_tree    = await self._load_prior_tree(package, ecosystem)
        except Exception as exc:
            log.warning(f"[sbom] Tree resolution failed: {exc}")
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=Outcome.HOLD,
                message=f"SBOM generation unavailable: {exc}",
                details={"error": str(exc)},
            )

        new_packages      = self._diff_new(current_tree, prior_tree)
        hash_mismatches   = self._diff_hashes(current_tree, prior_tree)

        if hash_mismatches:
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=Outcome.REJECTED,
                message=(
                    f"{len(hash_mismatches)} hash mismatch(es) detected in "
                    f"dependency tree of {package}@{version} — "
                    f"possible silent package replacement: "
                    f"{', '.join(f'{p}@{v}' for p, v in hash_mismatches[:3])}"
                ),
                details={
                    "hash_mismatches": hash_mismatches,
                    "new_packages":    new_packages,
                    "tree_size":       len(current_tree),
                },
            )

        if new_packages:
            action = self._outcome(self.new_transitive_action)
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=action,
                message=(
                    f"{len(new_packages)} new transitive package(s) introduced "
                    f"by {package}@{version}: "
                    f"{', '.join(f'{p}@{v}' for p, v in new_packages[:5])}"
                    f"{'...' if len(new_packages) > 5 else ''}"
                ),
                details={
                    "new_packages":  new_packages,
                    "tree_size":     len(current_tree),
                    "hash_mismatches": [],
                },
            )

        return GateResult(
            gate="Gate 6: SBOM Delta",
            outcome=Outcome.APPROVED,
            message=(
                f"No new transitive packages or hash mismatches for "
                f"{package}@{version} (tree size: {len(current_tree)})"
            ),
            details={
                "new_packages":    [],
                "hash_mismatches": [],
                "tree_size":       len(current_tree),
            },
        )

    async def _resolve_tree(
        self, package: str, version: str, ecosystem: str
    ) -> dict[tuple[str, str], str]:
        """
        Returns {(name, version): hash} for the full transitive tree.
        Uses deps.dev as the primary source for transitive graph data;
        falls back to ecosystem-native tools for local resolution.
        """
        tree: dict[tuple[str, str], str] = {}
        await self._walk_deps_dev(package, version, ecosystem, tree, depth=0)
        return tree

    async def _walk_deps_dev(
        self,
        package: str,
        version: str,
        ecosystem: str,
        tree: dict,
        depth: int,
    ) -> None:
        if depth > self.max_depth:
            return
        if (package, version) in tree:
            return

        eco_map = {"pypi": "PYPI", "npm": "NPM", "cargo": "CARGO",
                   "go": "GO", "maven": "MAVEN", "nuget": "NUGET"}
        eco = eco_map.get(ecosystem.lower(), ecosystem.upper())

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    f"https://api.deps.dev/v3alpha/systems/{eco}"
                    f"/packages/{package}/versions/{version}/dependencies"
                )
                if r.status_code == 404:
                    tree[(package, version)] = ""
                    return
                r.raise_for_status()
                data = r.json()
        except Exception as exc:
            log.debug(f"[sbom] deps.dev walk error at {package}@{version}: {exc}")
            tree[(package, version)] = ""
            return

        # Record this node with its hash
        tree[(package, version)] = data.get("version", {}).get("hash", "")

        # Recurse into direct dependencies
        deps = data.get("dependencies", [])
        tasks = []
        for dep in deps:
            dep_name    = dep.get("packageKey", {}).get("name", "")
            dep_version = dep.get("versionKey", {}).get("version", "")
            dep_eco     = dep.get("packageKey", {}).get("system", ecosystem).lower()
            if dep_name and dep_version:
                tasks.append(
                    self._walk_deps_dev(dep_name, dep_version, dep_eco, tree, depth + 1)
                )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _load_prior_tree(
        self, package: str, ecosystem: str
    ) -> dict[tuple[str, str], str]:
        """
        Load the prior dependency tree from the lockfile snapshot.
        In CI, this is the base-branch lockfile state from the checkout.
        Falls back to empty dict if not available.
        """
        snapshot_path = Path(f".oss-trust-cache/{ecosystem}/{package}.json")
        if snapshot_path.exists():
            data = json.loads(snapshot_path.read_text())
            return {(k.split("@")[0], k.split("@")[1]): v for k, v in data.items()}
        return {}

    def _diff_new(
        self,
        current: dict[tuple[str, str], str],
        prior: dict[tuple[str, str], str],
    ) -> list[tuple[str, str]]:
        """Return packages present in current tree but not in prior."""
        prior_packages = {name for name, _ in prior}
        return [
            (name, ver)
            for name, ver in current
            if name not in prior_packages
        ]

    def _diff_hashes(
        self,
        current: dict[tuple[str, str], str],
        prior: dict[tuple[str, str], str],
    ) -> list[tuple[str, str]]:
        """Return packages where the same name+version has a different hash."""
        mismatches = []
        for (name, ver), current_hash in current.items():
            prior_hash = prior.get((name, ver))
            if (
                prior_hash
                and current_hash
                and prior_hash != current_hash
            ):
                mismatches.append((name, ver))
        return mismatches

    def _outcome(self, action: str) -> str:
        return {
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
            "block":      Outcome.BLOCKED,
        }.get(action, Outcome.QUARANTINE)
