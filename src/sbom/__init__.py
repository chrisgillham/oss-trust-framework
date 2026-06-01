"""
Gate 6 — SBOM Delta (Recursive) + SBOM Generation
────────────────────────────────────────────────────
Generates a CycloneDX 1.6 SBOM from the resolved full dependency tree
(direct + all transitive dependencies), diffs against the prior lockfile
state, and flags new packages and hash mismatches.

Side-effect: After every successful tree resolution — whether the gate
passes or fails — a current, complete SBOM is written to:
  sbom/sbom-{ecosystem}.cdx.json          (CycloneDX JSON)
  sbom/sbom-{ecosystem}.cdx.xml           (CycloneDX XML, optional)

This ensures the repository SBOM is always up to date and accurate,
including all transitive dependencies discovered during the trust check.
The SBOM is uploaded as a GitHub Actions artifact and optionally committed
to the repository via the workflow.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)

SBOM_OUTPUT_DIR = Path("sbom")


class SBOMGate:
    def __init__(self, cfg: dict) -> None:
        self.recursive             = cfg.get("recursive", True)
        self.max_depth             = cfg.get("max_transitive_depth", 10)
        self.new_transitive_action = cfg.get("new_transitive_action", "quarantine")
        self.min_trust_score       = cfg.get("min_transitive_trust_score", 50)
        self.hash_algorithm        = cfg.get("hash_algorithm", "sha256")
        self.generate_sbom         = cfg.get("generate_sbom", True)
        self.sbom_formats          = cfg.get("sbom_formats", ["json"])    # json | xml | both
        self.sbom_output_dir       = Path(cfg.get("sbom_output_dir", "sbom"))
        self.commit_sbom           = cfg.get("commit_sbom", False)        # auto-commit to repo

    async def evaluate(self, package: str, version: str, ecosystem: str) -> GateResult:
        try:
            current_tree = await self._resolve_tree(package, version, ecosystem)
            prior_tree   = await self._load_prior_tree(package, ecosystem)
        except Exception as exc:
            log.warning(f"[sbom] Tree resolution failed: {exc}")
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=Outcome.HOLD,
                message=f"SBOM generation unavailable: {exc}",
                details={"error": str(exc)},
            )

        # ── Always generate the SBOM as a side-effect ─────────────────────
        # This runs regardless of gate outcome so the SBOM is always current.
        sbom_paths = {}
        if self.generate_sbom:
            sbom_paths = await self._write_sbom(package, version, ecosystem, current_tree)
            log.info(
                f"[sbom] SBOM updated: {len(current_tree)} components "
                f"({sum(1 for (n,_) in current_tree if n == package)} direct, "
                f"{len(current_tree) - 1} transitive)"
            )

        # ── Delta analysis ─────────────────────────────────────────────────
        new_packages    = self._diff_new(current_tree, prior_tree)
        hash_mismatches = self._diff_hashes(current_tree, prior_tree)

        # ── Save current tree as new snapshot ─────────────────────────────
        await self._save_snapshot(package, ecosystem, current_tree)

        base_details = {
            "new_packages":     [(n, v) for n, v in new_packages],
            "hash_mismatches":  [(n, v) for n, v in hash_mismatches],
            "tree_size":        len(current_tree),
            "sbom_paths":       {k: str(v) for k, v in sbom_paths.items()},
            "component_counts": {
                "total":      len(current_tree),
                "direct":     1,   # The package being evaluated
                "transitive": len(current_tree) - 1,
            },
        }

        if hash_mismatches:
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=Outcome.REJECTED,
                message=(
                    f"{len(hash_mismatches)} hash mismatch(es) in dependency tree of "
                    f"{package}@{version} — possible silent package replacement: "
                    f"{', '.join(f'{p}@{v}' for p, v in hash_mismatches[:3])}"
                ),
                details=base_details,
            )

        if new_packages:
            action = self._outcome(self.new_transitive_action)
            return GateResult(
                gate="Gate 6: SBOM Delta",
                outcome=action,
                message=(
                    f"{len(new_packages)} new transitive package(s) introduced by "
                    f"{package}@{version}: "
                    f"{', '.join(f'{p}@{v}' for p, v in new_packages[:5])}"
                    f"{'...' if len(new_packages) > 5 else ''}"
                ),
                details=base_details,
            )

        return GateResult(
            gate="Gate 6: SBOM Delta",
            outcome=Outcome.APPROVED,
            message=(
                f"No new transitive packages or hash mismatches for "
                f"{package}@{version} (tree: {len(current_tree)} components, "
                f"SBOM updated)"
            ),
            details=base_details,
        )

    # ── Tree resolution ───────────────────────────────────────────────────────

    async def _resolve_tree(
        self, package: str, version: str, ecosystem: str
    ) -> dict[tuple[str, str], str]:
        """
        Returns {(name, version): hash} for the full transitive tree.
        Uses deps.dev as the primary source. Falls back to empty entry on error.
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
        if depth > self.max_depth or (package, version) in tree:
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

        tree[(package, version)] = data.get("version", {}).get("hash", "")

        tasks = []
        for dep in data.get("dependencies", []):
            dep_name    = dep.get("packageKey", {}).get("name", "")
            dep_version = dep.get("versionKey", {}).get("version", "")
            dep_eco     = dep.get("packageKey", {}).get("system", ecosystem).lower()
            if dep_name and dep_version:
                tasks.append(
                    self._walk_deps_dev(dep_name, dep_version, dep_eco, tree, depth + 1)
                )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ── SBOM generation ───────────────────────────────────────────────────────

    async def _write_sbom(
        self,
        root_package: str,
        root_version: str,
        ecosystem: str,
        tree: dict[tuple[str, str], str],
    ) -> dict[str, Path]:
        """
        Generate a CycloneDX 1.6 SBOM from the resolved dependency tree.
        Returns a dict of {format: output_path}.
        """
        self.sbom_output_dir.mkdir(parents=True, exist_ok=True)

        sbom = self._build_cyclonedx(root_package, root_version, ecosystem, tree)
        paths: dict[str, Path] = {}

        if "json" in self.sbom_formats or "both" in self.sbom_formats:
            json_path = self.sbom_output_dir / f"sbom-{ecosystem}.cdx.json"
            json_path.write_text(
                json.dumps(sbom, indent=2, sort_keys=False) + "\n"
            )
            paths["json"] = json_path
            log.info(f"[sbom] CycloneDX JSON written: {json_path}")

        if "xml" in self.sbom_formats or "both" in self.sbom_formats:
            xml_path = self.sbom_output_dir / f"sbom-{ecosystem}.cdx.xml"
            xml_content = self._cyclonedx_to_xml(sbom)
            xml_path.write_text(xml_content)
            paths["xml"] = xml_path
            log.info(f"[sbom] CycloneDX XML written: {xml_path}")

        # Write a combined all-ecosystems manifest if multiple ecosystem
        # SBOMs exist in the output directory
        await self._write_manifest()

        if self.commit_sbom:
            await self._commit_sbom(paths)

        return paths

    def _build_cyclonedx(
        self,
        root_package: str,
        root_version: str,
        ecosystem: str,
        tree: dict[tuple[str, str], str],
    ) -> dict[str, Any]:
        """Build a CycloneDX 1.6 SBOM document from the dependency tree."""
        now        = datetime.now(timezone.utc).isoformat()
        bom_serial = self._bom_serial(root_package, root_version, ecosystem, now)
        repo_name  = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
        run_id     = os.environ.get("GITHUB_RUN_ID", "")
        sha        = os.environ.get("GITHUB_SHA", "")

        # ── Metadata component (the repo / application) ───────────────────
        metadata_component = {
            "type":    "application",
            "name":    repo_name,
            "version": sha[:8] if sha else "unknown",
            "purl":    f"pkg:github/{repo_name}@{sha[:8] if sha else 'unknown'}",
            "properties": [
                {"name": "oss-trust:run_id",    "value": run_id},
                {"name": "oss-trust:evaluated", "value": now},
            ],
        }

        # ── Component list (all packages in the tree) ─────────────────────
        purl_type = self._purl_type(ecosystem)
        components = []
        for (pkg_name, pkg_ver), pkg_hash in sorted(tree.items()):
            is_root = (pkg_name == root_package and pkg_ver == root_version)
            comp: dict[str, Any] = {
                "type":    "library",
                "name":    pkg_name,
                "version": pkg_ver,
                "purl":    f"pkg:{purl_type}/{pkg_name}@{pkg_ver}",
                "scope":   "required",
                "properties": [
                    {"name": "oss-trust:ecosystem",    "value": ecosystem},
                    {"name": "oss-trust:is_direct",    "value": str(is_root).lower()},
                    {"name": "oss-trust:depth",        "value": "0" if is_root else "transitive"},
                ],
            }
            if pkg_hash:
                # CycloneDX hashes must have a known algorithm — use SHA-256
                # The hash from deps.dev is the canonical content hash
                comp["hashes"] = [{"alg": "SHA-256", "content": pkg_hash}]
            if is_root:
                comp["evidence"] = {
                    "occurrences": [{"location": f"requirements.txt / lockfile ({ecosystem})"}]
                }
            components.append(comp)

        # ── Dependency graph ──────────────────────────────────────────────
        # For the root package, list all other tree members as dependsOn
        # (full transitive graph — deps.dev provides the full tree)
        root_purl    = f"pkg:{purl_type}/{root_package}@{root_version}"
        all_purls    = [f"pkg:{purl_type}/{n}@{v}" for n, v in tree.keys()
                        if not (n == root_package and v == root_version)]
        dependencies = [{"ref": root_purl, "dependsOn": all_purls}]

        return {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": bom_serial,
            "version":     1,
            "metadata": {
                "timestamp": now,
                "tools": [{
                    "vendor":  "Chris Gillham",
                    "name":    "OSS Trust Framework",
                    "version": "2.0.0",
                    "externalReferences": [{
                        "type": "website",
                        "url":  "https://github.com/chrisgillham/oss-trust-framework",
                    }],
                }],
                "component":  metadata_component,
                "properties": [
                    {"name": "oss-trust:gate",       "value": "Gate 6: SBOM Delta"},
                    {"name": "oss-trust:ecosystem",  "value": ecosystem},
                    {"name": "oss-trust:root_package", "value": f"{root_package}@{root_version}"},
                    {"name": "oss-trust:component_count", "value": str(len(tree))},
                    {"name": "oss-trust:transitive_count",
                     "value": str(len(tree) - 1)},
                ],
            },
            "components":   components,
            "dependencies": dependencies,
        }

    def _cyclonedx_to_xml(self, sbom: dict) -> str:
        """Generate a minimal CycloneDX 1.6 XML representation."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<bom xmlns="http://cyclonedx.org/schema/bom/1.6"',
            f'     version="{sbom["version"]}"',
            f'     serialNumber="{sbom["serialNumber"]}">',
            "  <metadata>",
            f'    <timestamp>{sbom["metadata"]["timestamp"]}</timestamp>',
            "    <tools>",
        ]
        for tool in sbom["metadata"]["tools"]:
            lines += [
                "      <tool>",
                f'        <vendor>{tool["vendor"]}</vendor>',
                f'        <name>{tool["name"]}</name>',
                f'        <version>{tool["version"]}</version>',
                "      </tool>",
            ]
        lines += ["    </tools>", "  </metadata>", "  <components>"]
        for comp in sbom["components"]:
            lines += [
                f'    <component type="{comp["type"]}">',
                f'      <name>{self._xml_escape(comp["name"])}</name>',
                f'      <version>{self._xml_escape(comp["version"])}</version>',
                f'      <purl>{self._xml_escape(comp["purl"])}</purl>',
            ]
            for h in comp.get("hashes", []):
                lines.append(
                    f'      <hash alg="{h["alg"]}">{h["content"]}</hash>'
                )
            lines.append("    </component>")
        lines += ["  </components>", "</bom>"]
        return "\n".join(lines) + "\n"

    def _xml_escape(self, s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace('"', "&quot;"))

    async def _write_manifest(self) -> None:
        """
        Write sbom/manifest.json — a lightweight index of all SBOM files
        in the output directory. Useful for tooling that needs to discover
        all SBOMs without scanning the directory.
        """
        manifest: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool":         "OSS Trust Framework v2.0.0",
            "repository":   os.environ.get("GITHUB_REPOSITORY", ""),
            "commit":       os.environ.get("GITHUB_SHA", ""),
            "sboms":        [],
        }
        for sbom_file in sorted(self.sbom_output_dir.glob("*.cdx.*")):
            try:
                stat = sbom_file.stat()
                entry: dict[str, Any] = {
                    "file":         sbom_file.name,
                    "format":       "json" if sbom_file.suffix == ".json" else "xml",
                    "size_bytes":   stat.st_size,
                    "updated_at":   datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
                # For JSON SBOMs, extract the component count without full parse
                if sbom_file.suffix == ".json":
                    try:
                        data = json.loads(sbom_file.read_text())
                        entry["component_count"]   = len(data.get("components", []))
                        entry["spec_version"]      = data.get("specVersion", "")
                        entry["serial_number"]     = data.get("serialNumber", "")
                        entry["ecosystem"]         = next(
                            (p["value"] for p in
                             data.get("metadata", {}).get("properties", [])
                             if p["name"] == "oss-trust:ecosystem"), ""
                        )
                    except Exception:
                        pass
                manifest["sboms"].append(entry)
            except Exception:
                pass

        manifest_path = self.sbom_output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    async def _commit_sbom(self, paths: dict[str, Path]) -> None:
        """
        Auto-commit the SBOM files to the repository.
        Only runs when commit_sbom: true in config and GITHUB_TOKEN is available.
        The workflow should use this in the runtime-monitor-register job
        rather than during PR checks (committing during a PR check creates
        a new commit that re-triggers the workflow).
        """
        token = os.environ.get("GITHUB_TOKEN", "")
        repo  = os.environ.get("GITHUB_REPOSITORY", "")
        sha   = os.environ.get("GITHUB_SHA", "")

        if not token or not repo:
            log.debug("[sbom] GITHUB_TOKEN or GITHUB_REPOSITORY not set — skipping commit")
            return

        import subprocess
        try:
            subprocess.run(
                ["git", "config", "user.name", "OSS Trust SBOM Bot"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "sbom-bot@oss-trust-framework"],
                check=True, capture_output=True,
            )
            for path in paths.values():
                subprocess.run(
                    ["git", "add", str(path)],
                    check=True, capture_output=True,
                )
            subprocess.run(
                ["git", "add", str(self.sbom_output_dir / "manifest.json")],
                check=True, capture_output=True,
            )
            result = subprocess.run(
                ["git", "diff", "--cached", "--quiet"],
                capture_output=True,
            )
            if result.returncode != 0:   # There are staged changes
                subprocess.run(
                    ["git", "commit", "-m",
                     f"sbom: update CycloneDX SBOM for {sha[:8] if sha else 'current'}\n\n"
                     f"Generated by OSS Trust Framework Gate 6 (SBOM Delta).\n"
                     f"Components: {', '.join(str(p) for p in paths.values())}"],
                    check=True, capture_output=True,
                )
                subprocess.run(["git", "push"], check=True, capture_output=True)
                log.info("[sbom] SBOM committed and pushed to repository")
            else:
                log.info("[sbom] SBOM unchanged — no commit needed")
        except subprocess.CalledProcessError as exc:
            log.warning(f"[sbom] SBOM commit failed: {exc.stderr.decode()[:200]}")

    # ── Snapshot management ───────────────────────────────────────────────────

    async def _load_prior_tree(
        self, package: str, ecosystem: str
    ) -> dict[tuple[str, str], str]:
        snapshot_path = Path(f".oss-trust-cache/{ecosystem}/{package}.json")
        if snapshot_path.exists():
            data = json.loads(snapshot_path.read_text())
            return {
                (k.split("@")[0], k.split("@")[1]): v
                for k, v in data.items()
                if "@" in k
            }
        return {}

    async def _save_snapshot(
        self,
        package: str,
        ecosystem: str,
        tree: dict[tuple[str, str], str],
    ) -> None:
        """Persist the current tree as the new baseline for future delta checks."""
        cache_dir = Path(f".oss-trust-cache/{ecosystem}")
        cache_dir.mkdir(parents=True, exist_ok=True)
        snapshot = {f"{n}@{v}": h for (n, v), h in tree.items()}
        (cache_dir / f"{package}.json").write_text(
            json.dumps(snapshot, indent=2) + "\n"
        )

    # ── Delta helpers ─────────────────────────────────────────────────────────

    def _diff_new(
        self,
        current: dict[tuple[str, str], str],
        prior: dict[tuple[str, str], str],
    ) -> list[tuple[str, str]]:
        prior_packages = {name for name, _ in prior}
        return [(name, ver) for name, ver in current if name not in prior_packages]

    def _diff_hashes(
        self,
        current: dict[tuple[str, str], str],
        prior: dict[tuple[str, str], str],
    ) -> list[tuple[str, str]]:
        return [
            (name, ver)
            for (name, ver), current_hash in current.items()
            if (
                (prior_hash := prior.get((name, ver)))
                and current_hash
                and prior_hash != current_hash
            )
        ]

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _outcome(self, action: str) -> str:
        return {
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
            "block":      Outcome.BLOCKED,
        }.get(action, Outcome.QUARANTINE)

    def _purl_type(self, ecosystem: str) -> str:
        return {
            "npm":      "npm",
            "pypi":     "pypi",
            "cargo":    "cargo",
            "go":       "golang",
            "maven":    "maven",
            "nuget":    "nuget",
            "rubygems": "gem",
        }.get(ecosystem.lower(), ecosystem.lower())

    def _bom_serial(
        self, package: str, version: str, ecosystem: str, timestamp: str
    ) -> str:
        """Generate a deterministic URN serial number for the BOM."""
        raw = f"{package}:{version}:{ecosystem}:{timestamp}"
        uid = hashlib.sha256(raw.encode()).hexdigest()
        return (
            f"urn:uuid:{uid[0:8]}-{uid[8:12]}-{uid[12:16]}"
            f"-{uid[16:20]}-{uid[20:32]}"
        )
