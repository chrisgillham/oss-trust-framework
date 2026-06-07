"""
Gate 4 — SBOM Delta + Hash Pin.

Generates a CycloneDX Software Bill of Materials for the package being
validated, diffs it against the previously pinned baseline, and quarantines
if any unexpected transitive dependencies appear.

Catches:
  - XZ Utils style: malicious code injected via a build-time dependency
  - Unexpected new transitive deps added in a patch release
  - Hash changes in a previously pinned transitive dep (re-tagging attack)

Tools required:
  - syft (SBOM generation): https://github.com/anchore/syft
    Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
    Or: brew install syft
  - cyclonedx-python-lib (CycloneDX parsing): pip install cyclonedx-python-lib

Baseline storage:
  - Pinned SBOMs are stored in config/sbom-baselines/<ecosystem>/<package>.json
  - On first run (no baseline exists), the current SBOM is pinned automatically
    and the result is PASS — subsequent runs diff against this baseline
  - Commit config/sbom-baselines/ to version control to track changes over time

Usage:
    result = await diff_sbom("requests", "2.33.0", "PyPI")
    if not result.passed:
        print(result.new_components)   # unexpected new transitive deps
        print(result.changed_hashes)   # hash changes in existing deps
"""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class SBOMDecision(str, Enum):
    PASS = "pass"
    QUARANTINE = "quarantine"
    SKIP = "skip"          # syft not installed
    ERROR = "error"        # syft invocation failed


@dataclass
class SBOMResult:
    decision: SBOMDecision
    package: str
    version: str
    ecosystem: str
    passed: bool
    new_components: list[str] = field(default_factory=list)
    removed_components: list[str] = field(default_factory=list)
    changed_hashes: list[str] = field(default_factory=list)
    total_components: int = 0
    baseline_existed: bool = False
    message: str = ""


# ---------------------------------------------------------------------------
# Baseline storage helpers
# ---------------------------------------------------------------------------

def _baseline_path(package: str, version: str, ecosystem: str) -> Path:
    base = Path(__file__).parent.parent.parent / "config" / "sbom-baselines" / ecosystem
    base.mkdir(parents=True, exist_ok=True)
    safe_name = package.replace("/", "_").replace("@", "").replace(":", "_")
    return base / f"{safe_name}.json"


def _load_baseline(package: str, ecosystem: str) -> Optional[dict]:
    path = _baseline_path(package, "", ecosystem)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None


def _save_baseline(package: str, ecosystem: str, components: dict) -> None:
    path = _baseline_path(package, "", ecosystem)
    with open(path, "w") as f:
        json.dump(components, f, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# syft invocation
# ---------------------------------------------------------------------------

def _syft_available() -> bool:
    try:
        result = subprocess.run(
            ["syft", "version"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_syft(package: str, version: str, ecosystem: str) -> Optional[dict]:
    """
    Invoke syft to generate a CycloneDX JSON SBOM for the package.

    Strategy: install the package into a temp directory, then run syft
    against that directory using the dir: source scheme. This works
    cross-platform (Linux CI and Windows) unlike the bare package specifier
    approach which only works on Linux.

    Returns the parsed SBOM dict, or None on failure.
    """
    import sys

    with tempfile.TemporaryDirectory() as tmpdir:
        install_dir = Path(tmpdir) / "pkg"
        install_dir.mkdir()

        # Step 1: pip install into temp dir
        if ecosystem == "PyPI":
            install_cmd = [
                sys.executable, "-m", "pip", "install",
                f"{package}=={version}",
                "--target", str(install_dir),
                "--quiet", "--no-cache-dir",
            ]
        elif ecosystem == "npm":
            install_cmd = [
                "npm", "install", f"{package}@{version}",
                "--prefix", str(install_dir),
                "--no-save",
            ]
        else:
            # Cargo and others: fall back to bare specifier (Linux only)
            specifier = f"{package}@{version}"
            try:
                result = subprocess.run(
                    ["syft", specifier, "-o", "cyclonedx-json", "--quiet"],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    return None
                return json.loads(result.stdout)
            except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
                return None

        try:
            pip_result = subprocess.run(
                install_cmd,
                capture_output=True, text=True, timeout=120
            )
            if pip_result.returncode != 0:
                logger.debug(
                    "sbom pip install failed for %s==%s: %s",
                    package, version, pip_result.stderr[:200]
                )
                return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        # Step 2: syft scan the install directory
        try:
            result = subprocess.run(
                ["syft", f"dir:{install_dir}", "-o", "cyclonedx-json", "--quiet"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None


# ---------------------------------------------------------------------------
# SBOM parsing and diffing
# ---------------------------------------------------------------------------

def _extract_components(sbom: dict) -> dict[str, str]:
    """
    Extract {name: version_hash} from a CycloneDX SBOM.
    The hash combines name + version + any available content hash.
    """
    components = {}
    for comp in sbom.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "unknown")

        # Prefer a content hash if available (strongest integrity signal)
        hashes = comp.get("hashes", [])
        content_hash = ""
        for h in hashes:
            if h.get("alg", "").upper() in ("SHA-256", "SHA-512"):
                content_hash = h.get("content", "")
                break

        # Fall back to hashing name+version
        identity = f"{name}@{version}:{content_hash}"
        components[name] = hashlib.sha256(identity.encode()).hexdigest()[:16]

    return components


def _diff_components(
    baseline: dict[str, str],
    current: dict[str, str],
) -> tuple[list[str], list[str], list[str]]:
    """
    Returns (new_components, removed_components, changed_hashes).
    new_components = deps in current but not baseline (unexpected additions)
    removed_components = deps in baseline but not current (may indicate removal)
    changed_hashes = deps in both but with different content hashes
    """
    baseline_names = set(baseline.keys())
    current_names = set(current.keys())

    new_components = sorted(current_names - baseline_names)
    removed_components = sorted(baseline_names - current_names)
    changed_hashes = sorted(
        name for name in baseline_names & current_names
        if baseline[name] != current[name]
    )

    return new_components, removed_components, changed_hashes


# ---------------------------------------------------------------------------
# Main gate function
# ---------------------------------------------------------------------------

async def diff_sbom(
    package: str,
    version: str,
    ecosystem: str,
    auto_pin_on_first_run: bool = True,
) -> SBOMResult:
    """
    Gate 4: Generate an SBOM for the package and diff against the pinned baseline.

    Args:
        package:                Package name.
        version:                Package version.
        ecosystem:              "PyPI", "npm", "Cargo", etc.
        auto_pin_on_first_run:  If True and no baseline exists, pin the current
                                SBOM and return PASS. If False, return QUARANTINE
                                when no baseline exists (strict mode).

    Returns:
        SBOMResult with decision and diff details.

    Scope note:
        Gate 4 catches unexpected changes to the transitive dependency graph.
        It does NOT execute the package or detect behavioral threats — that is
        Gate 5's responsibility. These are complementary controls.
    """
    if not _syft_available():
        return SBOMResult(
            decision=SBOMDecision.SKIP,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=True,   # Degrade gracefully — don't block if syft not installed
            message=(
                f"syft not installed — Gate 4 SBOM delta check skipped for {package}@{version}. "
                f"Install syft to enable: https://github.com/anchore/syft"
            ),
        )

    # Run syft in a thread (subprocess is blocking)
    loop = asyncio.get_event_loop()
    sbom = await loop.run_in_executor(None, _run_syft, package, version, ecosystem)

    if sbom is None:
        return SBOMResult(
            decision=SBOMDecision.ERROR,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=False,
            message=f"syft failed to generate SBOM for {package}@{version}.",
        )

    current_components = _extract_components(sbom)
    total = len(current_components)
    baseline = _load_baseline(package, ecosystem)

    # First run — no baseline exists yet
    if baseline is None:
        if auto_pin_on_first_run:
            _save_baseline(package, ecosystem, current_components)
            return SBOMResult(
                decision=SBOMDecision.PASS,
                package=package,
                version=version,
                ecosystem=ecosystem,
                passed=True,
                total_components=total,
                baseline_existed=False,
                message=(
                    f"No baseline existed for {package} ({ecosystem}). "
                    f"Pinned {total} components as new baseline. "
                    f"Commit config/sbom-baselines/ to version control."
                ),
            )
        else:
            return SBOMResult(
                decision=SBOMDecision.QUARANTINE,
                package=package,
                version=version,
                ecosystem=ecosystem,
                passed=False,
                total_components=total,
                baseline_existed=False,
                message=(
                    f"No baseline exists for {package} ({ecosystem}) and "
                    f"auto_pin_on_first_run=False. "
                    f"Run with auto_pin_on_first_run=True to establish baseline."
                ),
            )

    # Diff against baseline
    new_comps, removed_comps, changed_hashes = _diff_components(baseline, current_components)

    findings = []
    if new_comps:
        findings.append(f"Unexpected new transitive deps: {new_comps}")
    if changed_hashes:
        findings.append(f"Hash changes in existing deps: {changed_hashes}")

    if findings:
        return SBOMResult(
            decision=SBOMDecision.QUARANTINE,
            package=package,
            version=version,
            ecosystem=ecosystem,
            passed=False,
            new_components=new_comps,
            removed_components=removed_comps,
            changed_hashes=changed_hashes,
            total_components=total,
            baseline_existed=True,
            message=(
                f"QUARANTINE: {package}@{version} SBOM delta has findings. "
                + " | ".join(findings)
            ),
        )

    # Clean diff — update the baseline to the new version
    _save_baseline(package, ecosystem, current_components)

    return SBOMResult(
        decision=SBOMDecision.PASS,
        package=package,
        version=version,
        ecosystem=ecosystem,
        passed=True,
        removed_components=removed_comps,  # Removals are informational, not blocking
        total_components=total,
        baseline_existed=True,
        message=(
            f"SBOM delta clean for {package}@{version}. "
            f"{total} components verified. "
            + (f"Removed deps (informational): {removed_comps}." if removed_comps else "")
        ),
    )
