#!/usr/bin/env python3
"""
check_all.py
────────────
Batch trust check for packages across ALL supported ecosystems.

Supported ecosystems:
  PyPI      — Python Package Index        (pypi.org)
  npm       — Node.js / JavaScript        (registry.npmjs.org)
  Cargo     — Rust                        (crates.io)
  Go        — Go modules                  (proxy.golang.org)
  Maven     — Java/JVM (groupId:artifactId) (search.maven.org)
  NuGet     — .NET                        (api.nuget.org)
  RubyGems  — Ruby                        (rubygems.org)

Usage examples:

  # Check a single npm package
  python scripts/check_all.py --ecosystem npm --package express --version 4.19.2

  # Check a single PyPI package
  python scripts/check_all.py --ecosystem PyPI --package requests --version 2.32.3

  # Check a Maven artifact (groupId:artifactId format)
  python scripts/check_all.py --ecosystem Maven --package "org.apache.commons:commons-lang3" --version 3.14.0

  # Batch check from a manifest file
  python scripts/check_all.py --manifest deps.json

  # Batch check from package.json / pyproject.toml / Cargo.toml
  python scripts/check_all.py --from-package-json package.json
  python scripts/check_all.py --from-pyproject pyproject.toml
  python scripts/check_all.py --from-cargo-toml Cargo.toml
  python scripts/check_all.py --from-gemfile Gemfile.lock
  python scripts/check_all.py --from-nuget packages.config

  # Output as JSON (for CI integration)
  python scripts/check_all.py --ecosystem npm --package axios --version 1.7.2 --output json

  # Populate the trusted_publishers allowlist from an npm package.json
  python scripts/check_all.py --populate-allowlist npm package.json

Manifest file format (deps.json):
  [
    {"ecosystem": "npm",  "package": "express",  "version": "4.19.2"},
    {"ecosystem": "PyPI", "package": "requests", "version": "2.32.3"},
    {"ecosystem": "Cargo","package": "serde",    "version": "1.0.200"}
  ]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table
from rich import box

# Add project root to path for src/ imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.age_check.checker import check_release_age, AgeDecision

console = Console()

VALID_ECOSYSTEMS = ["PyPI", "npm", "Cargo", "Go", "Maven", "NuGet", "RubyGems"]

# Registry lookup URLs for allowlist population
REGISTRY_REPO_APIS: dict[str, str] = {
    "PyPI":     "https://pypi.org/pypi/{package}/json",
    "npm":      "https://registry.npmjs.org/{package}",
    "Cargo":    "https://crates.io/api/v1/crates/{package}",
    "NuGet":    "https://api.nuget.org/v3/registration5-semver1/{package}/index.json",
    "RubyGems": "https://rubygems.org/api/v1/gems/{package}.json",
}


# ── Secure URL parsing ────────────────────────────────────────────────────────

def _extract_github_repo(url: str) -> str | None:
    """
    Safely extract 'owner/repo' from a GitHub URL.

    Uses urllib.parse to validate the hostname exactly — prevents
    CodeQL CWE-20 'Incomplete URL substring sanitization' where a URL
    like https://evil.com/github.com/owner/repo would bypass a naive
    ``"github.com" in url`` substring check.

    Returns 'owner/repo' string or None if the URL is not a valid
    github.com URL with at least owner and repo path components.
    """
    if not url:
        return None
    url = re.sub(r"^git\+|\.git$", "", url.strip())
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9_.\-]+$", owner):
        return None
    if not re.match(r"^[A-Za-z0-9_.\-]+$", repo):
        return None
    return f"{owner}/{repo}"


# ── Manifest parsers ──────────────────────────────────────────────────────────

def parse_package_json(path: str) -> list[dict]:
    """Extract direct deps from package.json as npm entries."""
    data = json.loads(Path(path).read_text())
    entries = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version_spec in data.get(section, {}).items():
            # Strip semver range operators: ^1.2.3 -> 1.2.3, ~2.0 -> 2.0
            version = re.sub(r"^[^0-9]*", "", version_spec).split(" ")[0]
            if version:
                entries.append({"ecosystem": "npm", "package": name, "version": version})
    return entries


def parse_pyproject_toml(path: str) -> list[dict]:
    """Extract dependencies from pyproject.toml (PEP 621 format)."""
    data = tomllib.loads(Path(path).read_text())
    entries = []
    deps = (
        data.get("project", {}).get("dependencies", [])
        + data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys().__iter__().__class__
        # also handle [tool.poetry.dependencies] dict style
    )
    # PEP 621 style: list of "package>=1.0" strings
    raw_deps = data.get("project", {}).get("dependencies", [])
    for dep in raw_deps:
        match = re.match(r"^([A-Za-z0-9_\-\.]+)[>=<!\s]*([\d\.]+)?", dep)
        if match:
            name = match.group(1)
            version = match.group(2) or "latest"
            entries.append({"ecosystem": "PyPI", "package": name, "version": version})
    return entries


def parse_cargo_toml(path: str) -> list[dict]:
    """Extract crate dependencies from Cargo.toml."""
    data = tomllib.loads(Path(path).read_text())
    entries = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                version = re.sub(r"^[^0-9]*", "", spec)
            elif isinstance(spec, dict):
                version = spec.get("version", "latest")
                version = re.sub(r"^[^0-9]*", "", str(version))
            else:
                continue
            if version:
                entries.append({"ecosystem": "Cargo", "package": name, "version": version})
    return entries


def parse_gemfile_lock(path: str) -> list[dict]:
    """Extract gem versions from Gemfile.lock."""
    entries = []
    content = Path(path).read_text()
    in_gems = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_gems = True
            continue
        if in_gems and line.startswith("  ") and not line.startswith("    "):
            # Section header ended
            if not line.strip().startswith("remote:") and line.strip() and not line.strip().startswith("specs"):
                in_gems = False
        if in_gems:
            match = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([\d\.]+)\)", line)
            if match:
                entries.append({
                    "ecosystem": "RubyGems",
                    "package": match.group(1),
                    "version": match.group(2),
                })
    return entries


def parse_nuget_packages_config(path: str) -> list[dict]:
    """Extract packages from NuGet packages.config."""
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    entries = []
    for pkg in tree.getroot().findall("package"):
        name = pkg.get("id", "")
        version = pkg.get("version", "")
        if name and version:
            entries.append({"ecosystem": "NuGet", "package": name, "version": version})
    return entries


# ── Allowlist population ─────────────────────────────────────────────────────

async def fetch_repo_for_package(ecosystem: str, package: str) -> str | None:
    """Try to discover the canonical GitHub repo for a package."""
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "oss-trust-framework/0.5"}) as client:
        try:
            if ecosystem == "PyPI":
                resp = await client.get(REGISTRY_REPO_APIS["PyPI"].format(package=package))
                if resp.status_code == 200:
                    urls = resp.json().get("info", {}).get("project_urls") or {}
                    for key in ("Source", "Repository", "Homepage", "Source Code"):
                        repo = _extract_github_repo(urls.get(key, ""))
                        if repo:
                            return repo

            elif ecosystem == "npm":
                resp = await client.get(REGISTRY_REPO_APIS["npm"].format(package=package))
                if resp.status_code == 200:
                    repo_field = resp.json().get("repository", {})
                    url = repo_field.get("url", "") if isinstance(repo_field, dict) else str(repo_field)
                    repo = _extract_github_repo(url)
                    if repo:
                        return repo

            elif ecosystem == "Cargo":
                resp = await client.get(REGISTRY_REPO_APIS["Cargo"].format(package=package))
                if resp.status_code == 200:
                    repo_url = resp.json().get("crate", {}).get("repository", "")
                    repo = _extract_github_repo(repo_url)
                    if repo:
                        return repo

            elif ecosystem == "RubyGems":
                resp = await client.get(REGISTRY_REPO_APIS["RubyGems"].format(package=package))
                if resp.status_code == 200:
                    data = resp.json()
                    for field in ("source_code_uri", "homepage_uri", "bug_tracker_uri"):
                        repo = _extract_github_repo(data.get(field, "") or "")
                        if repo:
                            return repo

            elif ecosystem == "NuGet":
                resp = await client.get(
                    REGISTRY_REPO_APIS["NuGet"].format(package=package.lower())
                )
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [{}])[-1].get("items", [{}])
                    entry = items[-1].get("catalogEntry", {}) if items else {}
                    repo = _extract_github_repo(entry.get("projectUrl", "") or "")
                    if repo:
                        return repo

        except Exception as exc:
            console.print(f"[yellow]  warn: repo lookup failed for {package}: {exc}[/yellow]")

    return None


async def populate_allowlist(ecosystem: str, manifest_path: str) -> None:
    """
    Look up canonical GitHub repos for all packages in a manifest and emit
    YAML entries suitable for pasting into config/trusted_publishers.yaml.
    """
    if ecosystem == "npm":
        entries = parse_package_json(manifest_path)
    elif ecosystem == "PyPI":
        entries = parse_pyproject_toml(manifest_path)
    elif ecosystem == "Cargo":
        entries = parse_cargo_toml(manifest_path)
    elif ecosystem == "RubyGems":
        entries = parse_gemfile_lock(manifest_path)
    elif ecosystem == "NuGet":
        entries = parse_nuget_packages_config(manifest_path)
    else:
        console.print(f"[red]--populate-allowlist not yet supported for {ecosystem}[/red]")
        return

    console.print(f"\n[bold cyan]# {ecosystem} trusted_publishers entries[/bold cyan]")
    console.print(f"[bold cyan]# Generated from {manifest_path}[/bold cyan]\n")

    tasks = {e["package"]: fetch_repo_for_package(ecosystem, e["package"]) for e in entries}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    resolved = dict(zip(tasks.keys(), results))

    found, not_found = [], []
    for pkg, repo in resolved.items():
        if isinstance(repo, str):
            found.append((pkg, repo))
        else:
            not_found.append(pkg)

    for pkg, repo in sorted(found):
        console.print(f'  "{pkg}": "{repo}"')

    if not_found:
        console.print(f"\n[yellow]# Could not auto-resolve repos for:[/yellow]")
        for pkg in sorted(not_found):
            console.print(f'  # "{pkg}": "FIXME/repo"')

    console.print(f"\n# {len(found)}/{len(entries)} repos auto-resolved. Verify before committing.")


# ── Single package check ──────────────────────────────────────────────────────

async def check_one(ecosystem: str, package: str, version: str) -> dict:
    """Run age check (and future gate hooks) for one package."""
    result: dict[str, Any] = {
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "gates": {},
        "outcome": "UNKNOWN",
    }

    # Gate 1 — Age check
    try:
        age_result = await check_release_age(package=package, version=version, ecosystem=ecosystem)
        result["gates"]["age"] = {
            "decision": age_result.decision.value,
            "age_hours": round(age_result.age_hours, 1),
            "message": age_result.message,
        }
        if age_result.decision == AgeDecision.BLOCK:
            result["outcome"] = "BLOCKED"
        elif age_result.decision == AgeDecision.HOLD:
            result["outcome"] = "HOLD"
        else:
            result["outcome"] = "PASS"
    except Exception as exc:
        result["gates"]["age"] = {"decision": "ERROR", "message": str(exc)}
        result["outcome"] = "ERROR"

    return result


# ── Rendering ─────────────────────────────────────────────────────────────────

def render_table(results: list[dict]) -> None:
    table = Table(
        title="OSS Trust Framework — Multi-Ecosystem Check",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Ecosystem", style="cyan", no_wrap=True)
    table.add_column("Package", style="white")
    table.add_column("Version", style="dim")
    table.add_column("Age (h)", justify="right")
    table.add_column("Age Gate", justify="center")
    table.add_column("Outcome", justify="center")
    table.add_column("Message", style="dim", max_width=55)

    outcome_styles = {
        "PASS":    "[green]✅ PASS[/green]",
        "HOLD":    "[yellow]⏳ HOLD[/yellow]",
        "BLOCKED": "[red]🚫 BLOCKED[/red]",
        "ERROR":   "[magenta]⚠️  ERROR[/magenta]",
        "UNKNOWN": "[dim]?[/dim]",
    }
    decision_styles = {
        "pass":    "[green]pass[/green]",
        "hold":    "[yellow]hold[/yellow]",
        "block":   "[red]block[/red]",
        "zd_eligible": "[blue]zd[/blue]",
        "ERROR":   "[magenta]error[/magenta]",
    }

    for r in results:
        age_gate = r["gates"].get("age", {})
        decision = age_gate.get("decision", "ERROR")
        age_hours = str(age_gate.get("age_hours", "—"))
        message = age_gate.get("message", "")[:120]

        table.add_row(
            r["ecosystem"],
            r["package"],
            r["version"],
            age_hours,
            decision_styles.get(decision, decision),
            outcome_styles.get(r["outcome"], r["outcome"]),
            message,
        )

    console.print(table)

    blocked = [r for r in results if r["outcome"] == "BLOCKED"]
    held    = [r for r in results if r["outcome"] == "HOLD"]
    errors  = [r for r in results if r["outcome"] == "ERROR"]

    console.print(
        f"\n[bold]Summary:[/bold] {len(results)} packages checked — "
        f"[green]{len(results) - len(blocked) - len(held) - len(errors)} passed[/green], "
        f"[yellow]{len(held)} on hold[/yellow], "
        f"[red]{len(blocked)} blocked[/red], "
        f"[magenta]{len(errors)} errors[/magenta]"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="OSS Trust Framework — multi-ecosystem package checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Single package mode
    p.add_argument("--ecosystem", choices=VALID_ECOSYSTEMS,
                   help="Package ecosystem (single-package mode)")
    p.add_argument("--package", help="Package name")
    p.add_argument("--version", help="Exact version")
    p.add_argument("--github-repo", default=None,
                   help="owner/repo for OpenSSF Scorecard (optional)")

    # Manifest / lockfile modes
    p.add_argument("--manifest", metavar="FILE",
                   help="JSON manifest file [{ecosystem, package, version}, ...]")
    p.add_argument("--from-package-json", metavar="package.json",
                   help="Check all deps from an npm package.json")
    p.add_argument("--from-pyproject", metavar="pyproject.toml",
                   help="Check all deps from a pyproject.toml")
    p.add_argument("--from-cargo-toml", metavar="Cargo.toml",
                   help="Check all deps from a Cargo.toml")
    p.add_argument("--from-gemfile", metavar="Gemfile.lock",
                   help="Check all gems from Gemfile.lock")
    p.add_argument("--from-nuget", metavar="packages.config",
                   help="Check all packages from NuGet packages.config")

    # Allowlist population
    p.add_argument("--populate-allowlist", nargs=2, metavar=("ECOSYSTEM", "FILE"),
                   help="Auto-discover GitHub repos and emit trusted_publishers YAML")

    p.add_argument("--output", choices=["table", "json"], default="table")
    p.add_argument("--fail-on-hold", action="store_true",
                   help="Exit non-zero if any package is in HOLD state (CI strict mode)")
    return p


async def async_main(args: argparse.Namespace) -> int:
    # --- Allowlist population mode ---
    if args.populate_allowlist:
        ecosystem, manifest = args.populate_allowlist
        await populate_allowlist(ecosystem, manifest)
        return 0

    # --- Build package list ---
    entries: list[dict] = []

    if args.manifest:
        entries = json.loads(Path(args.manifest).read_text())

    if args.from_package_json:
        entries.extend(parse_package_json(args.from_package_json))

    if args.from_pyproject:
        entries.extend(parse_pyproject_toml(args.from_pyproject))

    if args.from_cargo_toml:
        entries.extend(parse_cargo_toml(args.from_cargo_toml))

    if args.from_gemfile:
        entries.extend(parse_gemfile_lock(args.from_gemfile))

    if args.from_nuget:
        entries.extend(parse_nuget_packages_config(args.from_nuget))

    # Single-package mode
    if args.ecosystem and args.package and args.version:
        entries.append({
            "ecosystem": args.ecosystem,
            "package": args.package,
            "version": args.version,
        })

    if not entries:
        console.print("[red]Error: no packages to check. Provide --package/--version/--ecosystem "
                      "or a manifest/lockfile option.[/red]")
        return 2

    # --- Run checks concurrently ---
    console.print(f"[bold]Checking {len(entries)} package(s) across ecosystems...[/bold]\n")

    tasks = [
        check_one(e["ecosystem"], e["package"], e["version"])
        for e in entries
    ]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    # --- Output ---
    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        render_table(results)

    # --- Exit code ---
    has_blocked = any(r["outcome"] == "BLOCKED" for r in results)
    has_held    = any(r["outcome"] == "HOLD"    for r in results)

    if has_blocked:
        return 1
    if args.fail_on_hold and has_held:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
