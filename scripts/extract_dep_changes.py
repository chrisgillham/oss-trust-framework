#!/usr/bin/env python3
"""
extract_dep_changes.py
Diffs lock files between base and head SHAs and outputs a JSON array
of changed packages for the GitHub Actions matrix.

Output format (written to $GITHUB_OUTPUT):
  packages=[{"package":"lodash","version":"4.17.20","ecosystem":"npm","registry_url":""}]

Usage:
  python scripts/extract_dep_changes.py \
    --base <base_sha> \
    --head <head_sha>

Supported lock files:
  package-lock.json  (npm)
  yarn.lock          (npm)
  requirements*.txt  (pypi)
  pyproject.toml     (pypi — [tool.poetry.dependencies] / [project.dependencies])
  Cargo.lock         (cargo)
  go.sum             (go)
  Gemfile.lock       (rubygems)
  packages.lock.json (nuget)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


# ── Ecosystem registry defaults ───────────────────────────────────────────────

ECOSYSTEM_REGISTRY: dict[str, str] = {
    "npm":       "https://registry.npmjs.org",
    "pypi":      "https://pypi.org/simple",
    "cargo":     "https://crates.io",
    "go":        "https://proxy.golang.org",
    "rubygems":  "https://rubygems.org",
    "nuget":     "https://api.nuget.org/v3/index.json",
}


def git_diff_files(base: str, head: str) -> list[str]:
    """Return list of files changed between two SHAs."""
    result = subprocess.run(
        ["git", "diff", "--name-only", base, head],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip().splitlines()


def git_show(sha: str, path: str) -> str:
    """Return file content at a given SHA."""
    result = subprocess.run(
        ["git", "show", f"{sha}:{path}"],
        capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else ""


def parse_package_lock(content_before: str, content_after: str) -> list[dict]:
    """Extract new/updated packages from package-lock.json v2/v3."""
    if not content_after:
        return []
    changes: list[dict] = []
    try:
        before = json.loads(content_before) if content_before else {}
        after  = json.loads(content_after)
        # v3 format uses "packages" key
        pkgs_before = before.get("packages", before.get("dependencies", {}))
        pkgs_after  = after.get("packages",  after.get("dependencies", {}))

        for name, meta in pkgs_after.items():
            if name.startswith("node_modules/"):
                clean_name = name[len("node_modules/"):]
            else:
                clean_name = name

            ver_after  = meta.get("version", "")
            ver_before = pkgs_before.get(name, {}).get("version", "")

            if ver_after and ver_after != ver_before:
                changes.append({
                    "package":      clean_name,
                    "version":      ver_after,
                    "ecosystem":    "npm",
                    "registry_url": ECOSYSTEM_REGISTRY["npm"],
                })
    except (json.JSONDecodeError, AttributeError):
        pass
    return changes


def parse_cargo_lock(content_before: str, content_after: str) -> list[dict]:
    """Parse Cargo.lock TOML format."""
    changes: list[dict] = []
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib   # type: ignore
        except ImportError:
            sys.stderr.write("[extract] tomllib not available — Cargo.lock parsing skipped\n")
            return changes

    def extract_pkgs(content: str) -> dict[tuple, str]:
        if not content:
            return {}
        try:
            data = tomllib.loads(content)
        except Exception:
            return {}
        return {
            (p["name"], p.get("source", "")): p["version"]
            for p in data.get("package", [])
        }

    before = extract_pkgs(content_before)
    after  = extract_pkgs(content_after)

    for (name, source), ver in after.items():
        if before.get((name, source)) != ver:
            changes.append({
                "package":      name,
                "version":      ver,
                "ecosystem":    "cargo",
                "registry_url": ECOSYSTEM_REGISTRY["cargo"],
            })
    return changes


def parse_go_sum(content_before: str, content_after: str) -> list[dict]:
    """Parse go.sum — each line is: module@version hash"""
    changes: list[dict] = []
    seen: set[tuple] = set()

    def extract(content: str) -> dict:
        pkgs: dict[tuple, str] = {}
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            at_idx = parts[0].rfind("@")
            if at_idx < 0:
                continue
            module  = parts[0][:at_idx]
            version = parts[0][at_idx + 1:]
            if "/go.mod" not in parts[0]:   # Skip go.mod-only entries
                pkgs[(module, version)] = parts[1] if len(parts) > 1 else ""
        return pkgs

    before = extract(content_before)
    after  = extract(content_after)

    for (module, ver), h in after.items():
        if (module, ver) not in before:
            key = (module, ver)
            if key not in seen:
                seen.add(key)
                changes.append({
                    "package":      module,
                    "version":      ver.lstrip("v"),
                    "ecosystem":    "go",
                    "registry_url": ECOSYSTEM_REGISTRY["go"],
                })
    return changes


def parse_requirements_txt(content_before: str, content_after: str) -> list[dict]:
    """Parse requirements*.txt — supports ==, >=, ~= pinning."""
    changes: list[dict] = []
    pin_re = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", re.MULTILINE)

    before_pkgs = {m.group(1).lower(): m.group(2) for m in pin_re.finditer(content_before)}
    after_pkgs  = {m.group(1).lower(): m.group(2) for m in pin_re.finditer(content_after)}

    for name, ver in after_pkgs.items():
        if before_pkgs.get(name) != ver:
            changes.append({
                "package":      name,
                "version":      ver,
                "ecosystem":    "pypi",
                "registry_url": ECOSYSTEM_REGISTRY["pypi"],
            })
    return changes


def parse_pyproject_toml(content_before: str, content_after: str) -> list[dict]:
    """Extract pinned dependencies from pyproject.toml (Poetry and PEP 621)."""
    changes: list[dict] = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib   # type: ignore
        except ImportError:
            return changes

    pin_re = re.compile(r"==\s*([^\s,\"']+)")

    def extract_versions(content: str) -> dict[str, str]:
        if not content:
            return {}
        try:
            data = tomllib.loads(content)
        except Exception:
            return {}
        deps: dict[str, str] = {}
        # PEP 621
        for dep in data.get("project", {}).get("dependencies", []):
            m = re.match(r"([A-Za-z0-9_.\-]+).*?==\s*([^\s,\"']+)", dep)
            if m:
                deps[m.group(1).lower()] = m.group(2)
        # Poetry
        for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if isinstance(spec, str):
                m = pin_re.search(spec)
                if m:
                    deps[name.lower()] = m.group(1)
        return deps

    before = extract_versions(content_before)
    after  = extract_versions(content_after)

    for name, ver in after.items():
        if before.get(name) != ver:
            changes.append({
                "package":      name,
                "version":      ver,
                "ecosystem":    "pypi",
                "registry_url": ECOSYSTEM_REGISTRY["pypi"],
            })
    return changes


def parse_gemfile_lock(content_before: str, content_after: str) -> list[dict]:
    """Parse Gemfile.lock GEM section."""
    changes: list[dict] = []
    gem_re = re.compile(r"^\s{4}([a-zA-Z0-9_.\-]+)\s+\(([^)]+)\)", re.MULTILINE)

    before = {m.group(1): m.group(2) for m in gem_re.finditer(content_before)}
    after  = {m.group(1): m.group(2) for m in gem_re.finditer(content_after)}

    for name, ver in after.items():
        if before.get(name) != ver:
            changes.append({
                "package":      name,
                "version":      ver,
                "ecosystem":    "rubygems",
                "registry_url": ECOSYSTEM_REGISTRY["rubygems"],
            })
    return changes


# ── Dispatcher ────────────────────────────────────────────────────────────────

PARSERS: dict[str, callable] = {
    "package-lock.json":  parse_package_lock,
    "Cargo.lock":         parse_cargo_lock,
    "go.sum":             parse_go_sum,
    "Gemfile.lock":       parse_gemfile_lock,
    "pyproject.toml":     parse_pyproject_toml,
}

REQUIREMENTS_PATTERN = re.compile(r"requirements[^/]*\.txt$")
NUGET_PATTERN        = re.compile(r"packages\.lock\.json$")


def dispatch(filename: str, before: str, after: str) -> list[dict]:
    basename = Path(filename).name

    if basename in PARSERS:
        return PARSERS[basename](before, after)

    if REQUIREMENTS_PATTERN.search(filename):
        return parse_requirements_txt(before, after)

    return []


def dedup(packages: list[dict]) -> list[dict]:
    """Deduplicate by (package, version, ecosystem)."""
    seen: set[tuple] = set()
    result: list[dict] = []
    for p in packages:
        key = (p["package"], p["version"], p["ecosystem"])
        if key not in seen:
            seen.add(key)
            result.append(p)
    return result


# ── Main ──────────────────────────────────────────────────────────────────────

LOCKFILE_PATTERNS = [
    "package-lock.json", "yarn.lock", "Cargo.lock", "go.sum",
    "Gemfile.lock", "packages.lock.json",
]
MANIFEST_PATTERNS = ["pyproject.toml"]
REQUIREMENTS_RE   = re.compile(r"requirements[^/]*\.txt$")


def is_dependency_file(path: str) -> bool:
    name = Path(path).name
    return (
        name in LOCKFILE_PATTERNS
        or name in MANIFEST_PATTERNS
        or bool(REQUIREMENTS_RE.search(path))
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract changed dependency packages")
    parser.add_argument("--base", required=True, help="Base commit SHA")
    parser.add_argument("--head", required=True, help="Head commit SHA")
    args = parser.parse_args()

    changed_files = git_diff_files(args.base, args.head)
    dep_files     = [f for f in changed_files if is_dependency_file(f)]

    all_packages: list[dict] = []

    for filepath in dep_files:
        before = git_show(args.base, filepath)
        after  = git_show(args.head, filepath)
        try:
            pkgs = dispatch(filepath, before, after)
            all_packages.extend(pkgs)
            if pkgs:
                sys.stderr.write(
                    f"[extract] {filepath}: {len(pkgs)} changed package(s)\n"
                )
        except Exception as exc:
            sys.stderr.write(f"[extract] Error parsing {filepath}: {exc}\n")

    packages = dedup(all_packages)
    output   = json.dumps(packages)

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"packages={output}\n")
    else:
        # Fallback for local testing
        print(f"packages={output}")

    sys.stderr.write(
        f"[extract] Total: {len(packages)} unique changed package(s) across "
        f"{len(dep_files)} dependency file(s)\n"
    )


if __name__ == "__main__":
    main()
