"""
oss_trust_framework.check_all
──────────────────────────────
Batch dependency checker — reads requirements.txt + framework_deps.txt
(or any lockfile you point it at) and runs every package through the
OSS Trust Framework pipeline.

Exposed as the ``oss-trust check-all`` CLI command after
``pip install oss-trust-framework``.

Can also be called directly from a cloned repo:
    python check_all.py          # repo-root shim calls this module
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import click
import httpx
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from urllib.parse import urlparse

from oss_trust_framework.age_check.checker import check_release_age, AgeDecision

console = Console()

# ── Registry repo-lookup APIs (for interactive allowlist population) ──────────
REPO_LOOKUP: dict[str, str] = {
    "PyPI":     "https://pypi.org/pypi/{package}/json",
    "npm":      "https://registry.npmjs.org/{package}",
    "Cargo":    "https://crates.io/api/v1/crates/{package}",
    "RubyGems": "https://rubygems.org/api/v1/gems/{package}.json",
    "NuGet":    "https://api.nuget.org/v3/registration5-semver1/{package}/index.json",
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
    # Strip common prefixes that appear in npm/cargo registry metadata
    url = re.sub(r"^git\+|\.git$", "", url.strip())
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    # Exact hostname match only — no substring tricks
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    # Validate owner/repo contain only safe characters
    owner, repo = parts[0], parts[1]
    if not re.match(r"^[A-Za-z0-9_.\-]+$", owner):
        return None
    if not re.match(r"^[A-Za-z0-9_.\-]+$", repo):
        return None
    return f"{owner}/{repo}"

# ── File resolution ───────────────────────────────────────────────────────────

def _resolve_config_dir(config_dir: str | None) -> Path:
    """
    Locate config/trusted_publishers.yaml.

    Search order:
      1. --config-dir flag (explicit)
      2. Current working directory (user ran oss-trust check-all from their project)
      3. The directory containing this module (framework repo itself)
    """
    if config_dir:
        return Path(config_dir)
    cwd_config = Path.cwd() / "config"
    if (cwd_config / "trusted_publishers.yaml").exists():
        return cwd_config
    module_config = Path(__file__).parent.parent / "config"
    if (module_config / "trusted_publishers.yaml").exists():
        return module_config
    # Default to cwd — will be created if allowlist additions are made
    return cwd_config


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse PEP 508 requirements.txt — all packages assumed PyPI."""
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><!\s]+=\s*([\d\.]+[^\s,;]*)", line)
        if match:
            entries.append({
                "ecosystem": "PyPI",
                "package":   match.group(1),
                "version":   match.group(2).strip(),
                "dev":       False,
                "source":    path.name,
            })
    return entries


def parse_framework_deps_txt(path: Path) -> list[dict]:
    """
    Parse framework_deps.txt.
    Format: [dev:]ECOSYSTEM:package==version
    Examples:
        PyPI:httpx==0.27.0
        dev:PyPI:pytest==8.2.2
        npm:express==4.19.2
    """
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        is_dev = False
        if line.lower().startswith("dev:"):
            is_dev = True
            line = line[4:]
        if ":" not in line:
            continue
        ecosystem, rest = line.split(":", 1)
        match = re.match(r"^([A-Za-z0-9_\-\.@/]+)\s*[=~><!\s]+=\s*([\d\.]+[^\s,;]*)", rest)
        if match:
            entries.append({
                "ecosystem": ecosystem.strip(),
                "package":   match.group(1),
                "version":   match.group(2).strip(),
                "dev":       is_dev,
                "source":    path.name,
            })
    return entries


def parse_package_json(path: Path) -> list[dict]:
    """Extract deps from package.json as npm entries."""
    data = json.loads(path.read_text())
    entries = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        is_dev = section != "dependencies"
        for name, spec in data.get(section, {}).items():
            version = re.sub(r"^[^0-9]*", "", str(spec)).split(" ")[0]
            if version:
                entries.append({
                    "ecosystem": "npm", "package": name, "version": version,
                    "dev": is_dev, "source": path.name,
                })
    return entries


def parse_cargo_toml(path: Path) -> list[dict]:
    """Extract deps from Cargo.toml."""
    import tomllib
    data = tomllib.loads(path.read_text())
    entries = []
    for section, is_dev in [("dependencies", False), ("dev-dependencies", True), ("build-dependencies", False)]:
        for name, spec in data.get(section, {}).items():
            version = re.sub(r"^[^0-9]*", "", str(spec.get("version", spec) if isinstance(spec, dict) else spec))
            if version:
                entries.append({
                    "ecosystem": "Cargo", "package": name, "version": version,
                    "dev": is_dev, "source": path.name,
                })
    return entries


def parse_gemfile_lock(path: Path) -> list[dict]:
    """Extract gems from Gemfile.lock."""
    entries = []
    for line in path.read_text().splitlines():
        match = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([\d\.]+)\)", line)
        if match:
            entries.append({
                "ecosystem": "RubyGems", "package": match.group(1),
                "version": match.group(2), "dev": False, "source": path.name,
            })
    return entries


def parse_nuget_config(path: Path) -> list[dict]:
    """Extract packages from NuGet packages.config."""
    import xml.etree.ElementTree as ET
    tree = ET.parse(path)
    return [
        {"ecosystem": "NuGet", "package": p.get("id",""), "version": p.get("version",""),
         "dev": False, "source": path.name}
        for p in tree.getroot().findall("package")
        if p.get("id") and p.get("version")
    ]


# ── Trusted publisher helpers ─────────────────────────────────────────────────

def load_trusted_publishers(config_dir: Path) -> dict:
    tp = config_dir / "trusted_publishers.yaml"
    if tp.exists():
        return yaml.safe_load(tp.read_text()) or {}
    return {}


def save_trusted_publishers(config_dir: Path, data: dict) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "trusted_publishers.yaml").write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
    )


def is_in_allowlist(ecosystem: str, package: str, publishers: dict) -> bool:
    eco_map = publishers.get(ecosystem, {})
    if not isinstance(eco_map, dict):
        return False
    return package in eco_map or package.lower() in {k.lower() for k in eco_map}


def is_attestation_required(ecosystem: str, package: str, publishers: dict) -> bool:
    return package in publishers.get("require_attestation", {}).get(ecosystem, [])


async def fetch_canonical_repo(ecosystem: str, package: str) -> str | None:
    """Try to auto-discover the canonical GitHub repo for a package."""
    try:
        async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "oss-trust-framework/0.5"}) as client:
            if ecosystem == "PyPI":
                resp = await client.get(REPO_LOOKUP["PyPI"].format(package=package))
                if resp.status_code == 200:
                    urls = resp.json().get("info", {}).get("project_urls") or {}
                    for key in ("Source", "Repository", "Homepage", "Source Code"):
                        repo = _extract_github_repo(urls.get(key, ""))
                        if repo:
                            return repo

            elif ecosystem == "npm":
                resp = await client.get(REPO_LOOKUP["npm"].format(package=package))
                if resp.status_code == 200:
                    repo_field = resp.json().get("repository", {})
                    url = repo_field.get("url", "") if isinstance(repo_field, dict) else str(repo_field)
                    repo = _extract_github_repo(url)
                    if repo:
                        return repo

            elif ecosystem == "Cargo":
                resp = await client.get(
                    REPO_LOOKUP["Cargo"].format(package=package),
                    headers={"User-Agent": "oss-trust-framework/0.5"},
                )
                if resp.status_code == 200:
                    repo_url = resp.json().get("crate", {}).get("repository", "")
                    repo = _extract_github_repo(repo_url)
                    if repo:
                        return repo

            elif ecosystem == "RubyGems":
                resp = await client.get(REPO_LOOKUP["RubyGems"].format(package=package))
                if resp.status_code == 200:
                    data = resp.json()
                    for field in ("source_code_uri", "homepage_uri"):
                        repo = _extract_github_repo(data.get(field, "") or "")
                        if repo:
                            return repo
    except Exception:
        pass
    return None


# ── Interactive allowlist prompt ──────────────────────────────────────────────

async def prompt_allowlist(
    ecosystem: str,
    package: str,
    version: str,
    publishers: dict,
    config_dir: Path,
    quit_flag: list[bool],
) -> dict:
    if quit_flag[0]:
        return publishers

    console.print(f"\n[bold yellow]⚠  {ecosystem}/{package}@{version} is not in trusted_publishers.yaml[/bold yellow]")
    console.print(f"   [dim]Looking up canonical repo...[/dim]", end="")
    repo = await fetch_canonical_repo(ecosystem, package)
    if repo:
        console.print(f" found: [cyan]{repo}[/cyan]")
    else:
        console.print(" [dim]not found — enter manually[/dim]")

    console.print(
        "   [1] Add to allowlist only\n"
        "   [2] Add to allowlist + require_attestation\n"
        "   [s] Skip\n"
        "   [q] Quit interactive mode\n"
    )

    while True:
        choice = console.input("   [bold]Choice [1/2/s/q]:[/bold] ").strip().lower()

        if choice == "q":
            quit_flag[0] = True
            return publishers
        if choice == "s":
            return publishers
        if choice in ("1", "2"):
            if not repo:
                repo = console.input(f"   GitHub repo for {package} [owner/repo]: ").strip()
                if not repo or "/" not in repo:
                    console.print("   [red]Invalid. Skipping.[/red]")
                    return publishers

            publishers.setdefault(ecosystem, {})[package] = repo
            console.print(f"   [green]✅ Added {ecosystem}/{package}: {repo}[/green]")

            if choice == "2":
                publishers.setdefault("require_attestation", {}).setdefault(ecosystem, [])
                if package not in publishers["require_attestation"][ecosystem]:
                    publishers["require_attestation"][ecosystem].append(package)
                console.print(f"   [green]✅ require_attestation set for {package}[/green]")

            save_trusted_publishers(config_dir, publishers)
            console.print(f"   [dim]config/trusted_publishers.yaml saved.[/dim]")
            return publishers

        console.print("   [red]Enter 1, 2, s, or q.[/red]")


# ── Rendering ─────────────────────────────────────────────────────────────────

OUTCOME_STYLE = {
    "PASS":    "[green]✅ PASS[/green]",
    "HOLD":    "[yellow]⏳ HOLD[/yellow]",
    "BLOCKED": "[red]🚫 BLOCKED[/red]",
    "ERROR":   "[magenta]⚠  ERROR[/magenta]",
}
DECISION_STYLE = {
    "pass": "[green]pass[/green]", "hold": "[yellow]hold[/yellow]",
    "block": "[red]block[/red]", "zd_eligible": "[blue]zd[/blue]",
    "error": "[magenta]error[/magenta]",
}


def render_results(results: list[dict]) -> None:
    table = Table(
        title="OSS Trust Framework — Dependency Check",
        box=box.ROUNDED, show_lines=True, title_style="bold cyan",
    )
    for col, kw in [
        ("Ecosystem", {"style": "cyan", "no_wrap": True}),
        ("Package", {"style": "white"}),
        ("Version", {"style": "dim"}),
        ("Source", {"style": "dim", "no_wrap": True}),
        ("Allowlist", {"justify": "center"}),
        ("Attest", {"justify": "center"}),
        ("Age (h)", {"justify": "right"}),
        ("Gate 1", {"justify": "center"}),
        ("Outcome", {"justify": "center"}),
    ]:
        table.add_column(col, **kw)

    for r in results:
        age = r.get("age_hours")
        dec = r.get("gate1_decision", "error")
        table.add_row(
            r["ecosystem"], r["package"], r["version"], r.get("source", ""),
            "[green]✓[/green]" if r.get("in_allowlist") else "[yellow]–[/yellow]",
            "[cyan]✓[/cyan]" if r.get("attestation_required") else "[dim]–[/dim]",
            str(age) if age is not None else "—",
            DECISION_STYLE.get(dec, dec),
            OUTCOME_STYLE.get(r.get("outcome", "ERROR"), r.get("outcome", "")),
        )

    console.print(table)
    blocked  = [r for r in results if r.get("outcome") == "BLOCKED"]
    held     = [r for r in results if r.get("outcome") == "HOLD"]
    errors   = [r for r in results if r.get("outcome") == "ERROR"]
    unlisted = [r for r in results if not r.get("in_allowlist")]
    passed   = len(results) - len(blocked) - len(held) - len(errors)

    console.print(
        f"\n[bold]Summary:[/bold] {len(results)} packages — "
        f"[green]{passed} passed[/green]  "
        f"[yellow]{len(held)} on hold[/yellow]  "
        f"[red]{len(blocked)} blocked[/red]  "
        f"[magenta]{len(errors)} errors[/magenta]  "
        f"[yellow]{len(unlisted)} not in allowlist[/yellow]"
    )
    for label, items, color in [
        ("Blocked", blocked, "red"), ("On hold", held, "yellow"),
    ]:
        if items:
            console.print(f"\n[bold {color}]{label}:[/bold {color}]")
            for r in items:
                console.print(f"  • {r['ecosystem']}/{r['package']}@{r['version']} — {r.get('gate1_message','')}")


# ── Core async runner (importable for tests) ──────────────────────────────────

async def run_check_all(
    requirements: Path | None,
    framework_deps: Path | None,
    extra_manifests: list[Path],
    config_dir: Path,
    prod_only: bool,
    interactive: bool,
    output: str,
    fail_on_hold: bool,
) -> tuple[list[dict], int]:
    """
    Core logic — separated from Click so it can be called from tests
    or the repo-root shim without going through the CLI.

    Returns (results, exit_code).
    """
    entries: list[dict] = []

    if requirements and requirements.exists():
        e = parse_requirements_txt(requirements)
        console.print(f"[dim]  {requirements.name} -> {len(e)} packages[/dim]")
        entries.extend(e)
    elif requirements:
        console.print(f"[yellow]  {requirements} not found — skipping[/yellow]")

    if framework_deps and framework_deps.exists():
        e = parse_framework_deps_txt(framework_deps)
        if prod_only:
            before = len(e)
            e = [x for x in e if not x.get("dev")]
            console.print(f"[dim]  {framework_deps.name} -> {len(e)} packages ({before-len(e)} dev skipped)[/dim]")
        else:
            console.print(f"[dim]  {framework_deps.name} -> {len(e)} packages[/dim]")
        entries.extend(e)
    elif framework_deps:
        console.print(f"[yellow]  {framework_deps} not found — skipping[/yellow]")

    for p in extra_manifests:
        if not p.exists():
            console.print(f"[yellow]  {p} not found — skipping[/yellow]")
            continue
        name = p.name.lower()
        if name == "package.json":
            e = parse_package_json(p)
        elif name == "cargo.toml":
            e = parse_cargo_toml(p)
        elif name == "gemfile.lock":
            e = parse_gemfile_lock(p)
        elif name in ("packages.config", "packages.lock.json"):
            e = parse_nuget_config(p)
        else:
            console.print(f"[yellow]  Unknown manifest type: {p.name} — skipping[/yellow]")
            continue
        console.print(f"[dim]  {p.name} -> {len(e)} packages[/dim]")
        entries.extend(e)

    if not entries:
        console.print("[red]No packages found. Create requirements.txt or framework_deps.txt first.[/red]")
        return [], 2

    # Deduplicate
    seen: set[tuple] = set()
    unique: list[dict] = []
    for e in entries:
        key = (e["ecosystem"], e["package"].lower(), e["version"])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    if len(unique) < len(entries):
        console.print(f"[dim]  {len(entries)-len(unique)} duplicates removed -> {len(unique)} unique[/dim]")
    entries = unique

    console.print(f"\n[bold]Running Gate 1 age checks on {len(entries)} packages...[/bold]\n")

    # Concurrent age checks
    async def _check(e: dict) -> dict:
        try:
            result = await check_release_age(
                package=e["package"], version=e["version"], ecosystem=e["ecosystem"]
            )
            return {
                "decision": result.decision.value,
                "age_hours": round(result.age_hours, 1),
                "message": result.message,
            }
        except Exception as exc:
            return {"decision": "error", "age_hours": None, "message": str(exc)}

    age_results = await asyncio.gather(*[_check(e) for e in entries])

    publishers = load_trusted_publishers(config_dir)
    quit_flag = [False]
    results: list[dict] = []

    for entry, age in zip(entries, age_results):
        eco, pkg, ver = entry["ecosystem"], entry["package"], entry["version"]
        dec = age["decision"]
        outcome = {"block": "BLOCKED", "hold": "HOLD", "error": "ERROR"}.get(dec, "PASS")

        results.append({
            "ecosystem": eco, "package": pkg, "version": ver,
            "source": entry.get("source", ""),
            "in_allowlist": is_in_allowlist(eco, pkg, publishers),
            "attestation_required": is_attestation_required(eco, pkg, publishers),
            "age_hours": age["age_hours"],
            "gate1_decision": dec,
            "gate1_message": age["message"],
            "outcome": outcome,
        })

    # Interactive allowlist management
    if interactive:
        unlisted = [r for r in results if not r["in_allowlist"]]
        if unlisted:
            console.print(
                f"\n[bold yellow]{len(unlisted)} package(s) not in trusted_publishers.yaml[/bold yellow]\n"
                "[dim]Add them to enable Gate 2 provenance attestation verification.[/dim]\n"
            )
            for r in unlisted:
                publishers = await prompt_allowlist(
                    r["ecosystem"], r["package"], r["version"],
                    publishers, config_dir, quit_flag,
                )
                r["in_allowlist"] = is_in_allowlist(r["ecosystem"], r["package"], publishers)
                r["attestation_required"] = is_attestation_required(r["ecosystem"], r["package"], publishers)
        else:
            console.print("[green]✅ All packages are in the trusted_publishers allowlist.[/green]")

    console.print()
    if output == "json":
        click.echo(json.dumps(results, indent=2))
    else:
        render_results(results)

    blocked   = any(r["outcome"] == "BLOCKED" for r in results)
    on_hold   = any(r["outcome"] == "HOLD"    for r in results)
    exit_code = 1 if blocked or (fail_on_hold and on_hold) else 0
    return results, exit_code


# ── Click command (registered in oss_trust_framework.cli) ────────────────────

@click.command("check-all")
@click.option(
    "--requirements", "requirements_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Path to requirements.txt (default: ./requirements.txt)",
)
@click.option(
    "--framework-deps", "framework_deps_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Path to framework_deps.txt (default: ./framework_deps.txt)",
)
@click.option(
    "--manifest", "manifests",
    multiple=True,
    type=click.Path(path_type=Path),
    help="Additional lockfiles: package.json, Cargo.toml, Gemfile.lock, packages.config",
)
@click.option(
    "--config-dir",
    default=None,
    help="Directory containing config/trusted_publishers.yaml (auto-detected if omitted)",
)
@click.option(
    "--prod-only",
    is_flag=True,
    help="Skip dev: prefixed entries in framework_deps.txt",
)
@click.option(
    "--no-interactive",
    is_flag=True,
    help="Non-interactive mode — skip allowlist prompts (CI mode)",
)
@click.option(
    "--output",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option(
    "--fail-on-hold",
    is_flag=True,
    help="Exit 1 if any package is in HOLD state (strict CI)",
)
def check_all_command(
    requirements_file: Path | None,
    framework_deps_file: Path | None,
    manifests: tuple[Path, ...],
    config_dir: str | None,
    prod_only: bool,
    no_interactive: bool,
    output: str,
    fail_on_hold: bool,
) -> None:
    """
    Check all packages in requirements.txt + framework_deps.txt.

    Runs Gate 1 (age check) on every dependency and interactively offers
    to populate config/trusted_publishers.yaml for any unlisted package.

    \b
    Examples:
      oss-trust check-all
      oss-trust check-all --prod-only --no-interactive
      oss-trust check-all --manifest package.json --manifest Cargo.toml
      oss-trust check-all --output json --fail-on-hold
    """
    cwd = Path.cwd()
    resolved_config = _resolve_config_dir(config_dir)

    req  = requirements_file  or (cwd / "requirements.txt")
    fdep = framework_deps_file or (cwd / "framework_deps.txt")

    console.print(Panel(
        "[bold cyan]OSS Trust Framework — check-all[/bold cyan]\n"
        f"[dim]config: {resolved_config / 'trusted_publishers.yaml'}[/dim]",
        box=box.ROUNDED,
    ))

    _, exit_code = asyncio.run(run_check_all(
        requirements=req,
        framework_deps=fdep,
        extra_manifests=list(manifests),
        config_dir=resolved_config,
        prod_only=prod_only,
        interactive=not no_interactive,
        output=output,
        fail_on_hold=fail_on_hold,
    ))
    sys.exit(exit_code)
