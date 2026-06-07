"""
CLI entry point for the OSS Trust Framework.

Usage:
    oss-trust check --package requests --version 2.32.3 --ecosystem PyPI
    oss-trust zeroday request --cve CVE-2024-XXXXX --package requests --version 2.32.4
    oss-trust zeroday approve --request-id abc123def456 --approver-id approver_001
    oss-trust zeroday status --request-id abc123def456
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import click
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


@click.group()
@click.version_option(version="0.5.0", prog_name="oss-trust")
def main() -> None:
    """OSS Trust Framework — supply chain validation pipeline."""


# ---------------------------------------------------------------------------
# oss-trust check
# ---------------------------------------------------------------------------

@main.command()
@click.option("--package", required=True, help="Package name (e.g. requests)")
@click.option("--version", required=True, help="Exact version (e.g. 2.32.3)")
@click.option(
    "--ecosystem",
    required=True,
    type=click.Choice(["PyPI", "npm", "Cargo", "Go", "Maven"], case_sensitive=True),
)
@click.option("--github-repo", default=None, help="owner/repo for Gate 2 provenance + Gate 2.5 CI/CD audit")
@click.option(
    "--github-token",
    default=None,
    envvar="GITHUB_TOKEN",          # auto-reads GITHUB_TOKEN env var if flag not passed
    help="GitHub token for API access (Gates 2.5a-c). Reads GITHUB_TOKEN env var automatically.",
)
@click.option("--config", default="config/pipeline.yaml", show_default=True)
@click.option("--output", type=click.Choice(["table", "json"]), default="table")
def check(
    package: str,
    version: str,
    ecosystem: str,
    github_repo: str | None,
    github_token: str | None,
    config: str,
    output: str,
) -> None:
    """Run the full validation pipeline against a package version."""
    from oss_trust_framework.pipeline.orchestrator import Pipeline
    from oss_trust_framework.config import load_config

    # Fall back to environment variable if not passed explicitly
    resolved_token = github_token or os.environ.get("GITHUB_TOKEN")

    cfg = load_config(config)
    pipeline = Pipeline(config=cfg)

    result = asyncio.run(
        pipeline.run(
            package=package,
            version=version,
            ecosystem=ecosystem,
            github_repo=github_repo,
            github_token=resolved_token,
        )
    )

    if output == "json":
        click.echo(json.dumps({
            "outcome": result.outcome.value,
            "package": result.package,
            "version": result.version,
            "ecosystem": result.ecosystem,
            "lane": result.lane,
            "message": result.message,
            "gates": [
                {"gate": g.gate, "passed": g.passed, "decision": g.decision}
                for g in result.gates
            ],
        }, indent=2))
    else:
        _render_result_table(result)

    sys.exit(0 if result.outcome.value == "approved" else 1)


# ---------------------------------------------------------------------------
# oss-trust zeroday
# ---------------------------------------------------------------------------

@main.group()
def zeroday() -> None:
    """Manage zero-day expedited exception requests."""


@zeroday.command("request")
@click.option("--cve", required=True, help="CVE ID (e.g. CVE-2024-12345)")
@click.option("--package", required=True)
@click.option("--version", required=True)
@click.option("--ecosystem", required=True, type=click.Choice(["PyPI", "npm", "Cargo", "Go", "Maven"]))
@click.option("--requester", required=True, help="Email of the person requesting the exception")
@click.option("--config", default="config/pipeline.yaml", show_default=True)
def zd_request(cve: str, package: str, version: str, ecosystem: str, requester: str, config: str) -> None:
    """Request a zero-day expedited exception for a package update."""
    from oss_trust_framework.zeroday.validator import validate_zero_day_cve
    from oss_trust_framework.config import load_config, build_quorum_manager

    cfg = load_config(config)

    console.print(f"[bold]Validating CVE {cve}...[/bold]")
    cve_result = asyncio.run(
        validate_zero_day_cve(cve_id=cve, package=package, version=version, ecosystem=ecosystem)
    )

    if not cve_result.confirmed:
        console.print(f"[red]CVE validation failed:[/red] {cve_result.message}")
        sys.exit(1)

    console.print(f"[green]CVE confirmed[/green] by {cve_result.sources_confirmed} sources.")

    qm = build_quorum_manager(cfg)
    req = qm.create_request(
        cve_id=cve, package=package, version=version, ecosystem=ecosystem, requester=requester
    )

    console.print(f"\n[bold]Quorum request created[/bold]")
    console.print(f"  Request ID : [cyan]{req.request_id}[/cyan]")
    console.print(f"  Approvals  : 0 / {req.required_approvers} required")
    console.print(f"  Expires    : 6 hours from now")
    console.print(f"\nSend this request ID to your named approvers:")
    for aid, email in req.eligible_approvers.items():
        console.print(
            f"  {email}  ->  oss-trust zeroday approve "
            f"--request-id {req.request_id} --approver-id {aid}"
        )


@zeroday.command("approve")
@click.option("--request-id", required=True)
@click.option("--approver-id", required=True)
@click.option("--mfa-token", required=True, prompt="MFA token", hide_input=True)
@click.option("--config", default="config/pipeline.yaml", show_default=True)
def zd_approve(request_id: str, approver_id: str, mfa_token: str, config: str) -> None:
    """Record an approver's vote on a zero-day exception request."""
    from oss_trust_framework.config import load_config, build_quorum_manager

    cfg = load_config(config)
    qm = build_quorum_manager(cfg)

    result = asyncio.run(qm.record_approval(request_id, approver_id, mfa_token))

    if "error" in result:
        console.print(f"[red]Approval failed:[/red] {result['error']}")
        sys.exit(1)

    console.print(
        f"[green]Approval recorded.[/green] "
        f"{result['approvals_received']}/{result['approvals_required']} approvals received."
    )
    if result["status"] == "approved":
        console.print(
            f"\n[bold green]Quorum reached.[/bold green] "
            f"Run `oss-trust check` to continue the pipeline."
        )


@zeroday.command("status")
@click.option("--request-id", required=True)
@click.option("--config", default="config/pipeline.yaml", show_default=True)
def zd_status(request_id: str, config: str) -> None:
    """Check the status of a zero-day exception request."""
    from oss_trust_framework.config import load_config, build_quorum_manager

    cfg = load_config(config)
    qm = build_quorum_manager(cfg)
    status = qm.get_status(request_id)

    if status is None:
        console.print(f"[red]Request {request_id} not found.[/red]")
        sys.exit(1)

    color = {
        "approved": "green",
        "pending": "yellow",
        "expired": "red",
        "denied": "red",
    }.get(status.value, "white")
    console.print(f"Request [cyan]{request_id}[/cyan]: [{color}]{status.value.upper()}[/{color}]")


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _render_result_table(result) -> None:
    outcome_color = {
        "approved":       "green",
        "blocked":        "red",
        "quarantined":    "yellow",
        "hold":           "yellow",
        "pending_quorum": "cyan",
    }.get(result.outcome.value, "white")

    console.print(
        f"\n[bold]{result.package}@{result.version}[/bold] "
        f"({result.ecosystem}) — lane: {result.lane}"
    )
    console.print(f"Outcome: [{outcome_color}]{result.outcome.value.upper()}[/{outcome_color}]")
    console.print(f"Message: {result.message}\n")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Gate", style="dim")
    table.add_column("Passed")
    table.add_column("Decision")

    for g in result.gates:
        passed_str = "[green]yes[/green]" if g.passed else "[red]no[/red]"
        table.add_row(g.gate, passed_str, g.decision)

    console.print(table)

