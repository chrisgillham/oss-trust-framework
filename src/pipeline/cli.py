"""
OSS Trust Framework — CLI Entry Point
Provides `oss-trust check` and `oss-trust zeroday` commands.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


@click.group()
def main() -> None:
    """OSS Trust Framework — supply chain trust validation."""


# ── oss-trust check ───────────────────────────────────────────────────────────

@main.command()
@click.option("--package",    required=True, help="Package name")
@click.option("--version",    required=True, help="Package version")
@click.option("--ecosystem",  required=True, help="Ecosystem (npm, pypi, cargo, go, maven, nuget)")
@click.option("--config",     default="config/pipeline.yaml", help="Pipeline config path")
@click.option("--output",     default="table", type=click.Choice(["table", "json"]),
              help="Output format")
@click.option("--registry-url", default="", help="Source registry URL")
def check(
    package: str,
    version: str,
    ecosystem: str,
    config: str,
    output: str,
    registry_url: str,
) -> None:
    """Run the full nine-gate trust pipeline against a single package."""
    from oss_trust.pipeline import Pipeline

    pipeline = Pipeline(config_path=config)
    result = asyncio.run(
        pipeline.run(package, version, ecosystem, registry_url=registry_url)
    )

    if output == "json":
        click.echo(result.to_json())
    else:
        _print_table(result)

    # Exit code drives GitHub Actions gate
    exit_codes = {
        "approved":    0,
        "hold":        0,   # Informational; doesn't fail the gate alone
        "quarantined": 1,
        "blocked":     1,
        "rejected":    1,
    }
    sys.exit(exit_codes.get(result.outcome, 1))


def _print_table(result) -> None:
    from rich.panel import Panel
    from rich.text import Text

    outcome_color = {
        "approved":    "green",
        "hold":        "yellow",
        "quarantined": "red",
        "blocked":     "bright_red",
        "rejected":    "bright_red",
    }.get(result.outcome, "white")

    console.print()
    console.print(
        Panel(
            f"[bold {outcome_color}]{result.outcome.upper()}[/bold {outcome_color}]  "
            f"[dim]{result.package}@{result.version} ({result.ecosystem})[/dim]",
            title="OSS Trust Framework Result",
            border_style=outcome_color,
        )
    )

    # Gate results table
    table = Table(title="Gate Results", show_header=True, header_style="bold blue")
    table.add_column("Gate",     style="cyan",  no_wrap=True)
    table.add_column("Outcome",  style="bold",  no_wrap=True)
    table.add_column("Duration", style="dim",   no_wrap=True)
    table.add_column("Message")

    outcome_styles = {
        "approved":    "green",
        "hold":        "yellow",
        "quarantined": "red",
        "blocked":     "bright_red",
        "rejected":    "bright_red",
    }

    for gr in result.gate_results:
        style = outcome_styles.get(gr.outcome, "white")
        table.add_row(
            gr.gate,
            f"[{style}]{gr.outcome.upper()}[/{style}]",
            f"{gr.duration_ms:.0f}ms",
            gr.message[:100] + ("..." if len(gr.message) > 100 else ""),
        )

    console.print(table)

    # Trust score
    score_color = "green" if result.trust_score >= 80 else \
                  "yellow" if result.trust_score >= 50 else "red"
    console.print(
        f"\n[bold]Trust Score:[/bold] "
        f"[{score_color}]{result.trust_score}/100 ({result.trust_level})[/{score_color}]"
    )

    if result.trust_deductions:
        console.print("[bold]Deductions:[/bold]")
        for d in result.trust_deductions:
            console.print(f"  [dim]{d}[/dim]")

    console.print()


# ── oss-trust zeroday ─────────────────────────────────────────────────────────

@main.group()
def zeroday() -> None:
    """Zero-day expedited lane commands."""


@zeroday.command("request")
@click.option("--cve",       required=True, help="CVE ID (e.g. CVE-2024-12345)")
@click.option("--package",   required=True, help="Package name")
@click.option("--version",   required=True, help="Package version")
@click.option("--requester", required=True, help="Requester email")
@click.option("--ticket",    default="",    help="Ticket/issue URL (required if require_ticket=true)")
@click.option("--config",    default="config/pipeline.yaml", help="Pipeline config path")
def zeroday_request(
    cve: str,
    package: str,
    version: str,
    requester: str,
    ticket: str,
    config: str,
) -> None:
    """Request a zero-day CVE exception to bypass the age gate."""
    import yaml
    from oss_trust.zeroday import ZeroDayLane

    with open(config) as f:
        cfg = yaml.safe_load(f)

    lane   = ZeroDayLane(cfg.get("zero_day", {}))
    result = asyncio.run(
        lane.request_exception(cve, package, version, requester, ticket)
    )

    click.echo(json.dumps(result, indent=2))
    sys.exit(0 if result["approved"] else 1)


@zeroday.command("validate-token")
@click.option("--token",   required=True)
@click.option("--package", required=True)
@click.option("--config",  default="config/pipeline.yaml")
def zeroday_validate(token: str, package: str, config: str) -> None:
    """Validate that a zero-day exception token is still valid."""
    import yaml
    from oss_trust.zeroday import ZeroDayLane

    with open(config) as f:
        cfg = yaml.safe_load(f)

    lane  = ZeroDayLane(cfg.get("zero_day", {}))
    valid = asyncio.run(lane.validate_token(token, package))
    click.echo(json.dumps({"valid": valid}))
    sys.exit(0 if valid else 1)


# ── oss-trust anomaly ────────────────────────────────────────────────────────

@main.command()
@click.option("--package",           required=True)
@click.option("--version",           required=True)
@click.option("--quorum-id",         required=True)
@click.option("--anomaly-type",      default="unknown")
@click.option("--severity",          default="medium")
@click.option("--days-since-approval", default=0, type=int)
@click.option("--config",            default="config/pipeline.yaml")
def anomaly(
    package: str,
    version: str,
    quorum_id: str,
    anomaly_type: str,
    severity: str,
    days_since_approval: int,
    config: str,
) -> None:
    """Report a runtime anomaly for a monitored package."""
    import yaml
    from oss_trust.runtime import RuntimeTelemetry

    with open(config) as f:
        cfg = yaml.safe_load(f)

    telemetry = RuntimeTelemetry(cfg.get("runtime", {}))
    result = asyncio.run(
        telemetry.handle_anomaly({
            "package":             package,
            "version":             version,
            "quorum_id":           quorum_id,
            "anomaly_type":        anomaly_type,
            "severity":            severity,
            "days_since_approval": days_since_approval,
        })
    )
    click.echo(json.dumps(result, indent=2))
