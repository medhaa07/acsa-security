"""Command-line interface for ACSA (Artifact-Centric Security Analysis)."""

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from acsa.core.config import get_settings

app = typer.Typer(
    name="acsa",
    help="ACSA — Artifact-Centric Security Analysis: Evidence-driven software supply chain security.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print the ACSA CLI version and exit."""
    if value:
        console.print("[bold blue]ACSA[/bold blue] version [green]0.1.0[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help="Show the version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """ACSA CLI root callback."""


@app.command(name="version")
def show_version() -> None:
    """Display version information for ACSA."""
    console.print("[bold blue]ACSA[/bold blue] (Artifact-Centric Security Analysis) [green]v0.1.0[/green]")


@app.command(name="status")
def status() -> None:
    """Display current system foundation status and configured pipeline phases."""
    settings = get_settings()

    table = Table(title="ACSA Foundation & Pipeline Status")
    table.add_column("Pipeline Phase", style="cyan", no_wrap=True)
    table.add_column("Focus", style="magenta")
    table.add_column("Status", style="green")

    table.add_row("Phase 0", "Engineering Foundation, Domain Models & CLI", "[bold green]Ready[/bold green]")
    table.add_row("Phase 1", "Ingestion (manifest, lockfile, SBOM)", "[yellow]Planned[/yellow]")
    table.add_row("Phase 2", "Inventory Truth + OSV Advisory Matching", "[yellow]Planned[/yellow]")
    table.add_row("Phase 3", "Reachability (AST, Import/Call Graph)", "[yellow]Planned[/yellow]")
    table.add_row("Phase 4", "Context & Multi-Source Evidence Fusion", "[yellow]Planned[/yellow]")

    console.print(table)
    console.print(f"\n[dim]Environment: {settings.env} | Service: {settings.service_name}[/dim]")


@app.command(name="plan")
def pipeline_plan() -> None:
    """Display the end-to-end evidence pipeline roadmap and novelty capabilities."""
    console.print("[bold blue]ACSA Technical Pipeline Flow:[/bold blue]")
    console.print(
        "Repository → Inventory Truth → Vulnerability Intelligence → Applicability → "
        "Reachability → Context → Evidence Fusion → Verdict → Remediation → Verification → Proof\n"
    )

    novelty_table = Table(title="Core Novelty Features")
    novelty_table.add_column("Feature", style="bold cyan")
    novelty_table.add_column("Description", style="white")

    novelty_table.add_row(
        "Proof-Carrying Remediation",
        "Eventual PRs will carry cryptographic before/after evidence showing exposure path closure.",
    )
    novelty_table.add_row(
        "Minimum-Blast-Radius Fix",
        "Calculates smallest verified change that severs all proven exposure paths.",
    )
    novelty_table.add_row(
        "Contradiction-Aware Inventory",
        "Reconciles manifest, lockfile, SBOM, source, and runtime evidence instead of blind trust.",
    )
    novelty_table.add_row(
        "Uncertainty-Guided Dynamic Probe (Supporting)",
        "Identifies runtime evidence needed when static analysis cannot establish a conclusive verdict.",
    )

    console.print(novelty_table)


if __name__ == "__main__":
    app()
