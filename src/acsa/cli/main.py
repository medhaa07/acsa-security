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
    table.add_row("Phase 1", "Ingestion (manifest, lockfile, SBOM)", "[bold green]Ready[/bold green]")
    table.add_row("Phase 2", "Inventory Truth + OSV Advisory Matching", "[bold green]Ready[/bold green]")
    table.add_row("Phase 3", "Reachability (AST, Import/Call Graph)", "[bold green]Ready[/bold green]")
    table.add_row("Phase 4", "Context & Multi-Source Evidence Fusion", "[yellow]Planned[/yellow]")

    console.print(table)
    console.print(f"\n[dim]Environment: {settings.env} | Service: {settings.service_name}[/dim]")


@app.command(name="ingest")
def ingest(
    repository_path: Annotated[
        str,
        typer.Argument(help="Path to the repository workspace to ingest."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output machine-readable JSON results."),
    ] = False,
) -> None:
    """Ingest dependency manifests, lockfiles, and SBOMs from a repository workspace."""
    from pathlib import Path

    from acsa.ingestion.service import IngestionService

    service = IngestionService()
    result = service.ingest_repository(Path(repository_path))

    if json_output:
        console.print_json(result.model_dump_json(indent=2))
        return

    console.print(f"\n[bold blue]ACSA Artifact Ingestion Report[/bold blue] for: [cyan]{result.repository_path}[/cyan]\n")

    # Artifacts table
    art_table = Table(title="Discovered Artifacts")
    art_table.add_column("Relative Path", style="cyan")
    art_table.add_column("Format", style="magenta")
    art_table.add_column("Size (bytes)", justify="right")
    art_table.add_column("SHA-256", style="dim")

    for art in result.discovered_artifacts:
        art_table.add_row(
            art.relative_path,
            art.artifact_type.value,
            str(art.size_bytes),
            art.sha256[:16] + "..." if art.sha256 else "-",
        )
    if not result.discovered_artifacts:
        art_table.add_row("[dim]None found[/dim]", "-", "-", "-")
    console.print(art_table)

    # Ingestion metrics
    m = result.metrics
    console.print(
        f"\n[bold green][OK] Ingestion Summary:[/bold green] "
        f"[bold]{m.get('artifacts_parsed', 0)}[/bold] parsed, "
        f"[bold]{m.get('total_observations', 0)}[/bold] total observations, "
        f"[bold]{m.get('unique_components', 0)}[/bold] unique components, "
        f"[bold]{len(result.inventory.dependencies)}[/bold] dependency edges."
    )

    # Discrepancy highlights (Novelty 3 foundation)
    disc_count = m.get("components_with_version_discrepancy", 0)
    if disc_count > 0:
        disc_table = Table(title=f"Multi-Source Observations with Version Discrepancies ({disc_count})")
        disc_table.add_column("Component", style="yellow")
        disc_table.add_column("Observed Versions / Sources", style="white")

        for name in result.inventory.unique_component_names:
            if result.inventory.has_version_discrepancy(name):
                obs_list = result.inventory.get_observations_for_component(name)
                details = ", ".join(
                    f"{o.version or o.version_constraint} ({o.source_type.value})"
                    for o in obs_list
                )
                disc_table.add_row(name, details)
        console.print(disc_table)

    # Warnings / Errors
    if result.warnings:
        console.print(f"\n[yellow]Warnings ({len(result.warnings)}):[/yellow]")
        for w in result.warnings:
            console.print(f"  [yellow][!][/yellow] [{w.artifact_path}] {w.message}")

    if result.errors:
        console.print(f"\n[red]Errors ({len(result.errors)}):[/red]")
        for e in result.errors:
            console.print(f"  [red][ERROR][/red] [{e.artifact_path}] {e.message}")

    console.print("\n[dim]Phase 1 Ingestion complete. No external vulnerability queries executed.[/dim]")


@app.command(name="scan")
def scan(
    repository_path: Annotated[
        str,
        typer.Argument(help="Path to the repository workspace to scan."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output machine-readable JSON scan results."),
    ] = False,
) -> None:
    """Scan repository artifacts, evaluate exact-version vulnerability applicability via OSV, and compute static reachability."""
    from pathlib import Path

    from acsa.ingestion.service import IngestionService
    from acsa.reachability.models import ReachabilityState
    from acsa.reachability.service import ReachabilityService
    from acsa.vulnerability.models import ApplicabilityStatus
    from acsa.vulnerability.service import VulnerabilityService

    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(Path(repository_path))

    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(repository_path)
    )

    reach_service = ReachabilityService()
    scan_result = reach_service.enrich_scan_result(scan_result, repository_path=Path(repository_path))

    if json_output:
        console.print_json(scan_result.model_dump_json(indent=2))
        return

    console.print(
        f"\n[bold blue]ACSA Security Analysis[/bold blue] for: [cyan]{scan_result.repository_path}[/cyan]\n"
    )

    # Inventory section
    inv_table = Table(title="Inventory Truth Summary")
    inv_table.add_column("Metric", style="cyan")
    inv_table.add_column("Count", justify="right", style="bold white")
    inv_table.add_row("Artifacts Discovered", str(len(ingest_result.discovered_artifacts)))
    inv_table.add_row("Total Observations", str(len(scan_result.inventory.observations)))
    inv_table.add_row("Unique Components", str(len(scan_result.inventory.unique_component_names)))
    inv_table.add_row("Exact Versions Queried", str(scan_result.exact_versions_queried))
    console.print(inv_table)

    # Intelligence summary
    intel_table = Table(title="Vulnerability Intelligence Summary (OSV)")
    intel_table.add_column("Metric", style="magenta")
    unique_affected_versions = {
        (f.component.name, f.component.version)
        for f in scan_result.findings
        if f.applicability_status == ApplicabilityStatus.AFFECTED
    }
    intel_table.add_row("OSV Queries Sent", str(scan_result.queries_executed))
    intel_table.add_row("Advisories Evaluated", str(scan_result.advisories_count))
    intel_table.add_row(
        "Affected Advisory Findings",
        str(scan_result.affected_count),
        style="bold red" if scan_result.affected_count else "green",
    )
    intel_table.add_row(
        "Affected Exact Versions",
        str(len(unique_affected_versions)),
        style="bold red" if unique_affected_versions else "green",
    )
    intel_table.add_row("Not Affected", str(scan_result.not_affected_count))
    intel_table.add_row("Unknown / Ambiguous", str(scan_result.unknown_count))
    console.print(intel_table)

    if not scan_result.osv_available:
        console.print("\n[bold red][ERROR] OSV intelligence service was unavailable during scan.[/bold red]")
        for err in scan_result.errors:
            console.print(f"  [red]- {err}[/red]")
        return

    # Reachability summary
    reachable_count = sum(
        1 for f in scan_result.findings if f.reachability and f.reachability.status == ReachabilityState.REACHABLE
    )
    not_reachable_count = sum(
        1 for f in scan_result.findings if f.reachability and f.reachability.status == ReachabilityState.NOT_REACHABLE
    )
    reach_unknown_count = sum(
        1 for f in scan_result.findings if f.reachability and f.reachability.status == ReachabilityState.UNKNOWN
    )

    reach_table = Table(title="Reachability Analysis Summary (AST & Call Graph)")
    reach_table.add_column("Reachability State", style="cyan")
    reach_table.add_column("Findings Count", justify="right", style="bold")
    reach_table.add_row("REACHABLE", str(reachable_count), style="bold red" if reachable_count else "dim")
    reach_table.add_row("NOT_REACHABLE", str(not_reachable_count), style="bold green" if not_reachable_count else "dim")
    reach_table.add_row("UNKNOWN (Preserved Uncertainty)", str(reach_unknown_count), style="bold yellow" if reach_unknown_count else "dim")
    console.print(reach_table)

    # Detailed Findings with Reachability
    if scan_result.findings:
        console.print(f"\n[bold white]Detailed Findings & Exposure Paths ({len(scan_result.findings)}):[/bold white]")
        for f in scan_result.findings:
            if f.applicability_status == ApplicabilityStatus.AFFECTED:
                status_str = "[bold red]AFFECTED[/bold red]"
            elif f.applicability_status == ApplicabilityStatus.NOT_AFFECTED:
                status_str = "[bold green]NOT_AFFECTED[/bold green]"
            else:
                status_str = "[bold yellow]UNKNOWN[/bold yellow]"

            console.print("\n" + "-" * 60)
            console.print(f"[bold yellow]{f.vulnerability.id}[/bold yellow] ({f.vulnerability.severity or 'SEVERITY N/A'})")
            console.print(f"Package: [cyan]{f.component.name}@{f.component.version or '-'}[/cyan]")
            console.print(f"Status: {status_str}")

            if f.reachability:
                console.print("\nReachability:")
                if f.reachability.status == ReachabilityState.REACHABLE:
                    console.print("  Status: [bold red]REACHABLE[/bold red]")
                    if f.reachability.entry_point:
                        console.print(f"  Entry point: [cyan]{f.reachability.entry_point}[/cyan]")
                    if f.reachability.target_symbol:
                        console.print(f"  Vulnerable symbol: [bold magenta]{f.reachability.target_symbol}[/bold magenta]")
                    if f.reachability.evidence_path:
                        console.print("  Evidence path:")
                        for idx, step in enumerate(f.reachability.evidence_path):
                            if idx == 0:
                                console.print(f"    {step}")
                            else:
                                console.print(f"    [dim]->[/dim] {step}")
                elif f.reachability.status == ReachabilityState.NOT_REACHABLE:
                    console.print("  Status: [bold green]NOT_REACHABLE[/bold green]")
                else:
                    console.print("  Status: [bold yellow]UNKNOWN[/bold yellow]")
                    if f.reachability.uncertainty_reason:
                        console.print(f"  Reason: [yellow]{f.reachability.uncertainty_reason}[/yellow]")
        console.print("-" * 60)
    else:
        console.print("\n[bold green][OK] No vulnerabilities reported for exact installed package versions.[/bold green]")

    console.print(
        "\n[dim]Phase 3 Reachability Analysis complete. Attacker-controlled data flow will be evaluated in Phase 4.[/dim]"
    )


@app.command(name="plan")
def pipeline_plan() -> None:
    """Display the end-to-end evidence pipeline roadmap and novelty capabilities."""
    console.print("[bold blue]ACSA Technical Pipeline Flow:[/bold blue]")
    console.print(
        "Repository -> Inventory Truth -> Vulnerability Intelligence -> Applicability -> "
        "Reachability -> Context -> Evidence Fusion -> Verdict -> Remediation -> Verification -> Proof\n"
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
