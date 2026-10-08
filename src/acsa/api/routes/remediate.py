"""API route for Minimum-Blast-Radius remediation candidate generation."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.context.service import ContextService
from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.ingestion.service import IngestionService
from acsa.reachability.service import ReachabilityService
from acsa.remediation.models import RemediationReport
from acsa.remediation.service import RemediationService
from acsa.verdict.service import EvidenceFusionService
from acsa.vulnerability.service import VulnerabilityService

router = APIRouter(tags=["Remediation Analysis"])


class RemediateRequest(BaseModel):
    """Request payload to initiate minimum-blast-radius remediation analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


@router.post(
    "/remediate",
    response_model=RemediationReport,
    status_code=status.HTTP_200_OK,
    summary="Generate Minimum-Blast-Radius remediation candidates and simulated patches for repository findings",
)
async def remediate_repository(request: RemediateRequest) -> RemediationReport:
    """Analyze repository findings, determine dependency relations, select minimum safe versions, and simulate patches."""
    target_path = Path(request.repository_path)

    # Path traversal validation
    try:
        resolved_path = validate_safe_path(target_path, target_path)
    except PathTraversalError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Path security violation: {err}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid repository path: {err}",
        ) from err

    if not resolved_path.exists() or not resolved_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository workspace directory not found: '{request.repository_path}'",
        )

    # 1. Ingestion
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(resolved_path)

    # 2. OSV Intelligence
    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(resolved_path)
    )

    # 3. Static Reachability
    reach_service = ReachabilityService()
    findings_reach, reach_ev, graph = reach_service.analyze_findings(
        resolved_path, scan_result.findings
    )

    # 4. Context & Attacker-Controlled Data Flow
    ctx_service = ContextService()
    findings_ctx, ctx_ev = ctx_service.analyze_findings(
        resolved_path, findings_reach, graph=graph
    )

    intermediate_result = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    # 5. Evidence Fusion & Verdicts
    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)

    # 6. Minimum-Blast-Radius Remediation Analysis
    rem_service = RemediationService()
    rem_report = rem_service.remediate_repository(resolved_path, final_result)

    return rem_report
