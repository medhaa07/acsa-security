"""API route for repository vulnerability scanning and exact version applicability."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.ingestion.service import IngestionService
from acsa.vulnerability.models import VulnerabilityScanResult
from acsa.vulnerability.service import VulnerabilityService

router = APIRouter(tags=["Vulnerability Scanning"])


class ScanRequest(BaseModel):
    """Request payload to initiate vulnerability scanning for a repository workspace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


@router.post(
    "/scan",
    response_model=VulnerabilityScanResult,
    status_code=status.HTTP_200_OK,
    summary="Scan repository artifacts for exact-version vulnerability applicability via OSV",
)
async def scan_repository(request: ScanRequest) -> VulnerabilityScanResult:
    """Perform artifact ingestion followed by exact-version OSV vulnerability analysis."""
    target_path = Path(request.repository_path)

    # Enforce Phase 0 path security boundary: prevent path traversal and arbitrary filesystem escapes
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

    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(resolved_path)

    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(resolved_path)
    )
    return scan_result
