"""Domain models for remediation candidates, blast radius evaluation, and decisions."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class RemediationCandidate(BaseModel):
    """Novelty 2: Minimum-Blast-Radius Fix candidate.

    Represents an evaluated remediation option (upgrade, patch, or call-site guard)
    measured by its blast-radius score and ability to sever proven exposure paths.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique candidate ID")
    finding_ids: list[str] = Field(
        description="Findings addressed or resolved by this candidate remediation"
    )
    strategy_type: str = Field(
        description="Remediation approach: minimal_patch, minor_upgrade, major_upgrade, call_site_guard, dead_code_elimination"
    )
    target_component: str = Field(description="Component name targeted by remediation")
    current_version: str = Field(description="Current version installed in artifact")
    proposed_version: str | None = Field(
        default=None,
        description="Target upgraded version if remediation involves dependency upgrade",
    )
    blast_radius_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Calculated blast-radius score (0.0 = minimal possible surface change, 1.0 = massive breaking risk)",
    )
    breaking_change_risk: str = Field(
        default="low",
        description="Qualitative risk of breaking backward compatibility: low, medium, high",
    )
    code_changes: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured diffs or manifest modifications proposed by candidate",
    )
    description: str = Field(description="Summary of the remediation candidate")


class RemediationDecision(BaseModel):
    """The authoritative decision selecting the optimal remediation candidate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Decision ID")
    finding_id: str = Field(description="Target finding being remediated")
    selected_candidate: RemediationCandidate | None = Field(
        default=None,
        description="Chosen candidate fix with the lowest verified blast radius that closes exposure",
    )
    rationale: str = Field(
        description="Technical justification for selecting this remediation over alternatives"
    )
    approved: bool = Field(
        default=False,
        description="Whether this remediation decision has been approved for application",
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when decision was formulated",
    )
