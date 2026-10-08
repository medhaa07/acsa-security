"""Domain models for software components, dependencies, contradictions, and trust assessments."""

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.evidence.models import EvidenceSource


class Component(BaseModel):
    """An individual software component identified during inventory analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Canonical component ID")
    name: str = Field(description="Normalized component name (e.g. lodash)")
    version: str = Field(description="Exact resolved semantic version (e.g. 4.17.21)")
    purl: str | None = Field(
        default=None,
        description="Standardized Package URL (e.g. pkg:npm/lodash@4.17.21)",
    )
    ecosystem: str = Field(
        default="npm",
        description="Package ecosystem (default: npm)",
    )
    licenses: list[str] = Field(
        default_factory=list,
        description="List of declared or detected licenses (e.g. MIT, Apache-2.0)",
    )
    source_provenance: list[EvidenceSource] = Field(
        default_factory=list,
        description="All sources that observed or confirmed this component",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional component metadata",
    )


class Dependency(BaseModel):
    """A declared or resolved dependency edge between packages."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Target package name")
    version_constraint: str = Field(
        description="Declared version specifier (e.g. ^4.17.20 or ~1.2.3)"
    )
    resolved_version: str | None = Field(
        default=None,
        description="Resolved concrete version if determined from lockfile or install tree",
    )
    dependency_type: str = Field(
        default="direct",
        description="Classification: direct, dev, peer, optional, or transitive",
    )
    parent_component: str | None = Field(
        default=None,
        description="Name or ID of parent component introducing this dependency",
    )
    scope: str | None = Field(
        default="production",
        description="Runtime scope: production or development",
    )


class Contradiction(BaseModel):
    """Novelty 3: Discrepancy observed across disparate inventory sources.

    Captures conflicts between manifest, lockfile, SBOM, source AST, and artifact observations.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique contradiction ID")
    component_name: str = Field(description="Name of component subject to conflicting evidence")
    field_name: str = Field(
        description="Specific property with conflicting values (e.g. version, presence, dependencies)"
    )
    conflicting_sources: list[EvidenceSource] = Field(
        description="List of sources presenting incompatible assertions"
    )
    source_values: dict[str, Any] = Field(
        description="Mapping of source name to the specific value observed in that source"
    )
    description: str = Field(description="Human-readable explanation of the contradiction")
    severity: str = Field(
        default="medium",
        description="Impact severity of contradiction: low, medium, or high",
    )
    resolved: bool = Field(
        default=False,
        description="Whether this contradiction was reconciled by downstream evidence",
    )
    resolution_notes: str | None = Field(
        default=None,
        description="Rationale or evidence justifying how contradiction was reconciled",
    )


class TrustAssessment(BaseModel):
    """Trust score and consistency assessment for component inventory credibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique assessment ID")
    component_name: str = Field(description="Target component evaluated")
    trust_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence/trust score based on cross-source consistency (0.0 to 1.0)",
    )
    evaluated_sources: list[EvidenceSource] = Field(
        description="Sources evaluated during trust assessment"
    )
    has_contradictions: bool = Field(
        default=False,
        description="Indicates whether unresolved contradictions were detected",
    )
    contradiction_ids: list[str] = Field(
        default_factory=list,
        description="Identifiers of contradictions affecting this component",
    )
    confidence_summary: str = Field(
        description="Qualitative summary of component inventory confidence",
    )
