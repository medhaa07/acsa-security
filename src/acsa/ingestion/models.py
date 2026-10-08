"""Domain models for code repositories and point-in-time repository snapshots."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Repository(BaseModel):
    """A target source code repository under security analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique repository ID")
    name: str = Field(description="Repository name (e.g. org/repo or project name)")
    url: str | None = Field(default=None, description="Repository remote VCS URL if available")
    default_branch: str = Field(default="main", description="Primary default branch")
    ecosystem: str = Field(
        default="npm",
        description="Target package ecosystem (primary target is JavaScript/TypeScript npm)",
    )


class RepositorySnapshot(BaseModel):
    """A point-in-time snapshot of a repository's source and build artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique snapshot ID")
    repository_id: str = Field(description="Associated repository ID")
    commit_hash: str = Field(description="Git commit SHA or snapshot digest")
    snapshot_path: str = Field(description="Filesystem location of the unpacked snapshot")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of snapshot creation",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary snapshot metadata (e.g. branch, commit author, build tag)",
    )
