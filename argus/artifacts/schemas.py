"""Artifact Store value objects."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class BlobInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    storage_uri: str = Field(pattern=r"^artifact://sha256/[0-9a-f]{64}$")


class ArtifactPublication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: UUID
    snapshot_id: UUID
    task_id: UUID
    artifact_type: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    capabilities: list[str] = Field(min_length=1)
    producer_plugin_id: str = Field(min_length=1)
    producer_plugin_version: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    artifact_id: UUID | None = None
