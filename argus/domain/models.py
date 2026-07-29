"""Pydantic DTOs for the M1 V2 domain skeleton."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from argus.domain.enums import (
    EventLevel,
    AttemptStatus,
    FindingStatus,
    PluginKind,
    ReviewStatus,
    ReviewSubjectType,
    ScanEngine,
    ScanStatus,
    Severity,
    StaticConfidence,
    TaskStatus,
    VcsType,
)

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
NonEmptyStr = Annotated[str, Field(min_length=1)]
JsonObject = dict[str, JsonValue]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


class DomainModel(BaseModel):
    """Strict immutable DTO base shared by all V2 domain objects."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class Project(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    name: NonEmptyStr
    repository_path: NonEmptyStr
    default_config: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    archived_at: datetime | None = None

    _normalize_datetimes = field_validator("created_at", "updated_at", "archived_at", mode="after")(_as_utc)


class Scan(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    snapshot_id: UUID
    plan_id: UUID | None = None
    status: ScanStatus = ScanStatus.CREATED
    config: JsonObject = Field(default_factory=dict)
    config_hash: Sha256
    engine: ScanEngine = ScanEngine.LEGACY
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    version: int = Field(default=1, ge=1)

    _normalize_datetimes = field_validator("created_at", "started_at", "finished_at", mode="after")(_as_utc)


class SourceSnapshot(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    repository_path: NonEmptyStr
    vcs_type: VcsType
    commit_sha: str | None = None
    tree_hash: Sha256
    dirty: bool
    materialized_path: NonEmptyStr
    manifest_artifact_id: UUID
    created_at: datetime = Field(default_factory=utc_now)

    _normalize_created_at = field_validator("created_at", mode="after")(_as_utc)


class Task(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    plan_id: UUID | None = None
    plugin_id: NonEmptyStr
    plugin_version: NonEmptyStr
    kind: NonEmptyStr
    depends_on: list[UUID] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    optional_capabilities: list[str] = Field(default_factory=list)
    expected_capabilities: list[str] = Field(default_factory=list)
    config_hash: Sha256
    cache_key: Sha256
    continue_on_failure: bool = False
    max_attempts: int = Field(default=1, ge=1, le=100)
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    version: int = Field(default=1, ge=1)

    _normalize_datetimes = field_validator("created_at", "started_at", "finished_at", mode="after")(_as_utc)


class PlannedTask(DomainModel):
    id: UUID
    plugin_id: NonEmptyStr
    plugin_version: NonEmptyStr
    kind: PluginKind
    depends_on: list[UUID] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    optional_capabilities: list[str] = Field(default_factory=list)
    expected_capabilities: list[str] = Field(default_factory=list)
    config_hash: Sha256
    cache_key: Sha256
    continue_on_failure: bool = False
    max_attempts: int = Field(default=1, ge=1, le=100)


class TaskPlan(DomainModel):
    id: UUID
    scan_id: UUID
    tasks: list[PlannedTask]
    plan_hash: Sha256
    created_at: datetime = Field(default_factory=utc_now)

    _normalize_created_at = field_validator("created_at", mode="after")(_as_utc)


class TaskAttempt(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    task_id: UUID
    attempt_number: int = Field(ge=1)
    status: AttemptStatus = AttemptStatus.RUNNING
    plugin_id: NonEmptyStr
    plugin_version: NonEmptyStr
    input_artifact_ids: list[UUID] = Field(default_factory=list)
    input_hashes: dict[str, Sha256] = Field(default_factory=dict)
    config_hash: Sha256
    worker_pid: int = Field(ge=1)
    started_at: datetime = Field(default_factory=utc_now)
    heartbeat_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None

    _normalize_datetimes = field_validator(
        "started_at",
        "heartbeat_at",
        "finished_at",
        mode="after",
    )(_as_utc)


class ReviewRequest(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    task_id: UUID
    subject_type: ReviewSubjectType
    subject_ids: list[UUID] = Field(min_length=1)
    subject_hash: Sha256
    status: ReviewStatus = ReviewStatus.OPEN
    reviewer: str | None = None
    reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    decided_at: datetime | None = None

    _normalize_datetimes = field_validator("created_at", "decided_at", mode="after")(_as_utc)


class Artifact(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    snapshot_id: UUID
    task_id: UUID
    artifact_type: NonEmptyStr
    schema_version: NonEmptyStr
    capabilities: list[str] = Field(min_length=1)
    producer_plugin_id: NonEmptyStr
    producer_plugin_version: NonEmptyStr
    media_type: NonEmptyStr
    content_hash: Sha256
    size_bytes: int = Field(ge=0)
    storage_uri: NonEmptyStr
    metadata: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    _normalize_created_at = field_validator("created_at", mode="after")(_as_utc)


class CodeLocation(DomainModel):
    file: NonEmptyStr
    line: int = Field(ge=1)
    node_id: str | None = None


class StaticFindingV2(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    fingerprint: Sha256
    scan_id: UUID
    snapshot_id: UUID
    rule_id: NonEmptyStr
    rule_version: NonEmptyStr
    title: NonEmptyStr
    weakness_id: NonEmptyStr
    vuln_class: NonEmptyStr
    severity: Severity
    static_confidence: StaticConfidence
    status: FindingStatus
    locations: list[CodeLocation] = Field(min_length=1)
    source_node_ids: list[str] = Field(default_factory=list)
    sink_node_ids: list[str] = Field(default_factory=list)
    root_cause_key: Sha256 | None = None
    graph_slice_artifact_id: UUID | None = None
    evidence_artifact_ids: list[UUID] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    rationale: str
    remediation: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    _normalize_datetimes = field_validator("created_at", "updated_at", mode="after")(_as_utc)


class Event(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID | None = None
    scan_id: UUID | None = None
    task_id: UUID | None = None
    finding_id: UUID | None = None
    event_type: NonEmptyStr
    level: EventLevel = EventLevel.INFO
    payload: JsonObject = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    sequence: int | None = Field(default=None, ge=1)

    _normalize_created_at = field_validator("created_at", mode="after")(_as_utc)
