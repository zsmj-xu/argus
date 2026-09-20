"""Small public contracts for the Argus white-box scanning service."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from argus.repositories import GitRepositoryError, normalize_git_url


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"
    SKIPPED = "skipped"


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class ServiceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _safe_pattern(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} entries must be strings")
    candidate = value.strip().replace("\\", "/")
    if (
        not candidate
        or len(candidate) > 512
        or "\x00" in candidate
        or "\n" in candidate
        or "\r" in candidate
        or "," in candidate
        or candidate.startswith("/")
        or candidate.startswith("//")
        or any(part == ".." for part in candidate.split("/"))
    ):
        raise ValueError(f"{field_name} entries must be safe repository-relative patterns")
    return candidate


def _safe_ref(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > 256
        or "\x00" in candidate
        or any(char.isspace() for char in candidate)
        or candidate.startswith("-")
        or ".." in candidate
        or "@{" in candidate
        or candidate.endswith((".", "/"))
        or "//" in candidate
    ):
        raise ValueError("ref must be a safe Git branch, tag, or commit")
    if not all(char.isalnum() or char in "._/@+-" for char in candidate):
        raise ValueError("ref contains unsupported characters")
    return candidate


class ScanCreateRequest(ServiceModel):
    """One full-file scan request; repository registration is not required."""

    repository_url: str = Field(min_length=1, max_length=4096)
    ref: str | None = Field(default=None, max_length=256)
    include: list[str] = Field(default_factory=list, max_length=256)
    exclude: list[str] = Field(default_factory=list, max_length=256)
    background: str | None = Field(default=None, max_length=16_384)
    source_disclosure_confirmed: bool = Field(
        default=False,
        description="The caller confirms that selected source may be sent to the configured LLM.",
    )

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        try:
            return normalize_git_url(value)
        except GitRepositoryError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, value: str | None) -> str | None:
        return _safe_ref(value)

    @field_validator("include", "exclude")
    @classmethod
    def validate_patterns(cls, values: list[str], info: ValidationInfo) -> list[str]:
        field_name = str(info.field_name)
        normalized = [_safe_pattern(item, field_name) for item in values]
        return list(dict.fromkeys(normalized))

    @field_validator("background")
    @classmethod
    def validate_background(cls, value: str | None) -> str | None:
        if value is not None and ("\x00" in value or "\n" in value or "\r" in value):
            raise ValueError("background must not contain control characters")
        return value.strip() if value else None


class ScanProgress(ServiceModel):
    total_files: int = Field(default=0, ge=0)
    reviewed_files: int = Field(default=0, ge=0)
    failed_files: int = Field(default=0, ge=0)
    skipped_files: int = Field(default=0, ge=0)
    percent: int = Field(default=0, ge=0, le=100)


class ScanCapabilities(ServiceModel):
    """Capabilities that have been positively observed for one scan."""

    file_progress: bool = False
    llm_requests: bool = False
    event_protocol: bool = False


class ScanCoverage(ServiceModel):
    """Truthful coverage counters; ``total`` is null when it is not known."""

    total: int | None = Field(default=None, ge=0)
    reviewed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)
    percent: int | None = Field(default=None, ge=0, le=100)


class ScanErrorSummary(ServiceModel):
    """A bounded, actionable summary of the most recent scan error."""

    code: str | None = Field(default=None, max_length=256)
    message: str | None = Field(default=None, max_length=2_000)
    retryable: bool | None = None
    suggestion: str | None = Field(default=None, max_length=2_000)
    source: str | None = Field(default=None, max_length=128)


class ScanObservation(ServiceModel):
    """Derived runtime observability returned with every scan response."""

    stage: str = Field(default="unknown", max_length=256)
    stage_started_at: datetime | None = None
    elapsed_seconds: float = Field(default=0, ge=0)
    stage_elapsed_seconds: float = Field(default=0, ge=0)
    last_output_at: datetime | None = None
    last_progress_at: datetime | None = None
    worker_heartbeat_at: datetime | None = None
    deadline_at: datetime | None = None
    activity_state: str = Field(default="unknown", max_length=64)
    capabilities: ScanCapabilities = Field(default_factory=ScanCapabilities)
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    report_ready: bool = False
    history_available: bool = False
    error_summary: ScanErrorSummary = Field(default_factory=ScanErrorSummary)
    warnings: list[str] = Field(default_factory=list, max_length=16)
    event_count: int = Field(default=0, ge=0)
    dropped_event_count: int = Field(default=0, ge=0)
    truncated_event_count: int = Field(default=0, ge=0)


class ScanEvent(ServiceModel):
    """One immutable sanitized event in the scan history."""

    schema_version: int = Field(default=1, ge=1)
    event_id: int | None = Field(default=None, ge=1)
    timestamp: datetime
    id: int | None = Field(default=None, ge=1)
    cursor: int | None = Field(default=None, ge=1)
    scan_id: str
    attempt: int = Field(ge=0)
    source: str | None = Field(default=None, max_length=128)
    type: str = Field(min_length=1, max_length=128)
    stage: str | None = Field(default=None, max_length=256)
    level: str | None = Field(default=None, max_length=32)
    code: str | None = Field(default=None, max_length=256)
    message: str | None = Field(default=None, max_length=2_000)
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    truncated: bool = False
    accepted: bool = True
    dropped: bool = False


class ScanEventsResponse(ServiceModel):
    items: list[ScanEvent]
    next_cursor: int = Field(ge=0)
    has_more: bool = False
    oldest_cursor: int | None = None
    history_truncated: bool = False
    expired_event_count: int = Field(default=0, ge=0)


class ScanDiagnosticsResponse(ServiceModel):
    scan_id: str
    observation: ScanObservation
    summary: dict[str, Any] = Field(default_factory=dict)
    recent_errors: list[ScanEvent] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)


class FindingCreate(ServiceModel):
    """A normalized static finding produced by the OCR adapter."""

    rule_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=2_000)
    category: str = Field(default="security", min_length=1, max_length=128)
    severity: str = Field(default="unknown", min_length=1, max_length=32)
    confidence: str | None = Field(default=None, max_length=32)
    file: str | None = Field(default=None, max_length=4096)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    message: str = Field(min_length=1, max_length=20_000)
    evidence: str = Field(default="", max_length=20_000)
    remediation: str = Field(default="", max_length=20_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _safe_pattern(value, "file")

    @field_validator("end_line")
    @classmethod
    def validate_end_line(cls, value: int | None, info: ValidationInfo) -> int | None:
        start = info.data.get("start_line")
        if value is not None and start is not None and value < start:
            raise ValueError("end_line must be greater than or equal to start_line")
        return value


class FindingResponse(FindingCreate):
    id: str
    scan_id: str
    created_at: datetime


class ScanResponse(ServiceModel):
    id: str
    repository_url: str
    ref: str | None
    commit_sha: str | None = None
    include: list[str]
    exclude: list[str]
    background: str | None
    status: ScanStatus
    phase: str
    progress: ScanProgress
    finding_count: int = Field(default=0, ge=0)
    attempt: int = Field(default=0, ge=0)
    idempotency_key: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    observation: ScanObservation = Field(default_factory=ScanObservation)


class ScanListResponse(ServiceModel):
    items: list[ScanResponse]
    total: int = Field(ge=0)


class ScanReport(ServiceModel):
    scan: ScanResponse
    findings: list[FindingResponse]


class ServiceScanResult(ServiceModel):
    """Worker result independent of the OCR process implementation."""

    findings: list[FindingCreate] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.COMPLETED
    commit_sha: str | None = None
    session_id: str | None = None
    total_files: int = Field(default=0, ge=0)
    reviewed_files: int = Field(default=0, ge=0)
    failed_files: int = Field(default=0, ge=0)
    skipped_files: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @field_validator("status")
    @classmethod
    def validate_terminal_status(cls, value: ScanStatus) -> ScanStatus:
        if value in {ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.CANCELED}:
            raise ValueError("worker result must use a terminal scan status")
        return value
