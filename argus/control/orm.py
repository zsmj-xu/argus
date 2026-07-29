"""SQLAlchemy persistence entities.

ORM rows never cross the repository boundary; callers receive Pydantic domain
DTOs from :mod:`argus.domain.models`.
"""

from __future__ import annotations

from pydantic import JsonValue
from sqlalchemy import Boolean, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    repository_path: Mapped[str] = mapped_column(Text, nullable=False)
    default_config: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)
    archived_at: Mapped[str | None] = mapped_column(String(40))


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    config: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    engine: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[str | None] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SourceSnapshotRow(Base):
    __tablename__ = "source_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    repository_path: Mapped[str] = mapped_column(Text, nullable=False)
    vcs_type: Mapped[str] = mapped_column(String(16), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    tree_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dirty: Mapped[bool] = mapped_column(nullable=False)
    materialized_path: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_artifact_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class TaskRow(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plan_id: Mapped[str | None] = mapped_column(String(36), index=True)
    plugin_id: Mapped[str] = mapped_column(String(255), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    depends_on: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    required_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    optional_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    expected_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    continue_on_failure: Mapped[bool] = mapped_column(nullable=False, default=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[str | None] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_tasks_scan_status", "scan_id", "status"),
        UniqueConstraint("scan_id", "id", name="uq_tasks_scan_id_id"),
    )


class TaskPlanRow(Base):
    __tablename__ = "task_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("artifacts.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class TaskAttemptRow(Base):
    __tablename__ = "task_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    plugin_id: Mapped[str] = mapped_column(String(255), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(64), nullable=False)
    input_artifact_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    input_hashes: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    worker_pid: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    heartbeat_at: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    finished_at: Mapped[str | None] = mapped_column(String(40))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (UniqueConstraint("task_id", "attempt_number", name="uq_task_attempt_number"),)


class ReviewRequestRow(Base):
    __tablename__ = "review_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reviewer: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    decided_at: Mapped[str | None] = mapped_column(String(40))


class ArtifactRow(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    artifact_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    producer_plugin_id: Mapped[str] = mapped_column(String(255), nullable=False)
    producer_plugin_version: Mapped[str] = mapped_column(String(64), nullable=False)
    media_type: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_metadata: Mapped[dict[str, JsonValue]] = mapped_column("metadata", JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    weakness_id: Mapped[str] = mapped_column(String(128), nullable=False)
    vuln_class: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    static_confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    locations: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    source_node_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    sink_node_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    root_cause_key: Mapped[str | None] = mapped_column(String(64), index=True)
    graph_slice_artifact_id: Mapped[str | None] = mapped_column(String(36))
    evidence_artifact_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    preconditions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)

    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),)


class VerificationEnvironmentRow(Base):
    __tablename__ = "verification_environments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target_base_url: Mapped[str | None] = mapped_column(Text)
    scope_allowlist: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    health_checks: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    reset_capability: Mapped[str] = mapped_column(String(32), nullable=False)
    source_snapshot_binding: Mapped[str | None] = mapped_column(String(36), index=True)
    test_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_private_addresses: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class VerificationIdentityRow(Base):
    __tablename__ = "verification_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    handle: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    tenant: Mapped[str | None] = mapped_column(String(255))
    identity_attributes: Mapped[dict[str, JsonValue]] = mapped_column("attributes", JSON, nullable=False)
    credential_ref: Mapped[str] = mapped_column(String(320), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "handle",
            name="uq_verification_identity_project_handle",
        ),
    )


class VerificationRequirementRow(Base):
    __tablename__ = "verification_requirements"

    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    required_environment_capabilities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    required_identity_roles: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    required_test_data: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    missing_fields: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class VerificationPlanRow(Base):
    __tablename__ = "verification_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    environment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("verification_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    identity_handles: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    actions: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    request_budget: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    expected_observations: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    expected_side_effects: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    rollback_strategy: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    health_checks: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    abort_conditions: Mapped[list[dict[str, JsonValue]]] = mapped_column(JSON, nullable=False)
    risk_class: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(40), nullable=False)


class VerificationApprovalRow(Base):
    __tablename__ = "verification_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("verification_plans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reviewer: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
    decided_at: Mapped[str | None] = mapped_column(String(40))
    expires_at: Mapped[str | None] = mapped_column(String(40), index=True)


class VerificationAttemptRow(Base):
    __tablename__ = "verification_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("verification_plans.id", ondelete="CASCADE"), index=True
    )
    plan_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    environment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("verification_environments.id", ondelete="RESTRICT")
    )
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)
    response_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    health_before: Mapped[list[dict[str, JsonValue]] | None] = mapped_column(JSON)
    health_after: Mapped[list[dict[str, JsonValue]] | None] = mapped_column(JSON)
    abort_reason: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[str] = mapped_column(String(40), nullable=False)
    finished_at: Mapped[str | None] = mapped_column(String(40))


class VerificationEvidenceRow(Base):
    __tablename__ = "verification_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("verification_attempts.id", ondelete="CASCADE"), index=True
    )
    plan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("verification_plans.id", ondelete="CASCADE"), index=True
    )
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    identity_handle: Mapped[str] = mapped_column(String(128), nullable=False)
    request_summary: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    response_status: Mapped[int] = mapped_column(Integer, nullable=False)
    response_headers: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    body_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    observation: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    predicate_result: Mapped[str] = mapped_column(String(32), nullable=False)
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class EventRow(Base):
    __tablename__ = "events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    project_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="SET NULL"),
        index=True,
    )
    scan_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("tasks.id", ondelete="SET NULL"),
        index=True,
    )
    finding_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="SET NULL"),
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, JsonValue]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)
