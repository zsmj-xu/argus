"""Repository boundary between Pydantic DTOs and SQLAlchemy rows."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
import re
from typing import TypeVar, cast
from uuid import UUID

from pydantic import BaseModel, ValidationError
from sqlalchemy import Select, exists, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from argus.control.db import Database
from argus.control.orm import (
    ArtifactRow,
    EventRow,
    FindingRow,
    ProjectRow,
    ReviewRequestRow,
    ScanRow,
    SourceSnapshotRow,
    TaskAttemptRow,
    TaskPlanRow,
    TaskRow,
)
from argus.domain.enums import AttemptStatus, ReviewStatus, ScanStatus, TaskStatus
from argus.domain.errors import ConflictError, InvalidTransitionError, NotFoundError, SchemaValidationError
from argus.domain.models import (
    Artifact,
    Event,
    PlannedTask,
    Project,
    ReviewRequest,
    Scan,
    SourceSnapshot,
    StaticFindingV2,
    Task,
    TaskAttempt,
    TaskPlan,
)

DomainT = TypeVar("DomainT", bound=BaseModel)


def _validated(model_type: type[DomainT], data: dict[str, object]) -> DomainT:
    try:
        return model_type.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError(f"invalid persisted {model_type.__name__}: {exc}") from exc


def _revalidated(model_type: type[DomainT], value: DomainT) -> DomainT:
    """Defend the DB boundary against model_construct/model_copy bypasses."""
    return _validated(model_type, value.model_dump(mode="python", warnings="none"))


def _uuid(value: UUID | None) -> str | None:
    return str(value) if value is not None else None


def _dt(value: object) -> str | None:
    return value.isoformat() if value is not None and hasattr(value, "isoformat") else None


def _not_found(kind: str, object_id: UUID) -> NotFoundError:
    return NotFoundError(f"{kind} not found: {object_id}")


def _project_from_row(row: ProjectRow) -> Project:
    return _validated(
        Project,
        {
            "id": row.id,
            "name": row.name,
            "repository_path": row.repository_path,
            "default_config": row.default_config,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "archived_at": row.archived_at,
        },
    )


def _scan_from_row(row: ScanRow) -> Scan:
    return _validated(
        Scan,
        {
            "id": row.id,
            "project_id": row.project_id,
            "snapshot_id": row.snapshot_id,
            "plan_id": row.plan_id,
            "status": row.status,
            "config": row.config,
            "config_hash": row.config_hash,
            "engine": row.engine,
            "created_at": row.created_at,
            "started_at": row.started_at,
            "finished_at": row.finished_at,
            "error_code": row.error_code,
            "error_message": row.error_message,
            "version": row.version,
        },
    )


def _snapshot_from_row(row: SourceSnapshotRow) -> SourceSnapshot:
    return _validated(
        SourceSnapshot,
        {
            "id": row.id,
            "project_id": row.project_id,
            "repository_path": row.repository_path,
            "vcs_type": row.vcs_type,
            "commit_sha": row.commit_sha,
            "tree_hash": row.tree_hash,
            "dirty": row.dirty,
            "materialized_path": row.materialized_path,
            "manifest_artifact_id": row.manifest_artifact_id,
            "created_at": row.created_at,
        },
    )


def _task_from_row(row: TaskRow) -> Task:
    return _validated(
        Task,
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "plan_id": row.plan_id,
            "plugin_id": row.plugin_id,
            "plugin_version": row.plugin_version,
            "kind": row.kind,
            "depends_on": row.depends_on,
            "required_capabilities": row.required_capabilities,
            "optional_capabilities": row.optional_capabilities,
            "expected_capabilities": row.expected_capabilities,
            "config_hash": row.config_hash,
            "cache_key": row.cache_key,
            "continue_on_failure": row.continue_on_failure,
            "max_attempts": row.max_attempts,
            "status": row.status,
            "created_at": row.created_at,
            "started_at": row.started_at,
            "finished_at": row.finished_at,
            "error_code": row.error_code,
            "error_message": row.error_message,
            "version": row.version,
        },
    )


def _artifact_from_row(row: ArtifactRow) -> Artifact:
    return _validated(
        Artifact,
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "snapshot_id": row.snapshot_id,
            "task_id": row.task_id,
            "artifact_type": row.artifact_type,
            "schema_version": row.schema_version,
            "capabilities": row.capabilities,
            "producer_plugin_id": row.producer_plugin_id,
            "producer_plugin_version": row.producer_plugin_version,
            "media_type": row.media_type,
            "content_hash": row.content_hash,
            "size_bytes": row.size_bytes,
            "storage_uri": row.storage_uri,
            "metadata": row.artifact_metadata,
            "created_at": row.created_at,
        },
    )


def _attempt_from_row(row: TaskAttemptRow) -> TaskAttempt:
    return _validated(
        TaskAttempt,
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "task_id": row.task_id,
            "attempt_number": row.attempt_number,
            "status": row.status,
            "plugin_id": row.plugin_id,
            "plugin_version": row.plugin_version,
            "input_artifact_ids": row.input_artifact_ids,
            "input_hashes": row.input_hashes,
            "config_hash": row.config_hash,
            "worker_pid": row.worker_pid,
            "started_at": row.started_at,
            "heartbeat_at": row.heartbeat_at,
            "finished_at": row.finished_at,
            "error_code": row.error_code,
            "error_message": row.error_message,
        },
    )


def _review_from_row(row: ReviewRequestRow) -> ReviewRequest:
    return _validated(
        ReviewRequest,
        {
            "id": row.id,
            "scan_id": row.scan_id,
            "task_id": row.task_id,
            "subject_type": row.subject_type,
            "subject_ids": row.subject_ids,
            "subject_hash": row.subject_hash,
            "status": row.status,
            "reviewer": row.reviewer,
            "reason": row.reason,
            "created_at": row.created_at,
            "decided_at": row.decided_at,
        },
    )


def _finding_from_row(row: FindingRow) -> StaticFindingV2:
    return _validated(
        StaticFindingV2,
        {
            "id": row.id,
            "fingerprint": row.fingerprint,
            "scan_id": row.scan_id,
            "snapshot_id": row.snapshot_id,
            "rule_id": row.rule_id,
            "rule_version": row.rule_version,
            "title": row.title,
            "weakness_id": row.weakness_id,
            "vuln_class": row.vuln_class,
            "severity": row.severity,
            "static_confidence": row.static_confidence,
            "status": row.status,
            "locations": row.locations,
            "source_node_ids": row.source_node_ids,
            "sink_node_ids": row.sink_node_ids,
            "root_cause_key": row.root_cause_key,
            "graph_slice_artifact_id": row.graph_slice_artifact_id,
            "evidence_artifact_ids": row.evidence_artifact_ids,
            "preconditions": row.preconditions,
            "rationale": row.rationale,
            "remediation": row.remediation,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        },
    )


def _finding_values(finding: StaticFindingV2) -> dict[str, object]:
    return {
        "fingerprint": finding.fingerprint,
        "scan_id": str(finding.scan_id),
        "snapshot_id": str(finding.snapshot_id),
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "title": finding.title,
        "weakness_id": finding.weakness_id,
        "vuln_class": finding.vuln_class,
        "severity": finding.severity.value,
        "static_confidence": finding.static_confidence.value,
        "status": finding.status.value,
        "locations": [item.model_dump(mode="json") for item in finding.locations],
        "source_node_ids": finding.source_node_ids,
        "sink_node_ids": finding.sink_node_ids,
        "root_cause_key": finding.root_cause_key,
        "graph_slice_artifact_id": _uuid(finding.graph_slice_artifact_id),
        "evidence_artifact_ids": [str(item) for item in finding.evidence_artifact_ids],
        "preconditions": finding.preconditions,
        "rationale": finding.rationale,
        "remediation": finding.remediation,
        "created_at": _dt(finding.created_at),
        "updated_at": _dt(finding.updated_at),
    }


def _event_from_row(row: EventRow) -> Event:
    return _validated(
        Event,
        {
            "id": row.id,
            "project_id": row.project_id,
            "scan_id": row.scan_id,
            "task_id": row.task_id,
            "finding_id": row.finding_id,
            "event_type": row.event_type,
            "level": row.level,
            "payload": row.payload,
            "created_at": row.created_at,
            "sequence": row.sequence,
        },
    )


class ProjectRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, project: Project) -> Project:
        project = _revalidated(Project, project)
        row = ProjectRow(
            id=str(project.id),
            name=project.name,
            repository_path=project.repository_path,
            default_config=project.default_config,
            created_at=_dt(project.created_at) or "",
            updated_at=_dt(project.updated_at) or "",
            archived_at=_dt(project.archived_at),
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"project already exists: {project.id} or {project.name!r}") from exc
        return project

    def get(self, project_id: UUID) -> Project:
        with self.database.session() as session:
            row = session.get(ProjectRow, str(project_id))
            if row is None:
                raise _not_found("project", project_id)
            return _project_from_row(row)

    def list(self) -> list[Project]:
        with self.database.session() as session:
            rows = session.scalars(select(ProjectRow).order_by(ProjectRow.created_at, ProjectRow.id)).all()
            return [_project_from_row(row) for row in rows]

    def find_by_repository_path(self, repository_path: str) -> Project | None:
        statement = (
            select(ProjectRow)
            .where(ProjectRow.repository_path == repository_path)
            .order_by(ProjectRow.created_at, ProjectRow.id)
            .limit(1)
        )
        with self.database.session() as session:
            row = session.scalar(statement)
            return _project_from_row(row) if row is not None else None

    def update(self, project: Project) -> Project:
        project = _revalidated(Project, project)
        statement = (
            update(ProjectRow)
            .where(ProjectRow.id == str(project.id))
            .values(
                name=project.name,
                repository_path=project.repository_path,
                default_config=project.default_config,
                created_at=_dt(project.created_at),
                updated_at=_dt(project.updated_at),
                archived_at=_dt(project.archived_at),
            )
        )
        try:
            with self.database.session() as session:
                changed = cast(
                    CursorResult[tuple[object]],
                    session.execute(statement),
                ).rowcount
                if changed != 1:
                    raise _not_found("project", project.id)
        except IntegrityError as exc:
            raise ConflictError(f"project update conflicted: {project.id}") from exc
        return project


class ScanRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, scan: Scan) -> Scan:
        scan = _revalidated(Scan, scan)
        row = ScanRow(
            id=str(scan.id),
            project_id=str(scan.project_id),
            snapshot_id=str(scan.snapshot_id),
            plan_id=_uuid(scan.plan_id),
            status=scan.status.value,
            config=scan.config,
            config_hash=scan.config_hash,
            engine=scan.engine.value,
            created_at=_dt(scan.created_at) or "",
            started_at=_dt(scan.started_at),
            finished_at=_dt(scan.finished_at),
            error_code=scan.error_code,
            error_message=scan.error_message,
            version=scan.version,
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"scan could not be created: {scan.id}") from exc
        return scan

    def get(self, scan_id: UUID) -> Scan:
        with self.database.session() as session:
            row = session.get(ScanRow, str(scan_id))
            if row is None:
                raise _not_found("scan", scan_id)
            return _scan_from_row(row)

    def list(self, *, project_id: UUID | None = None) -> list[Scan]:
        statement: Select[tuple[ScanRow]] = select(ScanRow)
        if project_id is not None:
            statement = statement.where(ScanRow.project_id == str(project_id))
        statement = statement.order_by(ScanRow.created_at, ScanRow.id)
        with self.database.session() as session:
            return [_scan_from_row(row) for row in session.scalars(statement).all()]

    def update(self, scan: Scan) -> Scan:
        scan = _revalidated(Scan, scan)
        with self.database.session() as session:
            current = session.get(ScanRow, str(scan.id))
            if current is None:
                raise _not_found("scan", scan.id)
            if current.status != scan.status.value:
                raise InvalidTransitionError("scan status changes must use ScanService.transition()")
        return self._write(scan)

    def apply_transition(self, scan: Scan, *, source_status: ScanStatus) -> Scan:
        """Persist a transition prepared and validated by ScanService."""
        scan = _revalidated(Scan, scan)
        return self._write(scan, source_status=source_status)

    def _write(self, scan: Scan, *, source_status: ScanStatus | None = None) -> Scan:
        new_version = scan.version + 1
        statement = update(ScanRow).where(
            ScanRow.id == str(scan.id),
            ScanRow.version == scan.version,
        )
        if source_status is not None:
            statement = statement.where(ScanRow.status == source_status.value)
        statement = statement.values(
            project_id=str(scan.project_id),
            snapshot_id=str(scan.snapshot_id),
            plan_id=_uuid(scan.plan_id),
            status=scan.status.value,
            config=scan.config,
            config_hash=scan.config_hash,
            engine=scan.engine.value,
            created_at=_dt(scan.created_at),
            started_at=_dt(scan.started_at),
            finished_at=_dt(scan.finished_at),
            error_code=scan.error_code,
            error_message=scan.error_message,
            version=new_version,
        )
        try:
            with self.database.session() as session:
                changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
                if changed != 1:
                    exists = session.get(ScanRow, str(scan.id))
                    if exists is None:
                        raise _not_found("scan", scan.id)
                    raise ConflictError(f"stale scan version: {scan.id} expected {scan.version}")
        except IntegrityError as exc:
            raise ConflictError(f"scan update conflicted: {scan.id}") from exc
        return scan.model_copy(update={"version": new_version})


class TaskRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, task: Task) -> Task:
        task = _revalidated(Task, task)
        row = TaskRow(
            id=str(task.id),
            scan_id=str(task.scan_id),
            plan_id=_uuid(task.plan_id),
            plugin_id=task.plugin_id,
            plugin_version=task.plugin_version,
            kind=task.kind,
            depends_on=[str(item) for item in task.depends_on],
            required_capabilities=task.required_capabilities,
            optional_capabilities=task.optional_capabilities,
            expected_capabilities=task.expected_capabilities,
            config_hash=task.config_hash,
            cache_key=task.cache_key,
            continue_on_failure=task.continue_on_failure,
            max_attempts=task.max_attempts,
            status=task.status.value,
            created_at=_dt(task.created_at) or "",
            started_at=_dt(task.started_at),
            finished_at=_dt(task.finished_at),
            error_code=task.error_code,
            error_message=task.error_message,
            version=task.version,
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"task could not be created: {task.id}") from exc
        return task

    def get(self, task_id: UUID) -> Task:
        with self.database.session() as session:
            row = session.get(TaskRow, str(task_id))
            if row is None:
                raise _not_found("task", task_id)
            return _task_from_row(row)

    def claim_with_attempt(
        self,
        task_id: UUID,
        attempt: TaskAttempt,
    ) -> tuple[Task, TaskAttempt]:
        """Atomically claim READY Task and insert its RUNNING TaskAttempt."""
        attempt = _revalidated(TaskAttempt, attempt)
        if attempt.task_id != task_id:
            raise SchemaValidationError(f"attempt {attempt.id} belongs to task {attempt.task_id}, not {task_id}")
        try:
            with self.database.session() as session:
                current = session.get(TaskRow, str(task_id))
                if current is None:
                    raise _not_found("task", task_id)
                if current.status != TaskStatus.READY.value:
                    raise InvalidTransitionError(f"task {task_id} cannot be claimed from {current.status}")
                changed = cast(
                    CursorResult[tuple[object]],
                    session.execute(
                        update(TaskRow)
                        .where(
                            TaskRow.id == str(task_id),
                            TaskRow.version == current.version,
                            TaskRow.status == TaskStatus.READY.value,
                        )
                        .values(
                            status=TaskStatus.RUNNING.value,
                            started_at=current.started_at or _dt(attempt.started_at),
                            version=current.version + 1,
                        )
                    ),
                ).rowcount
                if changed != 1:
                    raise ConflictError(f"task claim lost: {task_id}")
                session.add(
                    TaskAttemptRow(
                        id=str(attempt.id),
                        scan_id=str(attempt.scan_id),
                        task_id=str(attempt.task_id),
                        attempt_number=attempt.attempt_number,
                        status=attempt.status.value,
                        plugin_id=attempt.plugin_id,
                        plugin_version=attempt.plugin_version,
                        input_artifact_ids=[str(item) for item in attempt.input_artifact_ids],
                        input_hashes=attempt.input_hashes,
                        config_hash=attempt.config_hash,
                        worker_pid=attempt.worker_pid,
                        started_at=_dt(attempt.started_at) or "",
                        heartbeat_at=_dt(attempt.heartbeat_at) or "",
                        finished_at=_dt(attempt.finished_at),
                        error_code=attempt.error_code,
                        error_message=attempt.error_message,
                    )
                )
                session.flush()
                session.expire(current)
                claimed = session.get(TaskRow, str(task_id))
                if claimed is None:
                    raise _not_found("task", task_id)
                return _task_from_row(claimed), attempt
        except IntegrityError as exc:
            raise ConflictError(
                f"task attempt claim conflicted: task={task_id} attempt={attempt.attempt_number}"
            ) from exc

    def list(self, *, scan_id: UUID) -> list[Task]:
        statement = select(TaskRow).where(TaskRow.scan_id == str(scan_id)).order_by(TaskRow.created_at, TaskRow.id)
        with self.database.session() as session:
            return [_task_from_row(row) for row in session.scalars(statement).all()]

    def update(self, task: Task) -> Task:
        task = _revalidated(Task, task)
        with self.database.session() as session:
            current = session.get(TaskRow, str(task.id))
            if current is None:
                raise _not_found("task", task.id)
            if current.status != task.status.value:
                raise InvalidTransitionError("task status changes must use TaskService.transition()")
        return self._write(task)

    def apply_transition(self, task: Task, *, source_status: TaskStatus) -> Task:
        """Persist a transition prepared and validated by TaskService."""
        task = _revalidated(Task, task)
        return self._write(task, source_status=source_status)

    def _write(self, task: Task, *, source_status: TaskStatus | None = None) -> Task:
        new_version = task.version + 1
        statement = update(TaskRow).where(
            TaskRow.id == str(task.id),
            TaskRow.version == task.version,
        )
        if source_status is not None:
            statement = statement.where(TaskRow.status == source_status.value)
        statement = statement.values(
            scan_id=str(task.scan_id),
            plan_id=_uuid(task.plan_id),
            plugin_id=task.plugin_id,
            plugin_version=task.plugin_version,
            kind=task.kind,
            depends_on=[str(item) for item in task.depends_on],
            required_capabilities=task.required_capabilities,
            optional_capabilities=task.optional_capabilities,
            expected_capabilities=task.expected_capabilities,
            config_hash=task.config_hash,
            cache_key=task.cache_key,
            continue_on_failure=task.continue_on_failure,
            max_attempts=task.max_attempts,
            status=task.status.value,
            created_at=_dt(task.created_at),
            started_at=_dt(task.started_at),
            finished_at=_dt(task.finished_at),
            error_code=task.error_code,
            error_message=task.error_message,
            version=new_version,
        )
        try:
            with self.database.session() as session:
                changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
                if changed != 1:
                    exists = session.get(TaskRow, str(task.id))
                    if exists is None:
                        raise _not_found("task", task.id)
                    raise ConflictError(f"stale task version: {task.id} expected {task.version}")
        except IntegrityError as exc:
            raise ConflictError(f"task update conflicted: {task.id}") from exc
        return task.model_copy(update={"version": new_version})


class TaskPlanRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, plan: TaskPlan, *, artifact_id: UUID) -> TaskPlan:
        plan = _revalidated(TaskPlan, plan)
        row = TaskPlanRow(
            id=str(plan.id),
            scan_id=str(plan.scan_id),
            plan_hash=plan.plan_hash,
            artifact_id=str(artifact_id),
            created_at=_dt(plan.created_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"task plan could not be created: {plan.id}") from exc
        return plan

    def get(self, plan_id: UUID) -> TaskPlan:
        with self.database.session() as session:
            row = session.get(TaskPlanRow, str(plan_id))
            if row is None:
                raise _not_found("task plan", plan_id)
            task_rows = session.scalars(
                select(TaskRow)
                .where(
                    TaskRow.plan_id == row.id,
                    TaskRow.plugin_id != "core.plan-compiler",
                )
                .order_by(TaskRow.created_at, TaskRow.id)
            ).all()
            tasks = [
                _validated(
                    PlannedTask,
                    {
                        "id": item.id,
                        "plugin_id": item.plugin_id,
                        "plugin_version": item.plugin_version,
                        "kind": item.kind,
                        "depends_on": item.depends_on,
                        "required_capabilities": item.required_capabilities,
                        "optional_capabilities": item.optional_capabilities,
                        "expected_capabilities": item.expected_capabilities,
                        "config_hash": item.config_hash,
                        "cache_key": item.cache_key,
                        "continue_on_failure": item.continue_on_failure,
                        "max_attempts": item.max_attempts,
                    },
                )
                for item in task_rows
            ]
            return _validated(
                TaskPlan,
                {
                    "id": row.id,
                    "scan_id": row.scan_id,
                    "tasks": tasks,
                    "plan_hash": row.plan_hash,
                    "created_at": row.created_at,
                },
            )

    def artifact_id(self, plan_id: UUID) -> UUID:
        with self.database.session() as session:
            row = session.get(TaskPlanRow, str(plan_id))
            if row is None:
                raise _not_found("task plan", plan_id)
            return UUID(row.artifact_id)


class TaskAttemptRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, attempt: TaskAttempt) -> TaskAttempt:
        attempt = _revalidated(TaskAttempt, attempt)
        row = TaskAttemptRow(
            id=str(attempt.id),
            scan_id=str(attempt.scan_id),
            task_id=str(attempt.task_id),
            attempt_number=attempt.attempt_number,
            status=attempt.status.value,
            plugin_id=attempt.plugin_id,
            plugin_version=attempt.plugin_version,
            input_artifact_ids=[str(item) for item in attempt.input_artifact_ids],
            input_hashes=attempt.input_hashes,
            config_hash=attempt.config_hash,
            worker_pid=attempt.worker_pid,
            started_at=_dt(attempt.started_at) or "",
            heartbeat_at=_dt(attempt.heartbeat_at) or "",
            finished_at=_dt(attempt.finished_at),
            error_code=attempt.error_code,
            error_message=attempt.error_message,
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(
                f"task attempt could not be created: task={attempt.task_id} attempt={attempt.attempt_number}"
            ) from exc
        return attempt

    def get(self, attempt_id: UUID) -> TaskAttempt:
        with self.database.session() as session:
            row = session.get(TaskAttemptRow, str(attempt_id))
            if row is None:
                raise _not_found("task attempt", attempt_id)
            return _attempt_from_row(row)

    def list(
        self,
        *,
        scan_id: UUID | None = None,
        task_id: UUID | None = None,
    ) -> list[TaskAttempt]:
        statement: Select[tuple[TaskAttemptRow]] = select(TaskAttemptRow)
        if scan_id is not None:
            statement = statement.where(TaskAttemptRow.scan_id == str(scan_id))
        if task_id is not None:
            statement = statement.where(TaskAttemptRow.task_id == str(task_id))
        statement = statement.order_by(
            TaskAttemptRow.started_at,
            TaskAttemptRow.attempt_number,
            TaskAttemptRow.id,
        )
        with self.database.session() as session:
            return [_attempt_from_row(row) for row in session.scalars(statement).all()]

    def next_number(self, task_id: UUID) -> int:
        statement = select(func.max(TaskAttemptRow.attempt_number)).where(TaskAttemptRow.task_id == str(task_id))
        with self.database.session() as session:
            current = session.scalar(statement)
            return int(current or 0) + 1

    def update(self, attempt: TaskAttempt) -> TaskAttempt:
        attempt = _revalidated(TaskAttempt, attempt)
        allowed_sources = {
            AttemptStatus.RUNNING: (
                AttemptStatus.RUNNING,
                AttemptStatus.WAITING_REVIEW,
            ),
            AttemptStatus.WAITING_REVIEW: (
                AttemptStatus.RUNNING,
                AttemptStatus.WAITING_REVIEW,
            ),
            AttemptStatus.SUCCEEDED: (AttemptStatus.RUNNING,),
            AttemptStatus.FAILED_RETRYABLE: (AttemptStatus.RUNNING,),
            AttemptStatus.FAILED: (
                AttemptStatus.RUNNING,
                AttemptStatus.WAITING_REVIEW,
            ),
            AttemptStatus.INTERRUPTED: (AttemptStatus.RUNNING,),
            AttemptStatus.CANCELED: (
                AttemptStatus.RUNNING,
                AttemptStatus.WAITING_REVIEW,
            ),
        }
        statement = (
            update(TaskAttemptRow)
            .where(
                TaskAttemptRow.id == str(attempt.id),
                TaskAttemptRow.status.in_([status.value for status in allowed_sources[attempt.status]]),
            )
            .values(
                status=attempt.status.value,
                heartbeat_at=_dt(attempt.heartbeat_at),
                finished_at=_dt(attempt.finished_at),
                error_code=attempt.error_code,
                error_message=attempt.error_message,
            )
        )
        with self.database.session() as session:
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                existing = session.get(TaskAttemptRow, str(attempt.id))
                if existing is None:
                    raise _not_found("task attempt", attempt.id)
                raise ConflictError(
                    f"task attempt transition conflicted: {attempt.id} {existing.status}->{attempt.status.value}"
                )
        return attempt

    def list_stale_running(self, *, heartbeat_before: datetime) -> Sequence[TaskAttempt]:
        statement = (
            select(TaskAttemptRow)
            .where(
                TaskAttemptRow.status == AttemptStatus.RUNNING.value,
                TaskAttemptRow.heartbeat_at < _dt(heartbeat_before),
            )
            .order_by(TaskAttemptRow.heartbeat_at, TaskAttemptRow.id)
        )
        with self.database.session() as session:
            return [_attempt_from_row(row) for row in session.scalars(statement).all()]


class ReviewRequestRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, review: ReviewRequest) -> ReviewRequest:
        review = _revalidated(ReviewRequest, review)
        row = ReviewRequestRow(
            id=str(review.id),
            scan_id=str(review.scan_id),
            task_id=str(review.task_id),
            subject_type=review.subject_type.value,
            subject_ids=[str(item) for item in review.subject_ids],
            subject_hash=review.subject_hash,
            status=review.status.value,
            reviewer=review.reviewer,
            reason=review.reason,
            created_at=_dt(review.created_at) or "",
            decided_at=_dt(review.decided_at),
        )
        try:
            with self.database.session() as session:
                session.execute(
                    update(ReviewRequestRow)
                    .where(
                        ReviewRequestRow.task_id == str(review.task_id),
                        ReviewRequestRow.status.in_(
                            [
                                ReviewStatus.OPEN.value,
                                ReviewStatus.APPROVED.value,
                            ]
                        ),
                        ReviewRequestRow.subject_hash != review.subject_hash,
                    )
                    .values(status=ReviewStatus.SUPERSEDED.value)
                )
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"review request could not be created: {review.id}") from exc
        return review

    def get(self, review_id: UUID) -> ReviewRequest:
        with self.database.session() as session:
            row = session.get(ReviewRequestRow, str(review_id))
            if row is None:
                raise _not_found("review request", review_id)
            return _review_from_row(row)

    def list(
        self,
        *,
        scan_id: UUID | None = None,
        task_id: UUID | None = None,
    ) -> list[ReviewRequest]:
        statement: Select[tuple[ReviewRequestRow]] = select(ReviewRequestRow)
        if scan_id is not None:
            statement = statement.where(ReviewRequestRow.scan_id == str(scan_id))
        if task_id is not None:
            statement = statement.where(ReviewRequestRow.task_id == str(task_id))
        statement = statement.order_by(
            ReviewRequestRow.created_at,
            ReviewRequestRow.id,
        )
        with self.database.session() as session:
            return [_review_from_row(row) for row in session.scalars(statement).all()]

    def decide(self, review: ReviewRequest) -> ReviewRequest:
        review = _revalidated(ReviewRequest, review)
        statement = (
            update(ReviewRequestRow)
            .where(
                ReviewRequestRow.id == str(review.id),
                ReviewRequestRow.status == ReviewStatus.OPEN.value,
            )
            .values(
                status=review.status.value,
                reviewer=review.reviewer,
                reason=review.reason,
                decided_at=_dt(review.decided_at),
            )
        )
        with self.database.session() as session:
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                existing = session.get(ReviewRequestRow, str(review.id))
                if existing is None:
                    raise _not_found("review request", review.id)
                raise ConflictError(f"review request is no longer open: {review.id} status={existing.status}")
        return review

    def supersede_open_for_scan(self, scan_id: UUID) -> int:
        statement = (
            update(ReviewRequestRow)
            .where(
                ReviewRequestRow.scan_id == str(scan_id),
                ReviewRequestRow.status == ReviewStatus.OPEN.value,
            )
            .values(status=ReviewStatus.SUPERSEDED.value)
        )
        with self.database.session() as session:
            return int(
                cast(
                    CursorResult[tuple[object]],
                    session.execute(statement),
                ).rowcount
                or 0
            )


class SourceSnapshotRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, snapshot: SourceSnapshot) -> SourceSnapshot:
        snapshot = _revalidated(SourceSnapshot, snapshot)
        row = SourceSnapshotRow(
            id=str(snapshot.id),
            project_id=str(snapshot.project_id),
            repository_path=snapshot.repository_path,
            vcs_type=snapshot.vcs_type.value,
            commit_sha=snapshot.commit_sha,
            tree_hash=snapshot.tree_hash,
            dirty=snapshot.dirty,
            materialized_path=snapshot.materialized_path,
            manifest_artifact_id=str(snapshot.manifest_artifact_id),
            created_at=_dt(snapshot.created_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"source snapshot could not be created: {snapshot.id}") from exc
        return snapshot

    def get(self, snapshot_id: UUID) -> SourceSnapshot:
        with self.database.session() as session:
            row = session.get(SourceSnapshotRow, str(snapshot_id))
            if row is None:
                raise _not_found("source snapshot", snapshot_id)
            return _snapshot_from_row(row)

    def list(self, *, project_id: UUID) -> list[SourceSnapshot]:
        statement = (
            select(SourceSnapshotRow)
            .where(SourceSnapshotRow.project_id == str(project_id))
            .order_by(SourceSnapshotRow.created_at, SourceSnapshotRow.id)
        )
        with self.database.session() as session:
            return [_snapshot_from_row(row) for row in session.scalars(statement).all()]


class ArtifactRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, artifact: Artifact) -> Artifact:
        artifact = _revalidated(Artifact, artifact)
        row = ArtifactRow(
            id=str(artifact.id),
            scan_id=str(artifact.scan_id),
            snapshot_id=str(artifact.snapshot_id),
            task_id=str(artifact.task_id),
            artifact_type=artifact.artifact_type,
            schema_version=artifact.schema_version,
            capabilities=artifact.capabilities,
            producer_plugin_id=artifact.producer_plugin_id,
            producer_plugin_version=artifact.producer_plugin_version,
            media_type=artifact.media_type,
            content_hash=artifact.content_hash,
            size_bytes=artifact.size_bytes,
            storage_uri=artifact.storage_uri,
            artifact_metadata=artifact.metadata,
            created_at=_dt(artifact.created_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"artifact could not be created: {artifact.id}") from exc
        return artifact

    def create_many(
        self,
        artifacts: Sequence[Artifact],
        *,
        findings: Sequence[StaticFindingV2] = (),
    ) -> list[Artifact]:
        validated = [_revalidated(Artifact, artifact) for artifact in artifacts]
        validated_findings = [_revalidated(StaticFindingV2, finding) for finding in findings]
        rows = [
            ArtifactRow(
                id=str(artifact.id),
                scan_id=str(artifact.scan_id),
                snapshot_id=str(artifact.snapshot_id),
                task_id=str(artifact.task_id),
                artifact_type=artifact.artifact_type,
                schema_version=artifact.schema_version,
                capabilities=artifact.capabilities,
                producer_plugin_id=artifact.producer_plugin_id,
                producer_plugin_version=artifact.producer_plugin_version,
                media_type=artifact.media_type,
                content_hash=artifact.content_hash,
                size_bytes=artifact.size_bytes,
                storage_uri=artifact.storage_uri,
                artifact_metadata=artifact.metadata,
                created_at=_dt(artifact.created_at) or "",
            )
            for artifact in validated
        ]
        try:
            with self.database.session() as session:
                session.add_all(rows)
                for finding in validated_findings:
                    existing = session.scalar(
                        select(FindingRow).where(
                            FindingRow.scan_id == str(finding.scan_id),
                            FindingRow.fingerprint == finding.fingerprint,
                        )
                    )
                    if existing is None:
                        session.add(
                            FindingRow(
                                id=str(finding.id),
                                **_finding_values(finding),
                            )
                        )
                        continue
                    values = _finding_values(
                        finding.model_copy(
                            update={
                                "id": UUID(existing.id),
                                "created_at": datetime.fromisoformat(existing.created_at),
                            }
                        )
                    )
                    for key, value in values.items():
                        setattr(existing, key, value)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError("artifact/finding batch could not be committed") from exc
        return validated

    def get(self, artifact_id: UUID) -> Artifact:
        with self.database.session() as session:
            row = session.get(ArtifactRow, str(artifact_id))
            if row is None:
                raise _not_found("artifact", artifact_id)
            return _artifact_from_row(row)

    def list(self, *, scan_id: UUID) -> list[Artifact]:
        statement = (
            select(ArtifactRow)
            .where(ArtifactRow.scan_id == str(scan_id))
            .order_by(ArtifactRow.created_at, ArtifactRow.id)
        )
        with self.database.session() as session:
            return [_artifact_from_row(row) for row in session.scalars(statement).all()]

    def find_latest_by_capability(
        self,
        *,
        scan_id: UUID,
        capability: str,
    ) -> Artifact | None:
        capability_values = func.json_each(ArtifactRow.capabilities).table_valued("value")
        statement = (
            select(ArtifactRow)
            .where(
                ArtifactRow.scan_id == str(scan_id),
                exists(select(1).select_from(capability_values).where(capability_values.c.value == capability)),
            )
            .order_by(ArtifactRow.created_at.desc(), ArtifactRow.id.desc())
            .limit(1)
        )
        with self.database.session() as session:
            row = session.scalar(statement)
            return _artifact_from_row(row) if row is not None else None

    def find_latest_by_metadata(
        self,
        *,
        artifact_type: str,
        metadata_key: str,
        metadata_value: str,
    ) -> Artifact | None:
        if re.fullmatch(r"[A-Za-z0-9_.-]+", metadata_key) is None:
            raise SchemaValidationError(f"invalid artifact metadata key: {metadata_key!r}")
        statement = (
            select(ArtifactRow)
            .where(
                ArtifactRow.artifact_type == artifact_type,
                func.json_extract(ArtifactRow.artifact_metadata, f"$.{metadata_key}") == metadata_value,
            )
            .order_by(ArtifactRow.created_at.desc(), ArtifactRow.id.desc())
            .limit(1)
        )
        with self.database.session() as session:
            row = session.scalar(statement)
            return _artifact_from_row(row) if row is not None else None

    def find_cached_outputs(
        self,
        *,
        plugin_id: str,
        plugin_version: str,
        task_cache_key: str,
    ) -> Sequence[Artifact]:
        statement = (
            select(ArtifactRow)
            .where(
                ArtifactRow.producer_plugin_id == plugin_id,
                ArtifactRow.producer_plugin_version == plugin_version,
                func.json_extract(
                    ArtifactRow.artifact_metadata,
                    "$.task_cache_key",
                )
                == task_cache_key,
            )
            .order_by(ArtifactRow.created_at.desc(), ArtifactRow.id.desc())
        )
        with self.database.session() as session:
            return [_artifact_from_row(row) for row in session.scalars(statement).all()]


class FindingRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(self, finding: StaticFindingV2) -> StaticFindingV2:
        finding = _revalidated(StaticFindingV2, finding)
        statement = select(FindingRow).where(
            FindingRow.scan_id == str(finding.scan_id),
            FindingRow.fingerprint == finding.fingerprint,
        )
        try:
            with self.database.session() as session:
                row = session.scalar(statement)
                if row is None:
                    row = FindingRow(
                        id=str(finding.id),
                        **_finding_values(finding),
                    )
                    session.add(row)
                    result = finding
                else:
                    result = finding.model_copy(
                        update={"id": UUID(row.id), "created_at": datetime.fromisoformat(row.created_at)}
                    )
                    for key, value in _finding_values(result).items():
                        setattr(row, key, value)
                session.flush()
                return result
        except IntegrityError as exc:
            raise ConflictError(
                f"finding upsert conflicted: scan={finding.scan_id} fingerprint={finding.fingerprint}"
            ) from exc

    def list(self, *, scan_id: UUID) -> list[StaticFindingV2]:
        statement = (
            select(FindingRow).where(FindingRow.scan_id == str(scan_id)).order_by(FindingRow.created_at, FindingRow.id)
        )
        with self.database.session() as session:
            return [_finding_from_row(row) for row in session.scalars(statement).all()]

    def get(self, finding_id: UUID) -> StaticFindingV2:
        with self.database.session() as session:
            row = session.get(FindingRow, str(finding_id))
            if row is None:
                raise _not_found("finding", finding_id)
            return _finding_from_row(row)


class EventRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def append(self, event: Event) -> Event:
        event = _revalidated(Event, event)
        if event.sequence is not None:
            raise SchemaValidationError("event sequence is assigned by the control store")
        row = EventRow(
            id=str(event.id),
            project_id=_uuid(event.project_id),
            scan_id=_uuid(event.scan_id),
            task_id=_uuid(event.task_id),
            finding_id=_uuid(event.finding_id),
            event_type=event.event_type,
            level=event.level.value,
            payload=event.payload,
            created_at=_dt(event.created_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
                return event.model_copy(update={"sequence": row.sequence})
        except IntegrityError as exc:
            raise ConflictError(f"event could not be appended: {event.id}") from exc

    def list(
        self,
        *,
        project_id: UUID | None = None,
        scan_id: UUID | None = None,
    ) -> list[Event]:
        statement: Select[tuple[EventRow]] = select(EventRow)
        if project_id is not None:
            statement = statement.where(EventRow.project_id == str(project_id))
        if scan_id is not None:
            statement = statement.where(EventRow.scan_id == str(scan_id))
        statement = statement.order_by(EventRow.sequence)
        with self.database.session() as session:
            return [_event_from_row(row) for row in session.scalars(statement).all()]


class Repositories:
    """Convenience bundle sharing one database and transaction configuration."""

    def __init__(self, database: Database) -> None:
        from argus.verification.persistence import VerificationRepositories

        self.projects = ProjectRepository(database)
        self.scans = ScanRepository(database)
        self.snapshots = SourceSnapshotRepository(database)
        self.tasks = TaskRepository(database)
        self.plans = TaskPlanRepository(database)
        self.attempts = TaskAttemptRepository(database)
        self.reviews = ReviewRequestRepository(database)
        self.artifacts = ArtifactRepository(database)
        self.findings = FindingRepository(database)
        self.events = EventRepository(database)
        self.verification = VerificationRepositories(database)

    @staticmethod
    def require_nonempty(items: Sequence[DomainT], kind: str) -> Sequence[DomainT]:
        if not items:
            raise NotFoundError(f"no {kind} records found")
        return items
