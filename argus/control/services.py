"""Application services and legal state transitions for M1."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from argus.control.repositories import Repositories
from argus.domain.enums import ReviewStatus, ScanStatus, TaskStatus
from argus.domain.errors import InvalidTransitionError, SchemaValidationError
from argus.domain.models import Event, ReviewRequest, Scan, Task, utc_now

SCAN_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.CREATED: frozenset(
        {ScanStatus.SNAPSHOTTING, ScanStatus.PLANNING, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.SNAPSHOTTING: frozenset({ScanStatus.PLANNING, ScanStatus.FAILED, ScanStatus.CANCELED}),
    ScanStatus.PLANNING: frozenset({ScanStatus.READY, ScanStatus.FAILED, ScanStatus.CANCELED}),
    ScanStatus.READY: frozenset({ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCELED}),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.WAITING_REVIEW, ScanStatus.STATIC_COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.WAITING_REVIEW: frozenset(
        {ScanStatus.RUNNING, ScanStatus.STATIC_COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.STATIC_COMPLETED: frozenset(
        {
            ScanStatus.WAITING_VERIFICATION_INPUT,
            ScanStatus.WAITING_APPROVAL,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELED,
        }
    ),
    ScanStatus.WAITING_VERIFICATION_INPUT: frozenset(
        {ScanStatus.WAITING_APPROVAL, ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.WAITING_APPROVAL: frozenset(
        {ScanStatus.VERIFYING, ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}
    ),
    ScanStatus.VERIFYING: frozenset({ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}),
    ScanStatus.COMPLETED: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.CANCELED: frozenset(),
}

TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset({TaskStatus.READY, TaskStatus.SKIPPED, TaskStatus.CANCELED}),
    TaskStatus.READY: frozenset({TaskStatus.RUNNING, TaskStatus.SKIPPED, TaskStatus.CANCELED}),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.WAITING_REVIEW,
            TaskStatus.SUCCEEDED,
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
            TaskStatus.FAILED_RETRYABLE,
            TaskStatus.CANCELED,
        }
    ),
    TaskStatus.WAITING_REVIEW: frozenset(
        {TaskStatus.RUNNING, TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELED}
    ),
    TaskStatus.INTERRUPTED: frozenset({TaskStatus.READY, TaskStatus.FAILED, TaskStatus.CANCELED}),
    TaskStatus.FAILED_RETRYABLE: frozenset({TaskStatus.READY, TaskStatus.FAILED, TaskStatus.CANCELED}),
    TaskStatus.SUCCEEDED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.SKIPPED: frozenset(),
    TaskStatus.CANCELED: frozenset(),
}

TERMINAL_SCAN_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED})
TERMINAL_TASK_STATUSES = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.SKIPPED,
        TaskStatus.CANCELED,
    }
)


def _transition_error(kind: str, object_id: UUID, source: str, target: str) -> InvalidTransitionError:
    return InvalidTransitionError(f"illegal {kind} transition for {object_id}: {source} -> {target}")


def _utc_timestamp(value: datetime | None) -> datetime:
    timestamp = value or utc_now()
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise SchemaValidationError("transition timestamp must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


class ScanService:
    def __init__(self, repositories: Repositories) -> None:
        self.repositories = repositories

    def transition(
        self,
        scan_id: UUID,
        target: ScanStatus,
        *,
        error_code: str | None = None,
        error_message: str | None = None,
        at: datetime | None = None,
    ) -> Scan:
        scan = self.repositories.scans.get(scan_id)
        if target not in SCAN_TRANSITIONS[scan.status]:
            raise _transition_error("scan", scan.id, scan.status.value, target.value)
        timestamp = _utc_timestamp(at)
        changes: dict[str, object] = {"status": target}
        if target is ScanStatus.RUNNING and scan.started_at is None:
            changes["started_at"] = timestamp
        if target in TERMINAL_SCAN_STATUSES:
            changes["finished_at"] = timestamp
        if target is ScanStatus.FAILED:
            changes["error_code"] = error_code
            changes["error_message"] = error_message
        elif error_code is not None or error_message is not None:
            raise InvalidTransitionError("error details are only valid for a failed scan")
        return self.repositories.scans.apply_transition(
            scan.model_copy(update=changes),
            source_status=scan.status,
        )


class TaskService:
    def __init__(self, repositories: Repositories) -> None:
        self.repositories = repositories

    def transition(
        self,
        task_id: UUID,
        target: TaskStatus,
        *,
        error_code: str | None = None,
        error_message: str | None = None,
        at: datetime | None = None,
    ) -> Task:
        task = self.repositories.tasks.get(task_id)
        if target not in TASK_TRANSITIONS[task.status]:
            raise _transition_error("task", task.id, task.status.value, target.value)
        timestamp = _utc_timestamp(at)
        changes: dict[str, object] = {"status": target}
        if target is TaskStatus.RUNNING and task.started_at is None:
            changes["started_at"] = timestamp
        if target in TERMINAL_TASK_STATUSES:
            changes["finished_at"] = timestamp
        if target in {
            TaskStatus.FAILED,
            TaskStatus.INTERRUPTED,
            TaskStatus.FAILED_RETRYABLE,
        }:
            changes["error_code"] = error_code
            changes["error_message"] = error_message
        elif error_code is not None or error_message is not None:
            raise InvalidTransitionError("error details are only valid for a failed or interrupted task")
        if target is TaskStatus.READY:
            changes["error_code"] = None
            changes["error_message"] = None
        return self.repositories.tasks.apply_transition(
            task.model_copy(update=changes),
            source_status=task.status,
        )


class ControlServices:
    def __init__(self, repositories: Repositories) -> None:
        self.scans = ScanService(repositories)
        self.tasks = TaskService(repositories)
        self.reviews = ReviewService(repositories)


class ReviewService:
    def __init__(self, repositories: Repositories) -> None:
        self.repositories = repositories

    def decide(
        self,
        review_id: UUID,
        target: ReviewStatus,
        *,
        reviewer: str,
        reason: str,
        at: datetime | None = None,
    ) -> ReviewRequest:
        if target not in {ReviewStatus.APPROVED, ReviewStatus.REJECTED}:
            raise InvalidTransitionError(f"review decisions must be approved or rejected, got {target.value}")
        if not reviewer.strip() or not reason.strip():
            raise SchemaValidationError("reviewer and reason are required")
        review = self.repositories.reviews.get(review_id)
        if review.status is not ReviewStatus.OPEN:
            raise InvalidTransitionError(f"review request {review.id} is not open: {review.status.value}")
        decided = self.repositories.reviews.decide(
            review.model_copy(
                update={
                    "status": target,
                    "reviewer": reviewer,
                    "reason": reason,
                    "decided_at": _utc_timestamp(at),
                }
            )
        )
        self.repositories.events.append(
            Event(
                scan_id=decided.scan_id,
                task_id=decided.task_id,
                event_type=f"review.{target.value}",
                payload={
                    "review_id": str(decided.id),
                    "reviewer": reviewer,
                    "reason": reason,
                    "subject_hash": decided.subject_hash,
                },
            )
        )
        return decided
