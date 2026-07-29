from __future__ import annotations

from datetime import datetime, timezone

import pytest

from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import ScanStatus, TaskStatus
from argus.domain.errors import InvalidTransitionError, SchemaValidationError

from .helpers import make_project, make_scan, make_task


def test_scan_state_transitions_are_service_controlled(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    services = ControlServices(repositories)
    timestamp = datetime(2026, 7, 29, 12, tzinfo=timezone.utc)

    planning = services.scans.transition(scan.id, ScanStatus.PLANNING, at=timestamp)
    ready = services.scans.transition(scan.id, ScanStatus.READY, at=timestamp)
    running = services.scans.transition(scan.id, ScanStatus.RUNNING, at=timestamp)

    assert planning.status is ScanStatus.PLANNING
    assert ready.status is ScanStatus.READY
    assert running.status is ScanStatus.RUNNING
    assert running.started_at == timestamp


def test_illegal_scan_transition_is_rejected(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))

    with pytest.raises(InvalidTransitionError, match="created -> completed"):
        ControlServices(repositories).scans.transition(scan.id, ScanStatus.COMPLETED)

    assert repositories.scans.get(scan.id).status is ScanStatus.CREATED


def test_repository_cannot_bypass_scan_service(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))

    with pytest.raises(InvalidTransitionError, match="ScanService"):
        repositories.scans.update(scan.model_copy(update={"status": ScanStatus.PLANNING}))


def test_task_failure_records_terminal_time_and_error(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    services = ControlServices(repositories)
    timestamp = datetime(2026, 7, 29, 12, tzinfo=timezone.utc)

    services.tasks.transition(task.id, TaskStatus.READY, at=timestamp)
    services.tasks.transition(task.id, TaskStatus.RUNNING, at=timestamp)
    failed = services.tasks.transition(
        task.id,
        TaskStatus.FAILED,
        error_code="plugin_failed",
        error_message="fixture failure",
        at=timestamp,
    )

    assert failed.status is TaskStatus.FAILED
    assert failed.started_at == timestamp
    assert failed.finished_at == timestamp
    assert failed.error_code == "plugin_failed"


def test_terminal_task_cannot_restart(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    services = ControlServices(repositories)

    services.tasks.transition(task.id, TaskStatus.SKIPPED)
    with pytest.raises(InvalidTransitionError, match="skipped -> running"):
        services.tasks.transition(task.id, TaskStatus.RUNNING)


def test_repository_cannot_bypass_task_service(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))

    with pytest.raises(InvalidTransitionError, match="TaskService"):
        repositories.tasks.update(task.model_copy(update={"status": TaskStatus.READY}))


def test_transition_rejects_naive_timestamp(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))

    with pytest.raises(SchemaValidationError, match="timezone-aware"):
        ControlServices(repositories).scans.transition(
            scan.id,
            ScanStatus.PLANNING,
            at=datetime(2026, 7, 29, 12),
        )
