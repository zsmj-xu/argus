from __future__ import annotations

from uuid import uuid4

import pytest

from argus.control.db import Database
from argus.control.repositories import Repositories
from argus.domain.errors import ConflictError, NotFoundError, SchemaValidationError

from .helpers import make_artifact, make_finding, make_project, make_scan, make_task


def test_project_scan_task_crud(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))

    updated_scan = repositories.scans.update(scan.model_copy(update={"error_message": "diagnostic"}))
    updated_task = repositories.tasks.update(task.model_copy(update={"error_message": "diagnostic"}))

    assert repositories.projects.get(project.id) == project
    assert repositories.projects.list() == [project]
    assert repositories.scans.get(scan.id) == updated_scan
    assert repositories.scans.list(project_id=project.id) == [updated_scan]
    assert repositories.tasks.get(task.id) == updated_task
    assert repositories.tasks.list(scan_id=scan.id) == [updated_task]
    assert updated_scan.version == 2
    assert updated_task.version == 2


def test_duplicate_project_name_is_a_conflict(repositories: Repositories) -> None:
    repositories.projects.create(make_project())

    with pytest.raises(ConflictError):
        repositories.projects.create(make_project())


def test_missing_object_raises_domain_error(repositories: Repositories) -> None:
    with pytest.raises(NotFoundError):
        repositories.projects.get(uuid4())


def test_stale_scan_update_is_rejected(control_db: Database) -> None:
    first = Repositories(control_db)
    second = Repositories(control_db)
    project = first.projects.create(make_project())
    created = first.scans.create(make_scan(project))
    stale_left = first.scans.get(created.id)
    stale_right = second.scans.get(created.id)

    first.scans.update(stale_left.model_copy(update={"error_message": "first"}))

    with pytest.raises(ConflictError, match="stale scan version"):
        second.scans.update(stale_right.model_copy(update={"error_message": "second"}))


def test_stale_task_update_is_rejected(control_db: Database) -> None:
    first = Repositories(control_db)
    second = Repositories(control_db)
    project = first.projects.create(make_project())
    scan = first.scans.create(make_scan(project))
    created = first.tasks.create(make_task(scan))
    stale_left = first.tasks.get(created.id)
    stale_right = second.tasks.get(created.id)

    first.tasks.update(stale_left.model_copy(update={"error_message": "first"}))

    with pytest.raises(ConflictError, match="stale task version"):
        second.tasks.update(stale_right.model_copy(update={"error_message": "second"}))


def test_repository_revalidates_json_before_update(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    invalid = scan.model_copy(update={"config": {"not_json": object()}})

    with pytest.raises(SchemaValidationError, match="invalid persisted Scan"):
        repositories.scans.update(invalid)

    assert repositories.scans.get(scan.id) == scan


def test_artifact_and_static_finding_commit_atomically(
    repositories: Repositories,
) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    artifact = make_artifact(scan, task)
    finding = make_finding(scan).model_copy(
        update={
            "graph_slice_artifact_id": artifact.id,
            "evidence_artifact_ids": [artifact.id],
            "root_cause_key": "d" * 64,
        }
    )

    repositories.artifacts.create_many([artifact], findings=[finding])

    assert repositories.artifacts.get(artifact.id) == artifact
    assert repositories.findings.get(finding.id) == finding


def test_artifact_conflict_rolls_back_finding_batch(
    repositories: Repositories,
) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    artifact = make_artifact(scan, task)
    finding = make_finding(scan)

    with pytest.raises(ConflictError):
        repositories.artifacts.create_many(
            [artifact, artifact],
            findings=[finding],
        )

    assert repositories.artifacts.list(scan_id=scan.id) == []
    assert repositories.findings.list(scan_id=scan.id) == []
