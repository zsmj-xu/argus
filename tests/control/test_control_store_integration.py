from __future__ import annotations

from pathlib import Path

from argus.control.db import Database, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.domain.enums import EventLevel

from .helpers import make_artifact, make_finding, make_project, make_scan, make_task


def test_control_store_round_trip_survives_database_restart(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path)
    first_database = Database(path)
    first = Repositories(first_database)

    project = first.projects.create(make_project())
    scan = first.scans.create(make_scan(project))
    task = first.tasks.create(make_task(scan))
    artifact = first.artifacts.create(make_artifact(scan, task))
    finding = first.findings.upsert(make_finding(scan))
    events = EventService(first.events)
    created_event = events.append(
        "scan.created",
        project_id=project.id,
        scan_id=scan.id,
        payload={"engine": "legacy"},
    )
    finding_event = events.append(
        "finding.created",
        level=EventLevel.WARNING,
        project_id=project.id,
        scan_id=scan.id,
        finding_id=finding.id,
    )
    first_database.close()

    second_database = Database(path)
    second = Repositories(second_database)
    try:
        assert second.projects.get(project.id) == project
        assert second.scans.get(scan.id) == scan
        assert second.tasks.get(task.id) == task
        assert second.artifacts.get(artifact.id) == artifact
        assert second.artifacts.list(scan_id=scan.id) == [artifact]
        assert second.findings.list(scan_id=scan.id) == [finding]
        assert second.events.list(scan_id=scan.id) == [created_event, finding_event]
        assert created_event.sequence == 1
        assert finding_event.sequence == 2
    finally:
        second_database.close()


def test_finding_upsert_preserves_identity_and_replaces_content(repositories: Repositories) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    original = repositories.findings.upsert(make_finding(scan, title="Original"))
    replacement = repositories.findings.upsert(make_finding(scan, title="Updated"))

    assert replacement.id == original.id
    assert replacement.created_at == original.created_at
    assert replacement.title == "Updated"
    assert repositories.findings.list(scan_id=scan.id) == [replacement]
