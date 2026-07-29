from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from argus.artifacts.schemas import ArtifactPublication
from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactPublisher, ArtifactView
from argus.control.db import Database, upgrade_database
from argus.control.repositories import Repositories
from argus.domain.errors import ArtifactCorruptionError

from tests.control.helpers import make_project, make_scan, make_task


@pytest.fixture
def repositories(tmp_path: Path) -> Iterator[Repositories]:
    path = tmp_path / "control.db"
    upgrade_database(path)
    database = Database(path)
    try:
        yield Repositories(database)
    finally:
        database.close()


def test_same_blob_creates_distinct_artifact_metadata(
    tmp_path: Path,
    repositories: Repositories,
) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    store = ArtifactStore(tmp_path / "runs")
    publisher = ArtifactPublisher(store, repositories.artifacts)
    publication = ArtifactPublication(
        scan_id=scan.id,
        snapshot_id=scan.snapshot_id,
        task_id=task.id,
        artifact_type="legacy.findings.authz.v1",
        schema_version="1.0",
        capabilities=["legacy.findings.authz.v1"],
        producer_plugin_id=task.plugin_id,
        producer_plugin_version=task.plugin_version,
        media_type="application/json",
    )

    first = publisher.publish_json({"findings": []}, publication)
    second = publisher.publish_json({"findings": []}, publication)

    assert first.id != second.id
    assert first.content_hash == second.content_hash
    assert first.storage_uri == second.storage_uri
    assert ArtifactView(store).read_json(first) == {"findings": []}
    assert len(repositories.artifacts.list(scan_id=scan.id)) == 2


def test_view_rejects_uri_metadata_mismatch(
    tmp_path: Path,
    repositories: Repositories,
) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    store = ArtifactStore(tmp_path / "runs")
    publisher = ArtifactPublisher(store, repositories.artifacts)
    artifact = publisher.publish_text(
        "report",
        ArtifactPublication(
            scan_id=scan.id,
            snapshot_id=scan.snapshot_id,
            task_id=task.id,
            artifact_type="legacy.report.markdown.v1",
            schema_version="1.0",
            capabilities=["legacy.report.markdown.v1"],
            producer_plugin_id=task.plugin_id,
            producer_plugin_version=task.plugin_version,
            media_type="text/markdown",
        ),
    )
    mismatched = artifact.model_copy(update={"storage_uri": f"artifact://sha256/{'f' * 64}"})

    with pytest.raises(ArtifactCorruptionError, match="metadata hash mismatch"):
        ArtifactView(store).read_bytes(mismatched)
