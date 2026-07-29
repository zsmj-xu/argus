from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import sqlite3

import pytest

from argus.artifacts.store import ArtifactStore
from argus.control.db import Database
from argus.control.maintenance import backup_database, collect_artifact_garbage
from argus.control.repositories import Repositories

from .helpers import make_artifact, make_project, make_scan, make_task


def test_database_backup_is_consistent_and_never_overwrites(
    control_db: Database,
    repositories: Repositories,
    tmp_path: Path,
) -> None:
    repositories.projects.create(make_project())
    destination = tmp_path / "backups" / "control.db"

    result = backup_database(control_db.path, destination)

    assert result.path == destination.resolve()
    assert result.size_bytes > 0
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert connection.execute("SELECT COUNT(*) FROM projects").fetchone() == (1,)
    with pytest.raises(FileExistsError):
        backup_database(control_db.path, destination)


def test_artifact_gc_is_dry_run_then_quarantines_only_unreferenced_blobs(
    control_db: Database,
    repositories: Repositories,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path)
    referenced_blob = store.put_bytes(b"referenced")
    orphan_blob = store.put_bytes(b"orphan")
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = repositories.tasks.create(make_task(scan))
    artifact = make_artifact(scan, task).model_copy(
        update={
            "content_hash": referenced_blob.content_hash,
            "size_bytes": referenced_blob.size_bytes,
            "storage_uri": referenced_blob.storage_uri,
        }
    )
    repositories.artifacts.create_many([artifact])

    preview = collect_artifact_garbage(
        control_db,
        runs_root=tmp_path,
        minimum_age=timedelta(0),
    )
    assert preview.candidates == (orphan_blob.content_hash,)
    assert preview.quarantined == ()
    assert store.read_bytes(orphan_blob.content_hash) == b"orphan"

    applied = collect_artifact_garbage(
        control_db,
        runs_root=tmp_path,
        apply=True,
        minimum_age=timedelta(0),
    )
    assert applied.quarantined == (orphan_blob.content_hash,)
    assert applied.quarantine_root is not None
    assert (applied.quarantine_root / orphan_blob.content_hash / "payload").read_bytes() == b"orphan"
    assert store.read_bytes(referenced_blob.content_hash) == b"referenced"


def test_artifact_gc_rejects_negative_minimum_age(
    control_db: Database,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="minimum_age"):
        collect_artifact_garbage(
            control_db,
            runs_root=tmp_path,
            minimum_age=timedelta(seconds=-1),
        )
