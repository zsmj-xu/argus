from __future__ import annotations

import subprocess
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from argus.domain.enums import VcsType
from argus.domain.errors import SnapshotError
from argus.snapshots.hashing import SnapshotManifest
from argus.snapshots.materialize import materialize_snapshot
from argus.snapshots.service import SnapshotService


def test_snapshot_is_full_copy_immune_to_later_source_changes(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    source = repository / "app.py"
    source.write_text("before\n", encoding="utf-8")
    runs_root = tmp_path / "runs"

    result = SnapshotService(runs_root).create(
        project_id=uuid4(),
        repository_path=repository,
        snapshot_id=uuid4(),
        manifest_artifact_id=uuid4(),
    )
    source.write_text("after\n", encoding="utf-8")

    copied = Path(result.snapshot.materialized_path) / "app.py"
    assert copied.read_text(encoding="utf-8") == "before\n"
    assert result.manifest_path.is_file()
    assert result.snapshot.tree_hash == result.manifest.tree_hash
    assert not (repository / ".codegraph").exists()


def test_snapshot_records_git_commit_and_dirty_state(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    (repository / "app.py").write_text("tracked\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=Argus Test",
            "-c",
            "user.email=argus@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
        check=True,
        capture_output=True,
    )

    clean = SnapshotService(tmp_path / "runs-clean").create(
        project_id=uuid4(),
        repository_path=repository,
        snapshot_id=uuid4(),
        manifest_artifact_id=uuid4(),
    )
    (repository / "app.py").write_text("dirty\n", encoding="utf-8")
    dirty = SnapshotService(tmp_path / "runs-dirty").create(
        project_id=uuid4(),
        repository_path=repository,
        snapshot_id=uuid4(),
        manifest_artifact_id=uuid4(),
    )

    assert clean.snapshot.vcs_type is VcsType.GIT
    assert clean.snapshot.commit_sha is not None
    assert len(clean.snapshot.commit_sha) == 40
    assert clean.snapshot.dirty is False
    assert dirty.snapshot.commit_sha == clean.snapshot.commit_sha
    assert dirty.snapshot.dirty is True
    assert dirty.snapshot.tree_hash != clean.snapshot.tree_hash


def test_non_git_directory_is_recorded_without_commit(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("plain\n", encoding="utf-8")

    result = SnapshotService(tmp_path / "runs").create(
        project_id=uuid4(),
        repository_path=repository,
        snapshot_id=uuid4(),
        manifest_artifact_id=uuid4(),
    )

    assert result.snapshot.vcs_type is VcsType.DIRECTORY
    assert result.snapshot.commit_sha is None
    assert result.snapshot.dirty is False


def test_source_change_during_materialization_fails_and_cleans_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    source = repository / "app.py"
    source.write_text("before\n", encoding="utf-8")
    runs_root = tmp_path / "runs"
    snapshot_id = uuid4()

    def mutate_after_copy(
        repository_root: str | Path,
        snapshots_root: str | Path,
        current_snapshot_id: UUID,
        manifest: SnapshotManifest,
    ) -> tuple[Path, Path]:
        result = materialize_snapshot(
            repository_root,
            snapshots_root,
            current_snapshot_id,
            manifest,
        )
        source.write_text("after\n", encoding="utf-8")
        return result

    monkeypatch.setattr("argus.snapshots.service.materialize_snapshot", mutate_after_copy)

    with pytest.raises(SnapshotError, match="source changed"):
        SnapshotService(runs_root).create(
            project_id=uuid4(),
            repository_path=repository,
            snapshot_id=snapshot_id,
            manifest_artifact_id=uuid4(),
        )

    assert not (runs_root / "_data" / "snapshots" / str(snapshot_id)).exists()
