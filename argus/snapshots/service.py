"""High-level immutable SourceSnapshot creation."""

from __future__ import annotations

import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from argus.domain.enums import VcsType
from argus.domain.errors import SnapshotError
from argus.domain.models import SourceSnapshot
from argus.snapshots.hashing import SnapshotManifest, build_manifest
from argus.snapshots.ignore import IgnoreMatcher
from argus.snapshots.materialize import materialize_snapshot


@dataclass(frozen=True)
class SnapshotResult:
    snapshot: SourceSnapshot
    manifest: SnapshotManifest
    manifest_path: Path


def _git_output(repository: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def git_identity(repository: str | Path) -> tuple[VcsType, str | None, bool]:
    root = Path(repository).resolve()
    inside = _git_output(root, "rev-parse", "--is-inside-work-tree")
    if inside != "true":
        return VcsType.DIRECTORY, None, False
    commit_sha = _git_output(root, "rev-parse", "HEAD")
    status = _git_output(root, "status", "--porcelain=v1", "--untracked-files=all")
    return VcsType.GIT, commit_sha, bool(status)


class SnapshotService:
    def __init__(self, runs_root: str | Path = "runs") -> None:
        self.runs_root = Path(runs_root).resolve()
        self.snapshots_root = self.runs_root / "_data" / "snapshots"

    def create(
        self,
        *,
        project_id: UUID,
        repository_path: str | Path,
        snapshot_id: UUID,
        manifest_artifact_id: UUID,
        ignore: list[str] | None = None,
        vcs_identity: tuple[VcsType, str | None, bool] | None = None,
    ) -> SnapshotResult:
        repository = Path(repository_path).resolve()
        matcher = IgnoreMatcher(repository, runs_root=self.runs_root, custom_patterns=ignore)
        vcs_type, commit_sha, dirty = vcs_identity or git_identity(repository)
        manifest = build_manifest(repository, matcher)
        source_path, manifest_path = materialize_snapshot(
            repository,
            self.snapshots_root,
            snapshot_id,
            manifest,
        )
        current_manifest = build_manifest(repository, matcher)
        current_vcs_type, current_commit_sha, _current_dirty = git_identity(repository)
        if current_manifest.tree_hash != manifest.tree_hash or (
            current_vcs_type is VcsType.GIT and (vcs_type is not VcsType.GIT or current_commit_sha != commit_sha)
        ):
            shutil.rmtree(source_path.parent)
            raise SnapshotError("source changed while snapshot was being materialized")
        snapshot = SourceSnapshot(
            id=snapshot_id,
            project_id=project_id,
            repository_path=str(repository),
            vcs_type=vcs_type,
            commit_sha=commit_sha,
            tree_hash=manifest.tree_hash,
            dirty=dirty,
            materialized_path=str(source_path),
            manifest_artifact_id=manifest_artifact_id,
        )
        return SnapshotResult(snapshot=snapshot, manifest=manifest, manifest_path=manifest_path)
