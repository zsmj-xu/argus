"""Atomic full-copy materialization for source snapshots."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from uuid import UUID

from argus.domain.errors import SnapshotError
from argus.domain.hashing import canonical_json_bytes
from argus.snapshots.hashing import SnapshotManifest, hash_file


def _write_manifest(path: Path, manifest: SnapshotManifest) -> None:
    data = canonical_json_bytes(manifest)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def materialize_snapshot(
    repository_root: str | Path,
    snapshots_root: str | Path,
    snapshot_id: UUID,
    manifest: SnapshotManifest,
) -> tuple[Path, Path]:
    source_root = Path(repository_root).resolve()
    storage_root = Path(snapshots_root).resolve()
    storage_root.mkdir(parents=True, exist_ok=True)
    destination = storage_root / str(snapshot_id)
    if destination.exists():
        raise SnapshotError(f"snapshot destination already exists: {destination}")

    temporary = Path(tempfile.mkdtemp(prefix=f".{snapshot_id}.", dir=storage_root))
    materialized_source = temporary / "source"
    materialized_source.mkdir()
    try:
        directory_entries = [entry for entry in manifest.entries if entry.type == "directory"]
        for entry in directory_entries:
            (materialized_source / entry.path).mkdir(parents=True, exist_ok=False)

        for entry in manifest.entries:
            source = source_root / entry.path
            target = materialized_source / entry.path
            if entry.type == "file":
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target, follow_symlinks=False)
                copied_hash, copied_size = hash_file(target)
                if copied_hash != entry.content_hash or copied_size != entry.size:
                    raise SnapshotError(f"source changed while snapshot was copied: {entry.path}")
            elif entry.type == "symlink":
                if entry.link_target is None:
                    raise SnapshotError(f"manifest symlink has no target: {entry.path}")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(entry.link_target, target)

        for entry in reversed(directory_entries):
            os.chmod(materialized_source / entry.path, entry.mode)

        manifest_path = temporary / "snapshot-manifest.json"
        _write_manifest(manifest_path, manifest)
        os.replace(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return destination / "source", destination / "snapshot-manifest.json"
