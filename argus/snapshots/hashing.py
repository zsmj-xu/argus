"""Source tree enumeration and deterministic manifest hashing."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from argus.domain.errors import SnapshotError
from argus.domain.hashing import sha256_digest
from argus.snapshots.ignore import IgnoreMatcher

_CHUNK_SIZE = 1024 * 1024
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


class ManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    type: Literal["file", "directory", "symlink"]
    size: int = Field(ge=0)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mode: int = Field(ge=0)
    link_target: str | None = None


class SnapshotManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    tree_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entries: list[ManifestEntry]


def hash_file(path: str | Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _safe_symlink_target(root: Path, path: Path) -> str:
    target = os.readlink(path)
    resolved = (path.parent / target).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SnapshotError(f"symlink escapes repository: {path} -> {target}") from exc
    return target


def build_manifest(repository_root: str | Path, matcher: IgnoreMatcher) -> SnapshotManifest:
    root = Path(repository_root).resolve()
    if not root.is_dir():
        raise SnapshotError(f"snapshot source is not a directory: {root}")

    entries: list[ManifestEntry] = []

    def visit(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise SnapshotError(f"cannot enumerate snapshot source: {directory}: {exc}") from exc
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SnapshotError(f"cannot stat snapshot source entry: {relative}: {exc}") from exc
            mode = stat.S_IMODE(info.st_mode)
            if child.is_symlink():
                if matcher.ignores(relative, is_directory=False):
                    continue
                target = _safe_symlink_target(root, path)
                target_bytes = target.encode("utf-8")
                entries.append(
                    ManifestEntry(
                        path=relative,
                        type="symlink",
                        size=len(target_bytes),
                        content_hash=hashlib.sha256(target_bytes).hexdigest(),
                        mode=mode,
                        link_target=target,
                    )
                )
            elif child.is_dir(follow_symlinks=False):
                if matcher.ignores(relative, is_directory=True):
                    continue
                entries.append(
                    ManifestEntry(
                        path=relative,
                        type="directory",
                        size=0,
                        content_hash=_EMPTY_HASH,
                        mode=mode,
                    )
                )
                visit(path)
            elif child.is_file(follow_symlinks=False):
                if matcher.ignores(relative, is_directory=False):
                    continue
                content_hash, size = hash_file(path)
                entries.append(
                    ManifestEntry(
                        path=relative,
                        type="file",
                        size=size,
                        content_hash=content_hash,
                        mode=mode,
                    )
                )
            else:
                raise SnapshotError(f"unsupported source entry type: {relative}")

    visit(root)
    canonical_entries = [cast(JsonValue, entry.model_dump(mode="json")) for entry in entries]
    return SnapshotManifest(tree_hash=sha256_digest({"entries": canonical_entries}), entries=entries)
