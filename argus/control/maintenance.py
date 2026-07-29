"""Recoverable Control Store and Artifact Store maintenance operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import shutil
import sqlite3

from sqlalchemy import select

from argus.control.db import Database
from argus.control.orm import ArtifactRow, VerificationEvidenceRow

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class DatabaseBackup:
    path: Path
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class ArtifactGcResult:
    referenced: int
    candidates: tuple[str, ...]
    quarantined: tuple[str, ...]
    quarantine_root: Path | None


def backup_database(source: str | Path, destination: str | Path) -> DatabaseBackup:
    """Create a transactionally consistent SQLite backup without overwriting."""
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if destination_path.exists():
        raise FileExistsError(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(source_path) as source_db:
            with sqlite3.connect(destination_path) as destination_db:
                source_db.backup(destination_db)
    except BaseException:
        destination_path.unlink(missing_ok=True)
        raise
    digest = hashlib.sha256()
    size = 0
    with destination_path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return DatabaseBackup(
        path=destination_path,
        size_bytes=size,
        sha256=digest.hexdigest(),
    )


def collect_artifact_garbage(
    database: Database,
    *,
    runs_root: str | Path = "runs",
    apply: bool = False,
    minimum_age: timedelta = timedelta(hours=24),
    now: datetime | None = None,
) -> ArtifactGcResult:
    """Mark unreferenced blobs and optionally move them to a recoverable quarantine."""
    if minimum_age < timedelta(0):
        raise ValueError("minimum_age must not be negative")
    root = Path(runs_root).resolve() / "_data" / "artifacts"
    content_root = root / "sha256"
    with database.session() as session:
        referenced = set(session.scalars(select(ArtifactRow.content_hash)).all())
        referenced.update(session.scalars(select(VerificationEvidenceRow.artifact_hash)).all())

    threshold = (now or datetime.now(timezone.utc)).timestamp() - minimum_age.total_seconds()
    candidates: list[tuple[str, Path]] = []
    if content_root.is_dir():
        resolved_content_root = content_root.resolve()
        for payload in sorted(content_root.glob("??/*/payload")):
            content_hash = payload.parent.name
            try:
                payload.resolve().relative_to(resolved_content_root)
            except ValueError:
                continue
            if (
                _SHA256.fullmatch(content_hash) is not None
                and content_hash[:2] == payload.parent.parent.name
                and content_hash not in referenced
                and not payload.is_symlink()
                and not payload.parent.is_symlink()
                and not payload.parent.parent.is_symlink()
                and payload.stat().st_mtime <= threshold
            ):
                candidates.append((content_hash, payload.parent))

    quarantine_root: Path | None = None
    quarantined: list[str] = []
    if apply and candidates:
        stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
        quarantine_root = root / ".trash" / stamp
        quarantine_root.mkdir(parents=True, exist_ok=False)
        for content_hash, source in candidates:
            destination = quarantine_root / content_hash
            shutil.move(str(source), destination)
            quarantined.append(content_hash)

    return ArtifactGcResult(
        referenced=len(referenced),
        candidates=tuple(content_hash for content_hash, _path in candidates),
        quarantined=tuple(quarantined),
        quarantine_root=quarantine_root,
    )
