"""SQLite persistence for the Argus API and worker processes."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Iterator
from uuid import uuid4

from .models import (
    FindingCreate,
    FindingResponse,
    ScanCreateRequest,
    ScanProgress,
    ScanResponse,
    ScanStatus,
    ServiceScanResult,
)


class ScanNotFound(LookupError):
    """The requested scan does not exist."""


class IdempotencyConflict(ValueError):
    """An idempotency key was reused with a different request."""


class LeaseLost(RuntimeError):
    """A worker attempted to update a scan it no longer owns."""


class ScanStateError(RuntimeError):
    """A state transition is not valid for the current scan."""


class QueueFull(RuntimeError):
    """The configured number of queued or running scans has been reached."""


class WorkerScan:
    """The immutable request data a worker needs after claiming a scan."""

    def __init__(
        self,
        *,
        id: str,
        repository_url: str,
        ref: str | None,
        commit_sha: str | None,
        include: tuple[str, ...],
        exclude: tuple[str, ...],
        background: str | None,
        attempt: int,
        cancel_requested: bool,
        lease_token: str | None = None,
    ) -> None:
        self.id = id
        self.repository_url = repository_url
        self.ref = ref
        self.commit_sha = commit_sha
        self.include = include
        self.exclude = exclude
        self.background = background
        self.attempt = attempt
        self.cancel_requested = cancel_requested
        self.lease_token = lease_token


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _request_hash(request: ScanCreateRequest) -> str:
    data = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _safe_error(value: str | None) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text[:2_000]


def resolve_scan_database() -> str | Path:
    """Resolve the shared API/worker SQLite path from one configuration point."""

    configured = os.getenv("ARGUS_SCAN_DB")
    if configured:
        if configured == ":memory:":
            return configured
        return Path(configured).expanduser().resolve()
    return Path(os.getenv("ARGUS_DATA_DIR", "data")).expanduser().resolve() / "service.sqlite3"


class ScanStore:
    """A small SQLite store shared by the API and one or more workers."""

    def __init__(self, database: str | Path, *, max_queue: int = 100) -> None:
        if max_queue < 1:
            raise ValueError("max_queue must be positive")
        self.database = str(database)
        self.max_queue = max_queue
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database,
            timeout=30,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 30000")
        if self.database != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            yield self._connection

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _initialize(self) -> None:
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE,
                    request_hash TEXT NOT NULL,
                    repository_url TEXT NOT NULL,
                    requested_ref TEXT,
                    include_json TEXT NOT NULL,
                    exclude_json TEXT NOT NULL,
                    background TEXT,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    commit_sha TEXT,
                    session_id TEXT,
                    coverage_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    attempt INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    worker_id TEXT,
                    lease_expires_at REAL,
                    heartbeat_at TEXT,
                    lease_token TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scans_queue
                    ON scans(status, created_at, lease_expires_at);
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT,
                    file TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    message TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan
                    ON findings(scan_id, severity, created_at, id);
                """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
            if "lease_token" not in columns:
                db.execute("ALTER TABLE scans ADD COLUMN lease_token TEXT")

    def ready(self) -> bool:
        with self._db() as db:
            db.execute("SELECT 1").fetchone()
        return True

    def create_scan(
        self,
        request: ScanCreateRequest,
        idempotency_key: str | None = None,
    ) -> tuple[ScanResponse, bool]:
        if idempotency_key is not None:
            if (
                not idempotency_key.strip()
                or len(idempotency_key) > 256
                or any(char in idempotency_key for char in "\x00\r\n")
            ):
                raise ValueError("Idempotency-Key must be a non-empty safe value")
            idempotency_key = idempotency_key.strip()
        request_hash = _request_hash(request)
        scan_id = uuid4().hex
        now = _stamp(_now())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if idempotency_key is not None:
                    existing = db.execute(
                        "SELECT * FROM scans WHERE idempotency_key = ?",
                        (idempotency_key,),
                    ).fetchone()
                    if existing is not None:
                        if existing["request_hash"] != request_hash:
                            db.rollback()
                            raise IdempotencyConflict("Idempotency-Key was already used for a different scan")
                        db.commit()
                        return self._scan_from_row(existing), False
                active = int(
                    db.execute(
                        "SELECT COUNT(*) FROM scans WHERE status IN (?, ?)",
                        (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value),
                    ).fetchone()[0]
                )
                if active >= self.max_queue:
                    db.rollback()
                    raise QueueFull("scan queue is full")
                db.execute(
                    """
                    INSERT INTO scans (
                        id, idempotency_key, request_hash, repository_url, requested_ref,
                        include_json, exclude_json, background, status, phase,
                        coverage_json, metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        idempotency_key,
                        request_hash,
                        request.repository_url,
                        request.ref,
                        json.dumps(request.include, ensure_ascii=False),
                        json.dumps(request.exclude, ensure_ascii=False),
                        request.background,
                        ScanStatus.QUEUED.value,
                        "queued",
                        json.dumps(ScanProgress().model_dump(mode="json")),
                        "{}",
                        now,
                        now,
                    ),
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        assert row is not None
        return self._scan_from_row(row), True

    def get_scan(self, scan_id: str) -> ScanResponse:
        with self._db() as db:
            row = db.execute(
                """
                SELECT s.*, COUNT(f.id) AS finding_count
                FROM scans AS s
                LEFT JOIN findings AS f ON f.scan_id = s.id
                WHERE s.id = ?
                GROUP BY s.id
                """,
                (scan_id,),
            ).fetchone()
        if row is None:
            raise ScanNotFound(scan_id)
        return self._scan_from_row(row)

    def list_scans(self, *, limit: int = 50, offset: int = 0) -> tuple[list[ScanResponse], int]:
        with self._db() as db:
            rows = db.execute(
                """
                SELECT s.*, COUNT(f.id) AS finding_count
                FROM scans AS s
                LEFT JOIN findings AS f ON f.scan_id = s.id
                GROUP BY s.id
                ORDER BY s.created_at DESC, s.id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            total = int(db.execute("SELECT COUNT(*) FROM scans").fetchone()[0])
        return [self._scan_from_row(row) for row in rows], total

    def list_findings(
        self,
        scan_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        category: str | None = None,
    ) -> tuple[list[FindingResponse], int]:
        self.get_scan(scan_id)
        clauses = ["scan_id = ?"]
        params: list[object] = [scan_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        if category:
            clauses.append("category = ?")
            params.append(category.lower())
        where = " AND ".join(clauses)
        with self._db() as db:
            rows = db.execute(
                f"SELECT * FROM findings WHERE {where} ORDER BY created_at, id LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            total = int(db.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", params).fetchone()[0])
        return [self._finding_from_row(row) for row in rows], total

    def claim_next(self, worker_id: str, *, lease_seconds: int = 300) -> WorkerScan | None:
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker_id and positive lease_seconds are required")
        now = _now()
        now_epoch = now.timestamp()
        lease_until = now_epoch + lease_seconds
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                expired = db.execute(
                    """
                    UPDATE scans
                    SET status = CASE WHEN cancel_requested = 1 THEN ? ELSE ? END,
                        phase = CASE WHEN cancel_requested = 1 THEN ? ELSE ? END,
                        finished_at = CASE WHEN cancel_requested = 1 THEN ? ELSE finished_at END,
                        worker_id = NULL, lease_expires_at = NULL, lease_token = NULL, updated_at = ?
                    WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?
                    """,
                    (
                        ScanStatus.CANCELED.value,
                        ScanStatus.QUEUED.value,
                        "canceled",
                        "queued",
                        _stamp(now),
                        _stamp(now),
                        ScanStatus.RUNNING.value,
                        now_epoch,
                    ),
                )
                del expired
                row = db.execute(
                    "SELECT * FROM scans WHERE status = ? ORDER BY created_at, id LIMIT 1",
                    (ScanStatus.QUEUED.value,),
                ).fetchone()
                if row is None:
                    db.commit()
                    return None
                db.execute(
                    """
                    UPDATE scans
                    SET status = ?, phase = ?, worker_id = ?, lease_expires_at = ?,
                        heartbeat_at = ?, lease_token = ?, attempt = attempt + 1,
                        started_at = COALESCE(started_at, ?), updated_at = ?, error = NULL
                    WHERE id = ? AND status = ?
                    """,
                    (
                        ScanStatus.RUNNING.value,
                        "preparing",
                        worker_id,
                        lease_until,
                        _stamp(now),
                        uuid4().hex,
                        _stamp(now),
                        _stamp(now),
                        row["id"],
                        ScanStatus.QUEUED.value,
                    ),
                )
                claimed = db.execute("SELECT * FROM scans WHERE id = ?", (row["id"],)).fetchone()
                db.commit()
            except Exception:
                db.rollback()
                raise
        assert claimed is not None
        return self._worker_from_row(claimed)

    def set_phase(self, scan_id: str, worker_id: str, phase: str, *, lease_token: str | None = None) -> None:
        self._owned_update(
            scan_id,
            worker_id,
            "phase = ?, updated_at = ?",
            (phase, _stamp(_now())),
            lease_token=lease_token,
        )

    def record_commit(self, scan_id: str, worker_id: str, commit_sha: str, *, lease_token: str | None = None) -> None:
        if not commit_sha or any(char not in "0123456789abcdef" for char in commit_sha.lower()):
            raise ValueError("commit_sha must be hexadecimal")
        self._owned_update(
            scan_id,
            worker_id,
            "commit_sha = ?, updated_at = ?",
            (commit_sha, _stamp(_now())),
            lease_token=lease_token,
        )

    def heartbeat(
        self,
        scan_id: str,
        worker_id: str,
        *,
        lease_seconds: int = 300,
        progress: ScanProgress | None = None,
        lease_token: str | None = None,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        now = _now()
        assignments = "lease_expires_at = ?, heartbeat_at = ?, updated_at = ?"
        values: list[object] = [now.timestamp() + lease_seconds, _stamp(now), _stamp(now)]
        if progress is not None:
            assignments += ", coverage_json = ?"
            values.append(json.dumps(progress.model_dump(mode="json"), ensure_ascii=False))
        values.extend((scan_id, worker_id, ScanStatus.RUNNING.value))
        where = "id = ? AND worker_id = ? AND status = ?"
        if lease_token is not None:
            where += " AND lease_token = ?"
            values.append(lease_token)
        with self._db() as db:
            cursor = db.execute(
                f"UPDATE scans SET {assignments} WHERE {where}",
                values,
            )
        if cursor.rowcount != 1:
            raise LeaseLost(scan_id)

    def is_cancel_requested(self, scan_id: str) -> bool:
        with self._db() as db:
            row = db.execute("SELECT cancel_requested FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise ScanNotFound(scan_id)
        return bool(row[0])

    def finish(
        self,
        scan_id: str,
        worker_id: str,
        result: ServiceScanResult,
        *,
        lease_token: str | None = None,
    ) -> ScanResponse:
        now = _stamp(_now())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                self._require_owned_row(row, worker_id, lease_token)
                assert row is not None
                if row["cancel_requested"]:
                    db.execute(
                        """
                        UPDATE scans SET status = ?, phase = ?, finished_at = ?, updated_at = ?,
                            worker_id = NULL, lease_expires_at = NULL, lease_token = NULL
                        WHERE id = ?
                        """,
                        (ScanStatus.CANCELED.value, "canceled", now, now, scan_id),
                    )
                    db.commit()
                    return self.get_scan(scan_id)

                if result.status not in {
                    ScanStatus.COMPLETED,
                    ScanStatus.PARTIAL,
                    ScanStatus.FAILED,
                    ScanStatus.SKIPPED,
                }:
                    raise ValueError("invalid terminal worker result status")
                db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                for finding in result.findings:
                    self._insert_finding(db, scan_id, finding, now)
                progress = ScanProgress(
                    total_files=result.total_files,
                    reviewed_files=result.reviewed_files,
                    failed_files=result.failed_files,
                    skipped_files=result.skipped_files,
                    percent=100
                    if result.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.SKIPPED}
                    else 0,
                )
                query = """
                    UPDATE scans
                    SET status = ?, phase = ?, commit_sha = COALESCE(?, commit_sha), session_id = ?,
                        coverage_json = ?, metadata_json = ?, finding_count = ?, error = ?,
                        finished_at = ?, updated_at = ?, worker_id = NULL, lease_expires_at = NULL,
                        lease_token = NULL
                    WHERE id = ? AND status = ? AND worker_id = ?
                """
                parameters: list[object] = [
                    result.status.value,
                    result.status.value,
                    result.commit_sha,
                    result.session_id,
                    json.dumps(progress.model_dump(mode="json"), ensure_ascii=False),
                    json.dumps(result.metadata, ensure_ascii=False, default=str),
                    len(result.findings),
                    _safe_error(result.error),
                    now,
                    now,
                    scan_id,
                    ScanStatus.RUNNING.value,
                    worker_id,
                ]
                if lease_token is not None:
                    query = query.rstrip() + " AND lease_token = ?"
                    parameters.append(lease_token)
                cursor = db.execute(query, parameters)
                if cursor.rowcount != 1:
                    raise LeaseLost(scan_id)
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        return self.get_scan(scan_id)

    def fail(self, scan_id: str, worker_id: str, error: str, *, lease_token: str | None = None) -> ScanResponse:
        result = ServiceScanResult(status=ScanStatus.FAILED, error=_safe_error(error))
        return self.finish(scan_id, worker_id, result, lease_token=lease_token)

    def cancel(self, scan_id: str) -> ScanResponse:
        now = _stamp(_now())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                db.rollback()
                raise ScanNotFound(scan_id)
            current = ScanStatus(row["status"])
            if current is ScanStatus.QUEUED:
                db.execute(
                    "UPDATE scans SET status = ?, phase = ?, finished_at = ?, updated_at = ? WHERE id = ?",
                    (ScanStatus.CANCELED.value, "canceled", now, now, scan_id),
                )
            elif current is ScanStatus.RUNNING:
                db.execute(
                    "UPDATE scans SET cancel_requested = 1, phase = ?, updated_at = ? WHERE id = ?",
                    ("cancel_requested", now, scan_id),
                )
            elif current in {
                ScanStatus.COMPLETED,
                ScanStatus.PARTIAL,
                ScanStatus.FAILED,
                ScanStatus.CANCELED,
                ScanStatus.SKIPPED,
            }:
                pass
            else:
                db.rollback()
                raise ScanStateError(f"cannot cancel scan in state {current.value}")
            db.commit()
        return self.get_scan(scan_id)

    def retry(self, scan_id: str) -> ScanResponse:
        now = _stamp(_now())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                db.rollback()
                raise ScanNotFound(scan_id)
            current = ScanStatus(row["status"])
            if current not in {
                ScanStatus.PARTIAL,
                ScanStatus.FAILED,
                ScanStatus.CANCELED,
                ScanStatus.SKIPPED,
            }:
                db.rollback()
                raise ScanStateError("only terminal failed, partial, canceled, or skipped scans can retry")
            db.execute(
                """
                UPDATE scans SET status = ?, phase = ?, coverage_json = ?,
                    cancel_requested = 0, worker_id = NULL, lease_expires_at = NULL,
                    heartbeat_at = NULL, lease_token = NULL, session_id = NULL, error = NULL,
                    finding_count = 0, updated_at = ?, finished_at = NULL
                WHERE id = ?
                """,
                (
                    ScanStatus.QUEUED.value,
                    "queued",
                    json.dumps(ScanProgress().model_dump(mode="json"), ensure_ascii=False),
                    now,
                    scan_id,
                ),
            )
            db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            db.commit()
        return self.get_scan(scan_id)

    def _owned_update(
        self,
        scan_id: str,
        worker_id: str,
        assignments: str,
        values: tuple[object, ...],
        *,
        lease_token: str | None = None,
    ) -> None:
        where = "id = ? AND worker_id = ? AND status = ?"
        parameters: list[object] = [*values, scan_id, worker_id, ScanStatus.RUNNING.value]
        if lease_token is not None:
            where += " AND lease_token = ?"
            parameters.append(lease_token)
        with self._db() as db:
            cursor = db.execute(
                f"UPDATE scans SET {assignments} WHERE {where}",
                parameters,
            )
        if cursor.rowcount != 1:
            raise LeaseLost(scan_id)

    @staticmethod
    def _require_owned_row(row: sqlite3.Row | None, worker_id: str, lease_token: str | None = None) -> None:
        if row is None:
            raise ScanNotFound("scan")
        if (
            row["status"] != ScanStatus.RUNNING.value
            or row["worker_id"] != worker_id
            or (lease_token is not None and row["lease_token"] != lease_token)
        ):
            raise LeaseLost(row["id"])

    @staticmethod
    def _insert_finding(db: sqlite3.Connection, scan_id: str, finding: FindingCreate, timestamp: str | None) -> None:
        data = finding.model_dump(mode="json")
        fingerprint_value = finding.metadata.get("fingerprint")
        fingerprint = (
            fingerprint_value
            if isinstance(fingerprint_value, str) and fingerprint_value
            else hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
            ).hexdigest()
        )
        finding_id = hashlib.sha256(f"{scan_id}:{fingerprint}".encode("utf-8")).hexdigest()[:32]
        db.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, scan_id, fingerprint, rule_id, title, category, severity, confidence,
                file, start_line, end_line, message, evidence, remediation, metadata_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                scan_id,
                fingerprint,
                finding.rule_id,
                finding.title,
                finding.category,
                finding.severity,
                finding.confidence,
                finding.file,
                finding.start_line,
                finding.end_line,
                finding.message,
                finding.evidence,
                finding.remediation,
                json.dumps(finding.metadata, ensure_ascii=False, default=str),
                timestamp,
            ),
        )

    @staticmethod
    def _progress(row: sqlite3.Row) -> ScanProgress:
        try:
            value = json.loads(row["coverage_json"])
            if isinstance(value, dict):
                return ScanProgress.model_validate(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        return ScanProgress()

    @classmethod
    def _scan_from_row(cls, row: sqlite3.Row) -> ScanResponse:
        def parsed(name: str) -> datetime | None:
            return datetime.fromisoformat(row[name]) if row[name] else None

        try:
            metadata = json.loads(row["metadata_json"])
            if not isinstance(metadata, dict):
                metadata = {}
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        return ScanResponse(
            id=row["id"],
            repository_url=row["repository_url"],
            ref=row["requested_ref"],
            commit_sha=row["commit_sha"],
            include=list(json.loads(row["include_json"])),
            exclude=list(json.loads(row["exclude_json"])),
            background=row["background"],
            status=ScanStatus(row["status"]),
            phase=row["phase"],
            progress=cls._progress(row),
            finding_count=int(row["finding_count"]),
            attempt=int(row["attempt"]),
            idempotency_key=row["idempotency_key"],
            session_id=row["session_id"],
            metadata=metadata,
            error=row["error"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            started_at=parsed("started_at"),
            finished_at=parsed("finished_at"),
        )

    @staticmethod
    def _finding_from_row(row: sqlite3.Row) -> FindingResponse:
        try:
            metadata = json.loads(row["metadata_json"])
            if not isinstance(metadata, dict):
                metadata = {}
        except (TypeError, ValueError, json.JSONDecodeError):
            metadata = {}
        return FindingResponse(
            id=row["id"],
            scan_id=row["scan_id"],
            rule_id=row["rule_id"],
            title=row["title"],
            category=row["category"],
            severity=row["severity"],
            confidence=row["confidence"],
            file=row["file"],
            start_line=row["start_line"],
            end_line=row["end_line"],
            message=row["message"],
            evidence=row["evidence"],
            remediation=row["remediation"],
            metadata=metadata,
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _worker_from_row(row: sqlite3.Row) -> WorkerScan:
        return WorkerScan(
            id=row["id"],
            repository_url=row["repository_url"],
            ref=row["requested_ref"],
            commit_sha=row["commit_sha"],
            include=tuple(json.loads(row["include_json"])),
            exclude=tuple(json.loads(row["exclude_json"])),
            background=row["background"],
            attempt=int(row["attempt"]),
            cancel_requested=bool(row["cancel_requested"]),
            lease_token=row["lease_token"],
        )
