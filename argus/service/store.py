"""SQLite persistence for the Argus API and worker processes."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterator, Mapping
from uuid import uuid4

from .models import (
    FindingCreate,
    FindingResponse,
    ScanCreateRequest,
    ScanDiagnosticsResponse,
    ScanEvent,
    ScanProgress,
    ScanResponse,
    ScanStatus,
    ServiceScanResult,
)
from .observability import (
    DEFAULT_ACTIVITY_STALE_SECONDS,
    DEFAULT_ACTIVITY_WARN_SECONDS,
    DEFAULT_EVENT_ESSENTIAL_RESERVE,
    DEFAULT_EVENT_LIMIT,
    DEFAULT_EVENT_RETENTION_DAYS,
    StructuredEventUpdate,
    build_observation,
    event_is_essential,
    has_actual_output_activity,
    log_stored_event,
    sanitize_event,
    sanitize_repository_url,
    structured_event_update,
)


_SCHEMA_VERSION = 2
_EVENT_CLEANUP_BATCH = 1_000
_EVENT_EXPORT_LIMIT = 2_000


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


def _positive_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        return default
    return value if value > 0 else default


_GENERIC_ERROR_CODES = frozenset(
    {
        "scan_failed",
        "scan_partial",
        "scan_completed",
        "scan_skipped",
        "scan_canceled",
        "cancel_completed",
        "worker_unknown",
        "event_recorded",
    }
)


def _should_replace_error(current_code: object, new_code: object) -> bool:
    current = str(current_code or "")
    new = str(new_code or "")
    if not current:
        return True
    if current not in _GENERIC_ERROR_CODES and new in _GENERIC_ERROR_CODES:
        return False
    return True


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
        self.event_limit = _positive_env_int("ARGUS_EVENT_LIMIT", DEFAULT_EVENT_LIMIT)
        self.event_retention_days = _positive_env_int("ARGUS_EVENT_RETENTION_DAYS", DEFAULT_EVENT_RETENTION_DAYS)
        self.activity_warn_seconds = _positive_env_int("ARGUS_ACTIVITY_WARN_SECONDS", DEFAULT_ACTIVITY_WARN_SECONDS)
        self.activity_stale_seconds = _positive_env_int("ARGUS_ACTIVITY_STALE_SECONDS", DEFAULT_ACTIVITY_STALE_SECONDS)
        self.event_essential_reserve = min(DEFAULT_EVENT_ESSENTIAL_RESERVE, max(1, self.event_limit // 100))
        self._last_cleanup_monotonic = 0.0
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
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
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
                    )
                    """
                )
                db.execute(
                    """
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
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_scans_queue ON scans(status, created_at, lease_expires_at)")
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity, created_at, id)"
                )

                columns = {row[1] for row in db.execute("PRAGMA table_info(scans)").fetchall()}
                additive_columns = {
                    "lease_token": "TEXT",
                    "phase_started_at": "TEXT",
                    "process_deadline_at": "TEXT",
                    "last_output_at": "TEXT",
                    "last_progress_at": "TEXT",
                    "capabilities_json": 'TEXT NOT NULL DEFAULT \'{"file_progress": false, "llm_requests": false, "event_protocol": false}\'',
                    "coverage_observation_json": "TEXT NOT NULL DEFAULT '{}'",
                    "history_available": "INTEGER NOT NULL DEFAULT 0",
                    "event_count": "INTEGER NOT NULL DEFAULT 0",
                    "event_dropped_count": "INTEGER NOT NULL DEFAULT 0",
                    "event_truncated_count": "INTEGER NOT NULL DEFAULT 0",
                    "event_expired_count": "INTEGER NOT NULL DEFAULT 0",
                    "last_error_code": "TEXT",
                    "last_error_message": "TEXT",
                    "last_error_retryable": "INTEGER",
                    "last_error_suggestion": "TEXT",
                    "last_error_source": "TEXT",
                }
                for name, definition in additive_columns.items():
                    if name not in columns:
                        db.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")

                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        attempt INTEGER NOT NULL,
                        worker_id TEXT,
                        source TEXT,
                        type TEXT NOT NULL,
                        stage TEXT,
                        level TEXT,
                        code TEXT,
                        message TEXT,
                        data_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        essential INTEGER NOT NULL DEFAULT 0,
                        truncated INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_event_attempts (
                        scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                        attempt INTEGER NOT NULL,
                        normal_count INTEGER NOT NULL DEFAULT 0,
                        essential_count INTEGER NOT NULL DEFAULT 0,
                        dropped_count INTEGER NOT NULL DEFAULT 0,
                        truncated_count INTEGER NOT NULL DEFAULT 0,
                        marker_cursor INTEGER,
                        PRIMARY KEY (scan_id, attempt)
                    )
                    """
                )
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_scan_cursor ON scan_events(scan_id, id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_attempt ON scan_events(scan_id, attempt, id)")
                db.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_retention ON scan_events(created_at, id)")
                db.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

    def ready(self) -> bool:
        self._maybe_cleanup_events()
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
        committed_events: list[dict[str, Any]] = []
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
                        coverage_json, metadata_json, phase_started_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        now,
                    ),
                )
                committed_events.append(
                    self._append_event_db(
                        db,
                        scan_id,
                        attempt=0,
                        worker_id=None,
                        event={
                            "source": "api",
                            "type": "scan.created",
                            "stage": "queued",
                            "level": "info",
                            "code": "scan_created",
                            "message": "Scan accepted and queued.",
                        },
                        timestamp=now,
                    )
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
            row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        assert row is not None
        self._log_events(committed_events)
        return self._scan_from_row(row), True

    def get_scan(self, scan_id: str) -> ScanResponse:
        self._maybe_cleanup_events()
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
        self._maybe_cleanup_events()
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

    def append_event(
        self,
        scan_id: str,
        worker_id: str,
        event: dict[str, Any],
        *,
        lease_token: str,
    ) -> dict[str, Any]:
        """Append one immutable, fenced event for the current worker attempt."""

        if not worker_id or not isinstance(lease_token, str) or not lease_token.strip():
            raise LeaseLost(scan_id)
        # Validate before opening the transaction so malformed input cannot
        # partially mutate counters or scan state.
        sanitize_event(event)
        now = _stamp(_now())
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                self._require_owned_row(row, worker_id, lease_token)
                assert row is not None
                appended = self._append_event_db(
                    db,
                    scan_id,
                    attempt=int(row["attempt"]),
                    worker_id=worker_id,
                    event=event,
                    timestamp=now,
                )
                committed_events.append(appended)
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)
        return appended

    def list_events(self, scan_id: str, *, after: int = 0, limit: int = 100) -> dict[str, object]:
        """Read immutable events after an integer cursor."""

        if isinstance(after, bool) or after < 0:
            raise ValueError("after must be a non-negative integer")
        if isinstance(limit, bool) or limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        self._maybe_cleanup_events()
        with self._db() as db:
            scan_exists = db.execute(
                "SELECT event_expired_count, event_dropped_count FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if scan_exists is None:
                raise ScanNotFound(scan_id)
            rows = db.execute(
                "SELECT * FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id LIMIT ?",
                (scan_id, after, limit + 1),
            ).fetchall()
            oldest = db.execute("SELECT MIN(id) FROM scan_events WHERE scan_id = ?", (scan_id,)).fetchone()[0]
        has_more = len(rows) > limit
        visible = rows[:limit]
        items = [self._event_from_row(row) for row in visible]
        next_cursor = int(items[-1]["cursor"]) if items else after
        return {
            "items": items,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "oldest_cursor": oldest,
            "history_truncated": bool(scan_exists["event_expired_count"] or scan_exists["event_dropped_count"]),
            "expired_event_count": int(scan_exists["event_expired_count"]),
        }

    def get_diagnostics(self, scan_id: str, *, recent_limit: int = 20) -> ScanDiagnosticsResponse:
        if isinstance(recent_limit, bool) or recent_limit < 1 or recent_limit > 100:
            raise ValueError("recent_limit must be between 1 and 100")
        self._maybe_cleanup_events()
        scan = self.get_scan(scan_id)
        with self._db() as db:
            rows = db.execute(
                """
                SELECT * FROM scan_events
                WHERE scan_id = ? AND (
                    lower(coalesce(level, '')) IN ('warning', 'error', 'critical')
                    OR lower(type) LIKE '%error%'
                    OR lower(type) LIKE '%failed%'
                )
                ORDER BY id DESC
                LIMIT ?
                """,
                (scan_id, recent_limit),
            ).fetchall()
        recent_errors = [ScanEvent.model_validate(self._event_from_row(row)) for row in reversed(rows)]
        all_events = self.list_events(scan_id, after=0, limit=500)
        evidence: list[dict[str, Any]] = []
        suggestions: list[str] = []
        all_event_items = all_events.get("items", [])
        if not isinstance(all_event_items, list):
            all_event_items = []
        for item in all_event_items:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            evidence_item = {
                "event_id": item.get("event_id"),
                "timestamp": item.get("timestamp"),
                "stage": item.get("stage"),
                "code": item.get("code"),
                "data": data if isinstance(data, dict) else {},
            }
            if evidence_item["code"] or evidence_item["data"]:
                evidence.append(evidence_item)
            suggestion = self._suggestion_for_event(item)
            if suggestion and suggestion not in suggestions:
                suggestions.append(suggestion)
        summary = {
            "status": scan.status.value,
            "stage": scan.observation.stage,
            "attempt": scan.attempt,
            "event_count": scan.observation.event_count,
            "dropped_event_count": scan.observation.dropped_event_count,
            "truncated_event_count": scan.observation.truncated_event_count,
            "history_available": scan.observation.history_available,
            "report_ready": scan.observation.report_ready,
        }
        return ScanDiagnosticsResponse(
            scan_id=scan_id,
            observation=scan.observation,
            summary=summary,
            recent_errors=recent_errors,
            evidence=evidence,
            suggestions=suggestions,
        )

    def export_diagnostics(self, scan_id: str) -> dict[str, object]:
        """Return a sanitized bounded diagnostics document for attachment export."""

        diagnostics = self.get_diagnostics(scan_id)
        scan = self.get_scan(scan_id)
        event_page = self.list_events(scan_id, after=0, limit=min(self.event_limit, _EVENT_EXPORT_LIMIT, 500))
        return {
            "schema_version": 1,
            "scan_id": scan.id,
            "repository_url": sanitize_repository_url(scan.repository_url),
            "ref": scan.ref,
            "commit_sha": scan.commit_sha,
            "status": scan.status.value,
            "phase": scan.phase,
            "attempt": scan.attempt,
            "observation": diagnostics.observation.model_dump(mode="json"),
            "summary": diagnostics.summary,
            "recent_errors": [item.model_dump(mode="json") for item in diagnostics.recent_errors],
            "evidence": diagnostics.evidence,
            "suggestions": diagnostics.suggestions,
            "events": event_page["items"],
            "events_next_cursor": event_page["next_cursor"],
            "events_truncated": bool(event_page["has_more"] or event_page["history_truncated"]),
            "expired_event_count": event_page["expired_event_count"],
        }

    def cleanup_events(self, *, now: datetime | None = None, max_events: int = _EVENT_CLEANUP_BATCH) -> int:
        """Delete at most one bounded batch of events older than the retention window."""

        if isinstance(max_events, bool) or max_events < 1 or max_events > _EVENT_CLEANUP_BATCH:
            raise ValueError(f"max_events must be between 1 and {_EVENT_CLEANUP_BATCH}")
        reference = now or _now()
        cutoff = _stamp(reference - timedelta(days=self.event_retention_days))
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                rows = db.execute(
                    "SELECT id, scan_id FROM scan_events WHERE created_at < ? ORDER BY id LIMIT ?",
                    (cutoff, max_events),
                ).fetchall()
                if not rows:
                    db.commit()
                    return 0
                event_ids = [int(row["id"]) for row in rows]
                scan_ids = {str(row["scan_id"]) for row in rows}
                placeholders = ",".join("?" for _ in event_ids)
                db.execute(f"DELETE FROM scan_events WHERE id IN ({placeholders})", event_ids)
                for affected_scan_id in scan_ids:
                    expired_count = sum(1 for row in rows if row["scan_id"] == affected_scan_id)
                    db.execute(
                        "UPDATE scans SET event_count = (SELECT COUNT(*) FROM scan_events WHERE scan_id = ?), "
                        "event_expired_count = event_expired_count + ? WHERE id = ?",
                        (affected_scan_id, expired_count, affected_scan_id),
                    )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        return len(event_ids)

    def _maybe_cleanup_events(self) -> None:
        current = time.monotonic()
        if current - self._last_cleanup_monotonic < 60:
            return
        self.cleanup_events()
        self._last_cleanup_monotonic = current

    def _append_event_db(
        self,
        db: sqlite3.Connection,
        scan_id: str,
        *,
        attempt: int,
        worker_id: str | None,
        event: Mapping[str, Any],
        timestamp: str | None,
    ) -> dict[str, Any]:
        essential = event_is_essential(event)
        safe = sanitize_event(event)
        db.execute(
            """
            INSERT INTO scan_event_attempts (scan_id, attempt)
            VALUES (?, ?)
            ON CONFLICT(scan_id, attempt) DO NOTHING
            """,
            (scan_id, attempt),
        )
        counter = db.execute(
            "SELECT * FROM scan_event_attempts WHERE scan_id = ? AND attempt = ?",
            (scan_id, attempt),
        ).fetchone()
        assert counter is not None
        total_count = int(counter["normal_count"]) + int(counter["essential_count"])
        terminal = str(safe.get("type")) in {
            "scan.completed",
            "scan.partial",
            "scan.failed",
            "scan.canceled",
            "scan.skipped",
        }
        # Reserve a final slot for the authoritative terminal event, plus one
        # truncation marker. Essential errors can use the normal-event budget;
        # the reserve is not a hard cap on the number of errors in a scan.
        normal_limit = max(0, self.event_limit - self.event_essential_reserve - 2)
        over_limit = (
            total_count >= self.event_limit
            if terminal
            else total_count >= max(0, self.event_limit - 2)
            or (not essential and int(counter["normal_count"]) >= normal_limit)
        )
        if over_limit:
            dropped_count = int(counter["dropped_count"]) + 1
            db.execute(
                """
                UPDATE scan_event_attempts SET dropped_count = ?
                WHERE scan_id = ? AND attempt = ?
                """,
                (dropped_count, scan_id, attempt),
            )
            db.execute(
                "UPDATE scans SET event_dropped_count = event_dropped_count + 1 WHERE id = ?",
                (scan_id,),
            )
            marker_cursor = counter["marker_cursor"]
            if marker_cursor is None and total_count < self.event_limit - 1:
                marker_safe = sanitize_event(
                    {
                        "source": "store",
                        "type": "observability.truncated",
                        "stage": safe.get("stage"),
                        "level": "warning",
                        "code": "event_limit",
                        "data": {
                            "dropped_count": dropped_count,
                            "truncated": True,
                        },
                    }
                )
                marker = self._insert_event_row(
                    db,
                    scan_id,
                    attempt=attempt,
                    worker_id=worker_id,
                    event=marker_safe,
                    timestamp=timestamp,
                    essential=True,
                )
                marker_cursor = marker["cursor"]
                db.execute(
                    """
                    UPDATE scan_event_attempts
                    SET essential_count = essential_count + 1, marker_cursor = ?
                    WHERE scan_id = ? AND attempt = ?
                    """,
                    (marker_cursor, scan_id, attempt),
                )
                self._record_accepted_event_db(db, scan_id, marker_safe, timestamp, truncated=True)
                # Structured logs reference only committed IDs. The caller
                # emits this marker after the surrounding transaction commits.
                safe_marker = marker
            else:
                safe_marker = None
            self._project_event_db(db, scan_id, safe, timestamp)
            dropped_data = dict(safe.get("data") or {})
            dropped_data.update({"truncated": True, "dropped_count": dropped_count})
            safe["data"] = dropped_data
            dropped = self._event_envelope(
                safe,
                scan_id=scan_id,
                attempt=attempt,
                event_id=None,
                timestamp=timestamp,
                truncated=True,
                accepted=False,
                dropped=True,
            )
            if safe_marker is not None:
                dropped["_committed_marker"] = safe_marker
            return dropped

        truncated = bool((safe.get("data") or {}).get("truncated"))
        stored = self._insert_event_row(
            db,
            scan_id,
            attempt=attempt,
            worker_id=worker_id,
            event=safe,
            timestamp=timestamp,
            essential=essential,
            truncated=truncated,
        )
        db.execute(
            f"""
            UPDATE scan_event_attempts
            SET {"essential_count" if essential else "normal_count"} = {"essential_count" if essential else "normal_count"} + 1,
                truncated_count = truncated_count + ?
            WHERE scan_id = ? AND attempt = ?
            """,
            (1 if truncated else 0, scan_id, attempt),
        )
        self._record_accepted_event_db(db, scan_id, safe, timestamp, truncated=truncated)
        return stored

    def _insert_event_row(
        self,
        db: sqlite3.Connection,
        scan_id: str,
        *,
        attempt: int,
        worker_id: str | None,
        event: Mapping[str, Any],
        timestamp: str | None,
        essential: bool,
        truncated: bool = False,
    ) -> dict[str, Any]:
        data = event.get("data")
        data_object = data if isinstance(data, dict) else {}
        cursor = db.execute(
            """
            INSERT INTO scan_events (
                scan_id, attempt, worker_id, source, type, stage, level, code,
                message, data_json, created_at, essential, truncated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                attempt,
                worker_id,
                event.get("source"),
                event["type"],
                event.get("stage"),
                event.get("level"),
                event.get("code"),
                event.get("message"),
                json.dumps(data_object, ensure_ascii=False, separators=(",", ":")),
                timestamp,
                int(essential),
                int(truncated),
            ),
        )
        event_id = cursor.lastrowid
        if event_id is None:
            raise RuntimeError("SQLite did not return an event cursor")
        return self._event_envelope(
            event,
            scan_id=scan_id,
            attempt=attempt,
            event_id=int(event_id),
            timestamp=timestamp,
            truncated=truncated,
        )

    @staticmethod
    def _event_envelope(
        event: Mapping[str, Any],
        *,
        scan_id: str,
        attempt: int,
        event_id: int | None,
        timestamp: str | None,
        truncated: bool = False,
        accepted: bool = True,
        dropped: bool = False,
    ) -> dict[str, Any]:
        envelope: dict[str, Any] = {
            "schema_version": 1,
            "event_id": event_id,
            "timestamp": timestamp,
            "id": event_id,
            "cursor": event_id,
            "scan_id": scan_id,
            "attempt": attempt,
            "source": event.get("source"),
            "type": event["type"],
            "stage": event.get("stage"),
            "level": event.get("level"),
            "code": event.get("code"),
            "message": event.get("message"),
            "data": dict(event.get("data") or {}),
            "created_at": timestamp,
            "truncated": truncated,
            "accepted": accepted,
            "dropped": dropped,
        }
        return envelope

    def _record_accepted_event_db(
        self,
        db: sqlite3.Connection,
        scan_id: str,
        event: Mapping[str, Any],
        timestamp: str | None,
        *,
        truncated: bool,
    ) -> None:
        db.execute(
            """
            UPDATE scans
            SET event_count = event_count + 1,
                event_truncated_count = event_truncated_count + ?,
                history_available = 1
            WHERE id = ?
            """,
            (1 if truncated else 0, scan_id),
        )
        self._project_event_db(db, scan_id, event, timestamp)

    def _project_event_db(
        self,
        db: sqlite3.Connection,
        scan_id: str,
        event: Mapping[str, Any],
        timestamp: str | None,
    ) -> None:
        """Keep the latest facts current even when detailed history is capped."""
        update = structured_event_update(event)
        if update is not None:
            self._apply_structured_update_db(db, scan_id, update, timestamp, event)
        self._record_process_deadline_db(db, scan_id, event, timestamp)
        level = str(event.get("level") or "").lower()
        event_type = str(event.get("type") or "").lower()
        if level in {"warning", "error", "critical"} or "error" in event_type or "failed" in event_type:
            data = event.get("data")
            data_mapping = data if isinstance(data, Mapping) else {}
            retryable = data_mapping.get("retryable") if isinstance(data_mapping.get("retryable"), bool) else None
            current_error = db.execute("SELECT last_error_code FROM scans WHERE id = ?", (scan_id,)).fetchone()
            new_code = event.get("code") or event.get("type")
            if current_error is None or _should_replace_error(current_error["last_error_code"], new_code):
                db.execute(
                    """
                    UPDATE scans
                    SET last_error_code = ?, last_error_message = ?, last_error_retryable = ?,
                        last_error_suggestion = ?, last_error_source = ?
                    WHERE id = ?
                    """,
                    (
                        new_code,
                        event.get("message"),
                        None if retryable is None else int(retryable),
                        self._suggestion_for_event(event),
                        event.get("source"),
                        scan_id,
                    ),
                )

    @staticmethod
    def _record_process_deadline_db(
        db: sqlite3.Connection,
        scan_id: str,
        event: Mapping[str, Any],
        timestamp: str | None,
    ) -> None:
        if timestamp is None or str(event.get("source") or "").lower() != "ocr":
            return
        code = str(event.get("code") or "").lower()
        event_type = str(event.get("type") or "").lower()
        if code not in {"ocr_starting", "process_started"} and event_type not in {"ocr.started", "ocr.phase"}:
            return
        data = event.get("data")
        if not isinstance(data, Mapping):
            return
        timeout = data.get("timeout_seconds")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or timeout <= 0
        ):
            return
        try:
            deadline = datetime.fromisoformat(timestamp) + timedelta(seconds=float(timeout))
        except (TypeError, ValueError, OverflowError):
            return
        db.execute(
            "UPDATE scans SET process_deadline_at = ? WHERE id = ? AND process_deadline_at IS NULL",
            (_stamp(deadline), scan_id),
        )

    def _apply_structured_update_db(
        self,
        db: sqlite3.Connection,
        scan_id: str,
        update: StructuredEventUpdate,
        timestamp: str | None,
        event: Mapping[str, Any],
    ) -> None:
        row = db.execute(
            "SELECT capabilities_json, coverage_observation_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if row is None:
            raise ScanNotFound(scan_id)
        capabilities = self._json_object(row["capabilities_json"])
        if update.event_protocol:
            capabilities["event_protocol"] = True
        if update.file_progress:
            capabilities["file_progress"] = True
        if update.llm_requests:
            capabilities["llm_requests"] = True
        assignments = ["capabilities_json = ?"]
        values: list[object] = [json.dumps(self._capabilities_object(capabilities), ensure_ascii=False)]
        if update.progress and timestamp is not None:
            assignments.append("last_progress_at = ?")
            values.append(timestamp)
        if update.output and has_actual_output_activity(event) and timestamp is not None:
            assignments.append("last_output_at = ?")
            values.append(timestamp)
        if update.coverage is not None:
            current = self._json_object(row["coverage_observation_json"])
            merged = self._merge_observation_coverage(current, update)
            assignments.extend(("coverage_observation_json = ?", "coverage_json = ?"))
            values.extend(
                (json.dumps(merged, ensure_ascii=False), json.dumps(self._legacy_coverage(merged), ensure_ascii=False))
            )
        values.append(scan_id)
        db.execute(f"UPDATE scans SET {', '.join(assignments)} WHERE id = ?", values)

    @staticmethod
    def _json_object(value: object) -> dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                return {}
            return dict(parsed) if isinstance(parsed, Mapping) else {}
        return {}

    @staticmethod
    def _capabilities_object(value: Mapping[str, Any]) -> dict[str, bool]:
        return {
            "file_progress": value.get("file_progress") is True,
            "llm_requests": value.get("llm_requests") is True,
            "event_protocol": value.get("event_protocol") is True,
        }

    @staticmethod
    def _merge_observation_coverage(current: Mapping[str, Any], update: StructuredEventUpdate) -> dict[str, Any]:
        incoming = update.coverage or {}
        current_total = current.get("total")
        total = incoming.get("total") if incoming.get("total") is not None else current_total
        counters: dict[str, int] = {}
        for key in ("reviewed", "failed", "skipped"):
            previous = current.get(key)
            previous_value = (
                previous if isinstance(previous, int) and not isinstance(previous, bool) and previous >= 0 else 0
            )
            incoming_value = incoming.get(key)
            incoming_count = (
                incoming_value
                if isinstance(incoming_value, int) and not isinstance(incoming_value, bool) and incoming_value >= 0
                else 0
            )
            counters[key] = (
                previous_value + incoming_count if update.coverage_delta else max(previous_value, incoming_count)
            )
        if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
            if sum(counters.values()) > total:
                return dict(current)
        else:
            total = None
        percent = (
            100 if total == 0 else min(100, round(sum(counters.values()) * 100 / total)) if total is not None else None
        )
        return {
            "known_total": total is not None,
            "total": total,
            **counters,
            "percent": percent,
        }

    @staticmethod
    def _legacy_coverage(value: Mapping[str, Any]) -> dict[str, int]:
        return {
            "total_files": int(value.get("total") or 0),
            "reviewed_files": int(value.get("reviewed") or 0),
            "failed_files": int(value.get("failed") or 0),
            "skipped_files": int(value.get("skipped") or 0),
            "percent": int(value.get("percent") or 0),
        }

    @staticmethod
    def _observation_coverage(progress: ScanProgress) -> dict[str, int | bool | None]:
        known_total = progress.total_files > 0
        percent = (
            min(
                100,
                round(
                    (progress.reviewed_files + progress.failed_files + progress.skipped_files)
                    * 100
                    / progress.total_files
                ),
            )
            if known_total
            else None
        )
        return {
            "known_total": known_total,
            "total": progress.total_files if known_total else None,
            "reviewed": progress.reviewed_files,
            "failed": progress.failed_files,
            "skipped": progress.skipped_files,
            "percent": percent,
        }

    @staticmethod
    def _suggestion_for_event(event: Mapping[str, Any]) -> str | None:
        code = str(event.get("code") or "")
        if code.startswith("invalid_schema"):
            return "Check the OCR adapter field contract and the field-specific error code; raw response text is not logged."
        return {
            "invalid_json": "Check the OCR JSON output mode and engine version.",
            "missing_json": "Check the OCR process exit status and output byte counters.",
            "git_dns": "Verify repository host DNS and retry.",
            "git_connect": "Verify network access and retry.",
            "git_tls": "Verify TLS certificates and proxy configuration.",
            "git_auth": "Check the worker Git credential helper or SSH agent.",
            "git_repo_missing": "Verify the repository URL and access.",
            "git_ref_missing": "Verify the requested branch, tag, or commit.",
            "git_timeout": "Retry or increase the Git timeout.",
            "git_limit": "Reduce repository size or increase the configured safety limit.",
            "lease_expired": "Check worker capacity and lease timing, then retry if the attempt did not complete.",
            "scan_failed": "Review the bounded diagnostics and retry when the dependency or input is available.",
            "scan_partial": "Review coverage warnings and retry if complete file coverage is required.",
            "cancel_completed": "Retry the scan when cancellation is no longer needed.",
            "event_limit": "Use the retained essential events; non-essential history was bounded.",
        }.get(code)

    def _log_events(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            marker = event.pop("_committed_marker", None)
            if isinstance(marker, dict) and isinstance(marker.get("event_id"), int):
                log_stored_event(marker["event_id"], marker)
            event_id = event.get("event_id")
            if event.get("accepted") is True and isinstance(event_id, int):
                log_stored_event(event_id, event)

    def claim_next(self, worker_id: str, *, lease_seconds: int = 300) -> WorkerScan | None:
        if not worker_id or lease_seconds <= 0:
            raise ValueError("worker_id and positive lease_seconds are required")
        self._maybe_cleanup_events()
        now = _now()
        now_epoch = now.timestamp()
        lease_until = now_epoch + lease_seconds
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                expired_rows = db.execute(
                    """
                    SELECT * FROM scans
                    WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?
                    """,
                    (ScanStatus.RUNNING.value, now_epoch),
                ).fetchall()
                for expired in expired_rows:
                    expired_status = ScanStatus.CANCELED if expired["cancel_requested"] else ScanStatus.QUEUED
                    expired_phase = "canceled" if expired["cancel_requested"] else "queued"
                    finished_at = _stamp(now) if expired_status is ScanStatus.CANCELED else None
                    db.execute(
                        """
                        UPDATE scans
                        SET status = ?, phase = ?, phase_started_at = ?, finished_at = ?,
                            worker_id = NULL, lease_expires_at = NULL, lease_token = NULL,
                            process_deadline_at = NULL,
                            heartbeat_at = NULL, last_output_at = NULL, last_progress_at = NULL,
                            coverage_observation_json = '{}', updated_at = ?
                        WHERE id = ? AND status = ? AND lease_expires_at = ?
                        """,
                        (
                            expired_status.value,
                            expired_phase,
                            _stamp(now),
                            finished_at,
                            _stamp(now),
                            expired["id"],
                            ScanStatus.RUNNING.value,
                            expired["lease_expires_at"],
                        ),
                    )
                    committed_events.append(
                        self._append_event_db(
                            db,
                            expired["id"],
                            attempt=int(expired["attempt"]),
                            worker_id=expired["worker_id"],
                            event={
                                "source": "worker",
                                "type": "scan.lease_expired",
                                "stage": expired_phase,
                                "level": "warning",
                                "code": "lease_expired",
                                "message": "The worker lease expired; the attempt was requeued or canceled.",
                                "data": {"attempt": int(expired["attempt"])},
                            },
                            timestamp=_stamp(now),
                        )
                    )
                row = db.execute(
                    "SELECT * FROM scans WHERE status = ? ORDER BY created_at, id LIMIT 1",
                    (ScanStatus.QUEUED.value,),
                ).fetchone()
                if row is None:
                    db.commit()
                    self._log_events(committed_events)
                    return None
                db.execute(
                    """
                    UPDATE scans
                    SET status = ?, phase = ?, phase_started_at = ?, worker_id = ?, lease_expires_at = ?,
                        heartbeat_at = ?, lease_token = ?, attempt = attempt + 1,
                        started_at = COALESCE(started_at, ?), updated_at = ?, error = NULL,
                        last_error_code = NULL, last_error_message = NULL, last_error_retryable = NULL,
                        last_error_suggestion = NULL, last_error_source = NULL
                    WHERE id = ? AND status = ?
                    """,
                    (
                        ScanStatus.RUNNING.value,
                        "preparing",
                        _stamp(now),
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
                assert claimed is not None
                committed_events.append(
                    self._append_event_db(
                        db,
                        claimed["id"],
                        attempt=int(claimed["attempt"]),
                        worker_id=worker_id,
                        event={
                            "source": "worker",
                            "type": "scan.claimed",
                            "stage": "preparing",
                            "level": "info",
                            "code": "claim_acquired",
                            "message": "Worker claimed the scan attempt.",
                            "data": {"attempt": int(claimed["attempt"])},
                        },
                        timestamp=_stamp(now),
                    )
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        assert claimed is not None
        self._log_events(committed_events)
        return self._worker_from_row(claimed)

    def set_phase(self, scan_id: str, worker_id: str, phase: str, *, lease_token: str | None = None) -> None:
        now = _stamp(_now())
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                self._require_owned_row(row, worker_id, lease_token)
                assert row is not None
                phase_started_at = row["phase_started_at"] if row["phase"] == phase else now
                last_progress_at = row["last_progress_at"] if row["phase"] == phase else now
                query = """
                    UPDATE scans SET phase = ?, phase_started_at = ?, updated_at = ?, last_progress_at = ?
                    WHERE id = ? AND worker_id = ? AND status = ?
                """
                parameters: list[object] = [
                    phase,
                    phase_started_at,
                    now,
                    last_progress_at,
                    scan_id,
                    worker_id,
                    ScanStatus.RUNNING.value,
                ]
                if lease_token is not None:
                    query = query.rstrip() + " AND lease_token = ?"
                    parameters.append(lease_token)
                cursor = db.execute(query, parameters)
                if cursor.rowcount != 1:
                    raise LeaseLost(scan_id)
                committed_events.append(
                    self._append_event_db(
                        db,
                        scan_id,
                        attempt=int(row["attempt"]),
                        worker_id=worker_id,
                        event={
                            "source": "worker",
                            "type": "scan.phase",
                            "stage": phase,
                            "level": "info",
                            "code": "phase_changed",
                            "message": f"Scan entered phase {phase}.",
                            "data": {"phase": phase},
                        },
                        timestamp=now,
                    )
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)

    def record_commit(self, scan_id: str, worker_id: str, commit_sha: str, *, lease_token: str | None = None) -> None:
        if not commit_sha or any(char not in "0123456789abcdef" for char in commit_sha.lower()):
            raise ValueError("commit_sha must be hexadecimal")
        now = _stamp(_now())
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                self._require_owned_row(row, worker_id, lease_token)
                assert row is not None
                query = """
                    UPDATE scans SET commit_sha = ?, updated_at = ?
                    WHERE id = ? AND worker_id = ? AND status = ?
                """
                parameters: list[object] = [commit_sha, now, scan_id, worker_id, ScanStatus.RUNNING.value]
                if lease_token is not None:
                    query = query.rstrip() + " AND lease_token = ?"
                    parameters.append(lease_token)
                cursor = db.execute(query, parameters)
                if cursor.rowcount != 1:
                    raise LeaseLost(scan_id)
                committed_events.append(
                    self._append_event_db(
                        db,
                        scan_id,
                        attempt=int(row["attempt"]),
                        worker_id=worker_id,
                        event={
                            "source": "worker",
                            "type": "scan.commit",
                            "stage": row["phase"],
                            "level": "info",
                            "code": "commit_recorded",
                            "message": "The resolved commit was recorded.",
                            "data": {"commit_sha": commit_sha},
                        },
                        timestamp=now,
                    )
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)

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
        assignment_values: list[object] = [now.timestamp() + lease_seconds, _stamp(now), _stamp(now)]
        progress_json: str | None = None
        observation_json: str | None = None
        if progress is not None:
            progress_json = json.dumps(progress.model_dump(mode="json"), ensure_ascii=False)
            observation_json = json.dumps(self._observation_coverage(progress), ensure_ascii=False)
            assignments += ", coverage_json = ?, coverage_observation_json = ?"
            assignment_values.extend((progress_json, observation_json))
        where_values: list[object] = [scan_id, worker_id, ScanStatus.RUNNING.value]
        where = "id = ? AND worker_id = ? AND status = ?"
        if lease_token is not None:
            where += " AND lease_token = ?"
            where_values.append(lease_token)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute(f"SELECT coverage_json FROM scans WHERE {where}", where_values).fetchone()
                if existing is None:
                    db.rollback()
                    raise LeaseLost(scan_id)
                if progress_json is not None and existing["coverage_json"] != progress_json:
                    assignments += ", last_progress_at = ?"
                    assignment_values.append(_stamp(now))
                cursor = db.execute(
                    f"UPDATE scans SET {assignments} WHERE {where}",
                    [*assignment_values, *where_values],
                )
                if cursor.rowcount != 1:
                    raise LeaseLost(scan_id)
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise

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
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                self._require_owned_row(row, worker_id, lease_token)
                assert row is not None
                if row["cancel_requested"]:
                    db.execute(
                        """
                        UPDATE scans SET status = ?, phase = ?, phase_started_at = ?, finished_at = ?, updated_at = ?,
                            worker_id = NULL, lease_expires_at = NULL, lease_token = NULL
                        WHERE id = ?
                        """,
                        (ScanStatus.CANCELED.value, "canceled", now, now, now, scan_id),
                    )
                    committed_events.append(
                        self._append_event_db(
                            db,
                            scan_id,
                            attempt=int(row["attempt"]),
                            worker_id=worker_id,
                            event={
                                "source": "worker",
                                "type": "scan.canceled",
                                "stage": "canceled",
                                "level": "warning",
                                "code": "cancel_completed",
                                "message": "The scan stopped because cancellation was requested.",
                            },
                            timestamp=now,
                        )
                    )
                else:
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
                        SET status = ?, phase = ?, phase_started_at = ?,
                            commit_sha = COALESCE(?, commit_sha), session_id = ?,
                            coverage_json = ?, coverage_observation_json = ?, last_progress_at = ?,
                            metadata_json = ?, finding_count = ?, error = ?,
                            finished_at = ?, updated_at = ?, worker_id = NULL, lease_expires_at = NULL,
                            lease_token = NULL
                        WHERE id = ? AND status = ? AND worker_id = ?
                    """
                    parameters: list[object] = [
                        result.status.value,
                        result.status.value,
                        now,
                        result.commit_sha,
                        result.session_id,
                        json.dumps(progress.model_dump(mode="json"), ensure_ascii=False),
                        json.dumps(self._observation_coverage(progress), ensure_ascii=False),
                        now,
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
                    terminal_level = {
                        ScanStatus.COMPLETED: "info",
                        ScanStatus.PARTIAL: "warning",
                        ScanStatus.FAILED: "error",
                        ScanStatus.SKIPPED: "notice",
                    }[result.status]
                    terminal_message = _safe_error(result.error) or f"Scan finished with status {result.status.value}."
                    retryable = result.status in {
                        ScanStatus.PARTIAL,
                        ScanStatus.FAILED,
                        ScanStatus.SKIPPED,
                    }
                    committed_events.append(
                        self._append_event_db(
                            db,
                            scan_id,
                            attempt=int(row["attempt"]),
                            worker_id=worker_id,
                            event={
                                "source": "worker",
                                "type": f"scan.{result.status.value}",
                                "stage": result.status.value,
                                "level": terminal_level,
                                "code": f"scan_{result.status.value}",
                                "message": terminal_message,
                                "data": {
                                    "status": result.status.value,
                                    "finding_count": len(result.findings),
                                    "retryable": retryable,
                                    "suggestion": (
                                        "Review diagnostics and retry when the dependency or input is available."
                                        if retryable
                                        else None
                                    ),
                                },
                            },
                            timestamp=now,
                        )
                    )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)
        return self.get_scan(scan_id)

    def fail(self, scan_id: str, worker_id: str, error: str, *, lease_token: str | None = None) -> ScanResponse:
        result = ServiceScanResult(status=ScanStatus.FAILED, error=_safe_error(error))
        return self.finish(scan_id, worker_id, result, lease_token=lease_token)

    def cancel(self, scan_id: str) -> ScanResponse:
        now = _stamp(_now())
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if row is None:
                    db.rollback()
                    raise ScanNotFound(scan_id)
                current = ScanStatus(row["status"])
                if current is ScanStatus.QUEUED:
                    db.execute(
                        """
                        UPDATE scans SET status = ?, phase = ?, phase_started_at = ?, finished_at = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (ScanStatus.CANCELED.value, "canceled", now, now, now, scan_id),
                    )
                    committed_events.append(
                        self._append_event_db(
                            db,
                            scan_id,
                            attempt=int(row["attempt"]),
                            worker_id=None,
                            event={
                                "source": "api",
                                "type": "scan.canceled",
                                "stage": "canceled",
                                "level": "warning",
                                "code": "cancel_completed",
                            },
                            timestamp=now,
                        )
                    )
                elif current is ScanStatus.RUNNING:
                    db.execute(
                        """
                        UPDATE scans
                        SET cancel_requested = 1, phase = ?, phase_started_at = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        ("cancel_requested", now, now, scan_id),
                    )
                    committed_events.append(
                        self._append_event_db(
                            db,
                            scan_id,
                            attempt=int(row["attempt"]),
                            worker_id=row["worker_id"],
                            event={
                                "source": "api",
                                "type": "scan.cancel_requested",
                                "stage": "cancel_requested",
                                "level": "warning",
                                "code": "cancel_requested",
                            },
                            timestamp=now,
                        )
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
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)
        return self.get_scan(scan_id)

    def retry(self, scan_id: str) -> ScanResponse:
        now = _stamp(_now())
        committed_events: list[dict[str, Any]] = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
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
                    UPDATE scans SET status = ?, phase = ?, phase_started_at = ?, coverage_json = ?,
                        coverage_observation_json = '{}', cancel_requested = 0, worker_id = NULL,
                        lease_expires_at = NULL, process_deadline_at = NULL, heartbeat_at = NULL, last_output_at = NULL,
                        last_progress_at = NULL, lease_token = NULL, session_id = NULL, error = NULL,
                        last_error_code = NULL, last_error_message = NULL, last_error_retryable = NULL,
                        last_error_suggestion = NULL, last_error_source = NULL,
                        finding_count = 0, updated_at = ?, finished_at = NULL
                    WHERE id = ?
                    """,
                    (
                        ScanStatus.QUEUED.value,
                        "queued",
                        now,
                        json.dumps(ScanProgress().model_dump(mode="json"), ensure_ascii=False),
                        now,
                        scan_id,
                    ),
                )
                db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                committed_events.append(
                    self._append_event_db(
                        db,
                        scan_id,
                        attempt=int(row["attempt"]),
                        worker_id=None,
                        event={
                            "source": "api",
                            "type": "scan.retried",
                            "stage": "queued",
                            "level": "info",
                            "code": "retry_queued",
                        },
                        timestamp=now,
                    )
                )
                db.commit()
            except Exception:
                if db.in_transaction:
                    db.rollback()
                raise
        self._log_events(committed_events)
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

    def _scan_from_row(self, row: sqlite3.Row) -> ScanResponse:
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
            progress=self._progress(row),
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
            observation=build_observation(
                row,
                activity_warn_seconds=self.activity_warn_seconds,
                activity_stale_seconds=self.activity_stale_seconds,
            ),
        )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> dict[str, Any]:
        try:
            data = json.loads(row["data_json"])
            if not isinstance(data, dict):
                data = {}
        except (TypeError, ValueError, json.JSONDecodeError):
            data = {}
        event_id = int(row["id"])
        timestamp = row["created_at"]
        return {
            "schema_version": 1,
            "event_id": event_id,
            "timestamp": timestamp,
            "id": event_id,
            "cursor": event_id,
            "scan_id": row["scan_id"],
            "attempt": int(row["attempt"]),
            "source": row["source"],
            "type": row["type"],
            "stage": row["stage"],
            "level": row["level"],
            "code": row["code"],
            "message": row["message"],
            "data": data,
            "created_at": timestamp,
            "truncated": bool(row["truncated"]),
            "accepted": True,
            "dropped": False,
        }

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
