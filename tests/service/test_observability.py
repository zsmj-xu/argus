from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import sqlite3

import pytest

from argus.service.models import FindingCreate, ScanCreateRequest, ScanProgress, ScanStatus, ServiceScanResult
from argus.service.store import LeaseLost, ScanStore


def claimed_store(path=":memory:"):
    store = ScanStore(path)
    scan, _ = store.create_scan(ScanCreateRequest(repository_url="https://example.invalid/repo.git"))
    claimed = store.claim_next("same-worker")
    assert claimed is not None
    return store, scan.id, claimed


def emit(store, claim, kind, data=None, level="info", code="event_recorded"):
    return store.append_event(
        claim.id,
        "same-worker",
        {
            "source": "ocr",
            "type": kind,
            "stage": "ocr_running",
            "level": level,
            "code": code,
            "data": data or {},
        },
        lease_token=claim.lease_token,
    )


def test_cursor_retry_and_same_worker_fencing(tmp_path):
    store, scan_id, old = claimed_store(tmp_path / "db.sqlite3")
    first = emit(store, old, "ocr.output_activity", {"stdout_bytes": 3})
    with store._db() as db:
        db.execute("UPDATE scans SET lease_expires_at=0 WHERE id=?", (scan_id,))
    new = store.claim_next("same-worker")
    assert new.attempt == 2 and new.lease_token != old.lease_token
    with pytest.raises(LeaseLost):
        emit(store, old, "ocr.output_activity", {"stdout_bytes": 9})
    with pytest.raises(LeaseLost):
        store.finish(scan_id, "same-worker", ServiceScanResult(), lease_token=old.lease_token)
    second = emit(store, new, "ocr.output_activity", {"stdout_bytes": 4})
    assert second["event_id"] > first["event_id"]
    history = store.list_events(scan_id)
    assert {e["attempt"] for e in history["items"]} >= {1, 2}
    page = store.list_events(scan_id, after=first["event_id"], limit=1)
    assert page["items"][0]["event_id"] > first["event_id"] and page["has_more"]
    store.close()
    reopened = ScanStore(tmp_path / "db.sqlite3")
    assert reopened.list_events(scan_id) == history


def test_phase_and_event_are_one_transaction(monkeypatch):
    store, scan_id, claim = claimed_store()
    before = store.get_scan(scan_id)
    history = store.list_events(scan_id)

    def fail_insert(*args, **kwargs):
        raise sqlite3.OperationalError("injected storage failure")

    monkeypatch.setattr(store, "_insert_event_row", fail_insert)
    with pytest.raises(sqlite3.OperationalError):
        store.set_phase(scan_id, "same-worker", "source_checking", lease_token=claim.lease_token)
    assert store.get_scan(scan_id).phase == before.phase
    assert store.list_events(scan_id) == history


def test_heartbeat_activity_and_deadline_are_distinct(monkeypatch):
    now = [datetime(2026, 9, 15, 12, tzinfo=UTC)]
    monkeypatch.setattr("argus.service.store._now", lambda: now[0])
    store, scan_id, claim = claimed_store()
    store.set_phase(scan_id, "same-worker", "ocr_running", lease_token=claim.lease_token)
    emit(store, claim, "phase", {"timeout_seconds": 1800}, code="ocr_running")
    progress = ScanProgress(total_files=2, reviewed_files=1, percent=50)
    store.heartbeat(scan_id, "same-worker", progress=progress, lease_token=claim.lease_token)
    first = store.get_scan(scan_id).observation
    now[0] += timedelta(seconds=125)
    store.heartbeat(scan_id, "same-worker", progress=progress, lease_token=claim.lease_token)
    second = store.get_scan(scan_id).observation
    assert second.last_progress_at == first.last_progress_at
    assert second.last_output_at is None
    assert second.deadline_at == first.deadline_at
    assert second.worker_heartbeat_at > first.worker_heartbeat_at
    # Query timestamps derive from the observation clock as well.
    from argus.service.observability import build_observation

    with store._db() as db:
        row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    warning = build_observation(row, now=now[0])
    assert warning.activity_state == "idle_warning"
    stale = build_observation(row, now=now[0] + timedelta(seconds=180))
    assert stale.activity_state == "stale_warning"
    assert store.get_scan(scan_id).status is ScanStatus.RUNNING
    store.set_phase(scan_id, "same-worker", "parsing", lease_token=claim.lease_token)
    assert store.get_scan(scan_id).observation.last_progress_at == now[0]


def test_coverage_updates_and_partial_is_not_forced_complete():
    store, scan_id, claim = claimed_store()
    emit(store, claim, "scan.inventory", {"total_files": 2})
    emit(store, claim, "file.completed", {"path": "a.py"})
    coverage = store.get_scan(scan_id).observation.coverage
    assert coverage.total == 2 and coverage.reviewed == 1 and coverage.percent == 50
    store.finish(
        scan_id,
        "same-worker",
        ServiceScanResult(
            status=ScanStatus.PARTIAL,
            total_files=2,
            reviewed_files=1,
        ),
        lease_token=claim.lease_token,
    )
    assert store.get_scan(scan_id).observation.coverage.percent == 50


@pytest.mark.parametrize("level", ["info", "error"])
def test_event_flood_preserves_terminal_and_marks_truncation(monkeypatch, level):
    monkeypatch.setenv("ARGUS_EVENT_LIMIT", "20")
    store, scan_id, claim = claimed_store()
    for _ in range(60):
        emit(store, claim, "ocr.output_activity", {"stderr_bytes": 2}, level=level)
    store.finish(scan_id, "same-worker", ServiceScanResult(), lease_token=claim.lease_token)
    history = store.list_events(scan_id)
    current = [e for e in history["items"] if e["attempt"] == claim.attempt]
    assert len(current) <= 20
    assert current[-1]["type"] == "scan.completed"
    assert any(e["type"] == "observability.truncated" for e in current)
    assert history["history_truncated"] is True
    assert store.get_scan(scan_id).observation.dropped_event_count > 0


def test_retention_keeps_results_and_reports_missing_history():
    store, scan_id, claim = claimed_store()
    store.finish(
        scan_id,
        "same-worker",
        ServiceScanResult(
            findings=[FindingCreate(rule_id="test", title="test", message="test")],
        ),
        lease_token=claim.lease_token,
    )
    with store._db() as db:
        db.execute("UPDATE scan_events SET created_at='2020-01-01T00:00:00+00:00'")
    assert store.cleanup_events() > 0
    history = store.list_events(scan_id)
    assert history["items"] == [] and history["expired_event_count"] > 0
    assert history["history_truncated"] is True
    assert store.get_scan(scan_id).finding_count == 1
    assert store.export_diagnostics(scan_id)["events_truncated"] is True


def test_no_raw_payloads_in_history_or_diagnostic_export():
    store, scan_id, claim = claimed_store()
    emit(
        store,
        claim,
        "llm.request.failed",
        {
            "request_id": "req-1",
            "http_status": 429,
            "token": "secret-token",
            "prompt": "PRIVATE_SOURCE",
            "response": "PRIVATE_RESPONSE",
            "detail": "PRIVATE_DETAIL",
        },
        level="error",
        code="llm_request_failed",
    )
    text = json.dumps(store.export_diagnostics(scan_id), default=str)
    assert all(
        sentinel not in text for sentinel in ("secret-token", "PRIVATE_SOURCE", "PRIVATE_RESPONSE", "PRIVATE_DETAIL")
    )
    assert "req-1" in text and "429" in text


def test_existing_database_migration_is_concurrent_and_preserves_legacy(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    original = ScanStore(database)
    scan, _ = original.create_scan(ScanCreateRequest(repository_url="https://example.invalid/legacy.git"))
    with original._db() as db:
        # Model a pre-observability row without manufacturing historical events.
        db.execute("DELETE FROM scan_events")
        db.execute("UPDATE scans SET history_available=0,event_count=0")
        db.execute("ALTER TABLE scans DROP COLUMN event_expired_count")
    original.close()

    def open_once(_):
        store = ScanStore(database)
        result = store.get_scan(scan.id)
        store.close()
        return result

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(open_once, range(4)))
    assert all(result.id == scan.id and not result.observation.history_available for result in results)
