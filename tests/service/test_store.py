import sqlite3

import pytest

from argus.service.models import FindingCreate, ScanCreateRequest, ScanProgress, ScanStatus, ServiceScanResult
from argus.service.store import (
    IdempotencyConflict,
    LeaseLost,
    QueueFull,
    ScanStateError,
    ScanStore,
    resolve_scan_database,
)


def request() -> ScanCreateRequest:
    return ScanCreateRequest(repository_url="https://example.com/repo.git", ref="main")


def test_api_and_worker_share_one_database_resolution(monkeypatch, tmp_path) -> None:
    configured = tmp_path / "shared" / "service.sqlite3"
    monkeypatch.setenv("ARGUS_SCAN_DB", str(configured))
    assert resolve_scan_database() == configured.resolve()

    monkeypatch.delenv("ARGUS_SCAN_DB")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path / "data"))
    assert resolve_scan_database() == (tmp_path / "data" / "service.sqlite3").resolve()


def test_store_claim_lease_commit_finish_and_persistence(tmp_path) -> None:
    database = tmp_path / "service.sqlite3"
    store = ScanStore(database)
    first, created = store.create_scan(request(), "key-1")
    same, reused = store.create_scan(request(), "key-1")
    assert created and not reused and same.id == first.id
    with pytest.raises(IdempotencyConflict):
        store.create_scan(ScanCreateRequest(repository_url="https://example.com/other.git"), "key-1")

    claimed = store.claim_next("worker-a", lease_seconds=30)
    assert claimed is not None and claimed.attempt == 1 and claimed.lease_token
    store.heartbeat(
        claimed.id,
        "worker-a",
        lease_seconds=30,
        progress=ScanProgress(total_files=10, reviewed_files=3, percent=30),
    )
    with pytest.raises(LeaseLost):
        store.heartbeat(claimed.id, "worker-b")
    with pytest.raises(LeaseLost):
        store.heartbeat(claimed.id, "worker-a", lease_token="stale-token")
    store.record_commit(claimed.id, "worker-a", "b" * 40)
    store.finish(
        claimed.id,
        "worker-a",
        ServiceScanResult(
            status=ScanStatus.PARTIAL,
            commit_sha="b" * 40,
            total_files=10,
            reviewed_files=8,
            failed_files=2,
            findings=[FindingCreate(rule_id="r", title="Finding", message="Evidence")],
        ),
    )
    completed = store.get_scan(claimed.id)
    assert completed.status is ScanStatus.PARTIAL
    assert completed.progress.reviewed_files == 8
    assert completed.finding_count == 1
    store.close()

    reopened = ScanStore(database)
    assert reopened.get_scan(claimed.id).commit_sha == "b" * 40
    findings, total = reopened.list_findings(claimed.id)
    assert len(findings) == total == 1
    assert sqlite3.connect(database).execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_failed_finish_preserves_observed_event_coverage() -> None:
    store = ScanStore(":memory:")
    store.create_scan(request())
    claimed = store.claim_next("worker-a")
    assert claimed is not None

    store.append_event(
        claimed.id,
        "worker-a",
        {
            "source": "ocr",
            "type": "scan.inventory",
            "stage": "ocr_running",
            "level": "info",
            "code": "scan_inventory",
            "data": {"files_total": 4, "reviewed_files": 0, "failed_files": 0, "skipped_files": 0},
        },
        lease_token=claimed.lease_token or "",
    )
    for path in ("a.py", "b.py"):
        store.append_event(
            claimed.id,
            "worker-a",
            {
                "source": "ocr",
                "type": "file.completed",
                "stage": "ocr_running",
                "level": "info",
                "code": "file_completed",
                "data": {"path": path, "total": 4},
            },
            lease_token=claimed.lease_token or "",
        )

    finished = store.finish(
        claimed.id,
        "worker-a",
        ServiceScanResult(status=ScanStatus.FAILED, error="ocr_invalid_output"),
        lease_token=claimed.lease_token,
    )

    assert finished.status is ScanStatus.FAILED
    assert finished.progress.total_files == 4
    assert finished.progress.reviewed_files == 2
    assert finished.observation.coverage.total == 4
    assert finished.observation.coverage.reviewed == 2
    assert finished.observation.coverage.percent == 50


def test_store_cancel_retry_and_expired_lease_recovery() -> None:
    store = ScanStore(":memory:")
    queued, _ = store.create_scan(request())
    assert store.cancel(queued.id).status is ScanStatus.CANCELED
    assert store.retry(queued.id).status is ScanStatus.QUEUED

    claimed = store.claim_next("worker-a", lease_seconds=1)
    assert claimed is not None
    with store._db() as db:
        db.execute("UPDATE scans SET lease_expires_at = 0 WHERE id = ?", (claimed.id,))
    recovered = store.claim_next("worker-b", lease_seconds=30)
    assert recovered is not None and recovered.id == claimed.id and recovered.attempt == 2
    assert recovered.lease_token and recovered.lease_token != claimed.lease_token

    with pytest.raises(LeaseLost):
        store.heartbeat(claimed.id, "worker-b", lease_token=claimed.lease_token)

    store.cancel(recovered.id)
    with pytest.raises(LeaseLost):
        store.record_commit(recovered.id, "worker-a", "c" * 40)
    with pytest.raises(ScanStateError):
        store.retry(recovered.id)


def test_store_enforces_active_queue_limit() -> None:
    store = ScanStore(":memory:", max_queue=1)
    store.create_scan(request())
    with pytest.raises(QueueFull):
        store.create_scan(request())
