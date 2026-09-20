from contextlib import contextmanager
from pathlib import Path
import threading

from argus.service.integration import RepositoryFetchError
from argus.service.models import FindingCreate, ScanCreateRequest, ScanProgress, ScanStatus, ServiceScanResult
from argus.service.store import ScanStore
from argus.service.worker import ScanWorker


class FakeProvider:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def prepare(self, _scan, _should_cancel=None, event_callback=None):
        if event_callback is not None:
            event_callback(
                {
                    "type": "phase",
                    "source": "git",
                    "stage": "source_checking",
                    "level": "info",
                    "code": "source_checkout_ready",
                    "message": "ignored by worker sanitization",
                    "data": {},
                }
            )
        yield self.path


class FakeRunner:
    def run(self, _scan, _workspace, progress, should_cancel, event_callback=None):
        assert not should_cancel()
        if event_callback is not None:
            event_callback(
                {
                    "type": "file.completed",
                    "source": "ocr",
                    "stage": "ocr_running",
                    "level": "info",
                    "code": "file_completed",
                    "message": "ignored by worker sanitization",
                    "data": {"path": "src/app.py", "reviewed_files": 1},
                }
            )
        progress(ScanProgress(total_files=2, reviewed_files=1, percent=50))
        return ServiceScanResult(
            status=ScanStatus.COMPLETED,
            total_files=2,
            reviewed_files=2,
            findings=[FindingCreate(rule_id="ocr/security", title="Issue", message="Found")],
        )


class FailingRunner:
    def run(self, _scan, _workspace, _progress, _should_cancel, _event_callback=None):
        raise RuntimeError("runner failed")


def make_scan(store: ScanStore) -> str:
    return store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))[0].id


def test_worker_claims_runs_and_persists_result(tmp_path) -> None:
    store = ScanStore(":memory:")
    scan_id = make_scan(store)
    result = ScanWorker(store, FakeProvider(tmp_path), FakeRunner(), worker_id="worker-1").run_once()
    assert result is not None and result.status is ScanStatus.COMPLETED
    scan = store.get_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.progress.percent == 100
    assert store.list_findings(scan_id)[0][0].title == "Issue"
    events = store.list_events(scan_id)["items"]
    assert any(event["type"] == "file.completed" for event in events)
    assert any(event["type"] == "scan.phase" and event["stage"] == "persisting" for event in events)


def test_worker_marks_exception_as_failed(tmp_path) -> None:
    store = ScanStore(":memory:")
    scan_id = make_scan(store)
    result = ScanWorker(store, FakeProvider(tmp_path), FailingRunner(), worker_id="worker-1").run_once()
    assert result is not None and result.status is ScanStatus.FAILED
    assert store.get_scan(scan_id).status is ScanStatus.FAILED
    assert store.get_scan(scan_id).error == "worker_unknown"


def test_worker_preserves_precise_boundary_error_and_safe_internal_context(tmp_path, caplog) -> None:
    class AuthFailingProvider:
        def prepare(self, _scan, _should_cancel=None, _event_callback=None):
            raise RepositoryFetchError(code="auth")

    store = ScanStore(":memory:")
    scan_id = make_scan(store)
    result = ScanWorker(store, AuthFailingProvider(), FakeRunner(), worker_id="worker-1").run_once()

    assert result is not None and result.error == "git_auth"
    events = store.list_events(scan_id)["items"]
    assert any(event["type"] == "error" and event["code"] == "git_auth" for event in events)
    assert "runner failed" not in caplog.text


def test_worker_fallback_log_contains_only_safe_exception_context(tmp_path, caplog) -> None:
    store = ScanStore(":memory:")
    scan_id = make_scan(store)
    ScanWorker(store, FakeProvider(tmp_path), FailingRunner(), worker_id="worker-1").run_once()

    assert '"exception_type":"RuntimeError"' in caplog.text
    assert "runner failed" not in caplog.text
    assert '"scan_id":"' + scan_id + '"' in caplog.text
    assert '"attempt":1' in caplog.text
    assert '"worker_id":"worker-1"' in caplog.text


def test_worker_liveness_heartbeat_runs_while_idle(tmp_path) -> None:
    store = ScanStore(":memory:")
    stop = threading.Event()
    calls: list[None] = []

    def observe() -> None:
        calls.append(None)
        if len(calls) >= 2:
            stop.set()

    worker = ScanWorker(
        store,
        FakeProvider(tmp_path),
        FakeRunner(),
        worker_id="worker-idle",
        heartbeat_observer=observe,
    )
    worker.run_forever(poll_seconds=0, stop_event=stop)

    assert len(calls) >= 2
