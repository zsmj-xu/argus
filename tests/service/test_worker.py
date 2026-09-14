from contextlib import contextmanager
from pathlib import Path

from argus.service.models import FindingCreate, ScanCreateRequest, ScanProgress, ScanStatus, ServiceScanResult
from argus.service.store import ScanStore
from argus.service.worker import ScanWorker


class FakeProvider:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def prepare(self, _scan, _should_cancel=None):
        yield self.path


class FakeRunner:
    def run(self, _scan, _workspace, progress, should_cancel):
        assert not should_cancel()
        progress(ScanProgress(total_files=2, reviewed_files=1, percent=50))
        return ServiceScanResult(
            status=ScanStatus.COMPLETED,
            total_files=2,
            reviewed_files=2,
            findings=[FindingCreate(rule_id="ocr/security", title="Issue", message="Found")],
        )


class FailingRunner:
    def run(self, _scan, _workspace, _progress, _should_cancel):
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


def test_worker_marks_exception_as_failed(tmp_path) -> None:
    store = ScanStore(":memory:")
    scan_id = make_scan(store)
    result = ScanWorker(store, FakeProvider(tmp_path), FailingRunner(), worker_id="worker-1").run_once()
    assert result is not None and result.status is ScanStatus.FAILED
    assert store.get_scan(scan_id).status is ScanStatus.FAILED
