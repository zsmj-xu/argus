"""Worker queue and process entrypoint for the white-box service."""

from __future__ import annotations

from contextlib import nullcontext
import os
from pathlib import Path
import threading
from typing import Callable, ContextManager, Protocol
import time
import uuid

from .models import ScanProgress, ScanStatus, ServiceScanResult
from .store import LeaseLost, ScanStore, WorkerScan


ProgressCallback = Callable[[ScanProgress], None]
CancelCheck = Callable[[], bool]


class WorkspaceProvider(Protocol):
    def prepare(self, scan: WorkerScan, should_cancel: CancelCheck | None = None) -> ContextManager[Path] | Path: ...


class OcrRunner(Protocol):
    def run(
        self,
        scan: WorkerScan,
        workspace: Path,
        progress: ProgressCallback,
        should_cancel: CancelCheck,
    ) -> ServiceScanResult: ...


class ScanWorker:
    """Claim one persisted job at a time and execute it outside the API process."""

    def __init__(
        self,
        store: ScanStore,
        workspace_provider: WorkspaceProvider,
        runner: OcrRunner,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 300,
    ) -> None:
        self.store = store
        self.workspace_provider = workspace_provider
        self.runner = runner
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self.lease_seconds = lease_seconds

    def run_once(self) -> ServiceScanResult | None:
        scan = self.store.claim_next(self.worker_id, lease_seconds=self.lease_seconds)
        if scan is None:
            return None

        lease_stop = threading.Event()
        lease_lost = threading.Event()

        def should_cancel() -> bool:
            return lease_lost.is_set() or self.store.is_cancel_requested(scan.id)

        def report_progress(progress: ScanProgress) -> None:
            self.store.heartbeat(
                scan.id,
                self.worker_id,
                lease_seconds=self.lease_seconds,
                progress=progress,
                lease_token=scan.lease_token,
            )

        def renew_lease() -> None:
            interval = max(1.0, min(self.lease_seconds / 3, 30.0))
            while not lease_stop.wait(interval):
                try:
                    self.store.heartbeat(
                        scan.id,
                        self.worker_id,
                        lease_seconds=self.lease_seconds,
                        lease_token=scan.lease_token,
                    )
                except Exception as exc:
                    # A lost lease is terminal for this attempt.  Other
                    # transient database errors are retried by the next tick.
                    if isinstance(exc, LeaseLost):
                        lease_lost.set()
                        return

        renewer = threading.Thread(
            target=renew_lease,
            name=f"argus-lease-{scan.id[:8]}",
            daemon=True,
        )
        renewer.start()
        try:
            self.store.set_phase(scan.id, self.worker_id, "preparing", lease_token=scan.lease_token)
            prepared = self.workspace_provider.prepare(scan, should_cancel)
            context = nullcontext(prepared) if isinstance(prepared, Path) else prepared
            with context as workspace:
                workspace_path = Path(workspace).resolve()
                commit_sha = getattr(prepared, "commit_sha", None)
                if isinstance(commit_sha, str) and commit_sha:
                    self.store.record_commit(scan.id, self.worker_id, commit_sha, lease_token=scan.lease_token)
                self.store.set_phase(scan.id, self.worker_id, "scanning", lease_token=scan.lease_token)
                result = self.runner.run(scan, workspace_path, report_progress, should_cancel)
                if result.commit_sha:
                    self.store.record_commit(
                        scan.id,
                        self.worker_id,
                        result.commit_sha,
                        lease_token=scan.lease_token,
                    )
            self.store.finish(scan.id, self.worker_id, result, lease_token=scan.lease_token)
            return result
        except LeaseLost:
            return ServiceScanResult(status=ScanStatus.FAILED, error="worker lease lost")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            try:
                self.store.fail(scan.id, self.worker_id, error, lease_token=scan.lease_token)
            except LeaseLost:
                # A recovery worker may have taken ownership.  It owns the
                # only authoritative terminal transition for this attempt.
                pass
            return ServiceScanResult(status=ScanStatus.FAILED, error=error)
        finally:
            lease_stop.set()
            renewer.join(timeout=min(2.0, max(0.1, self.lease_seconds / 10)))

    def run_until_empty(self, max_scans: int | None = None) -> int:
        completed = 0
        while max_scans is None or completed < max_scans:
            result = self.run_once()
            if result is None:
                break
            completed += 1
        return completed

    def run_forever(
        self,
        *,
        poll_seconds: float = 1.0,
        stop_event: threading.Event | None = None,
    ) -> None:
        stop = stop_event or threading.Event()
        while not stop.is_set():
            result = self.run_once()
            if result is None:
                stop.wait(poll_seconds)


def main() -> None:
    """Start the production worker using environment-based configuration."""

    from .integration import GitWorkspaceProvider, OpenCodeReviewServiceRunner

    data_root = Path(os.getenv("ARGUS_DATA_DIR", "data")).resolve()
    from .store import resolve_scan_database

    database = resolve_scan_database()
    store = ScanStore(database, max_queue=_positive_env_int("ARGUS_MAX_QUEUE", 100))
    worker = ScanWorker(
        store,
        GitWorkspaceProvider(
            data_root / "workspaces",
            timeout_seconds=_positive_env_int("ARGUS_GIT_TIMEOUT_SECONDS", 600),
            max_bytes=_positive_env_int("ARGUS_MAX_REPOSITORY_BYTES", 1 << 30),
            max_files=_positive_env_int("ARGUS_MAX_REPOSITORY_FILES", 50_000),
        ),
        OpenCodeReviewServiceRunner.from_environment(),
        worker_id=os.getenv("ARGUS_WORKER_ID") or None,
        lease_seconds=_positive_env_int("ARGUS_WORKER_LEASE_SECONDS", 300),
    )
    heartbeat_path = data_root / "worker.heartbeat"
    poll_seconds = float(os.getenv("ARGUS_WORKER_POLL_SECONDS", "1"))
    try:
        while True:
            heartbeat_path.touch()
            result = worker.run_once()
            if result is None:
                time.sleep(poll_seconds)
    finally:
        store.close()


def _positive_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        return default
    return value if value > 0 else default


if __name__ == "__main__":
    main()
