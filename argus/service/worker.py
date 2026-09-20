"""Worker queue and process entrypoint for the white-box service."""

from __future__ import annotations

from contextlib import nullcontext
import json
import logging
import math
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable, ContextManager, Mapping, Protocol
import time
import uuid

from .models import ScanProgress, ScanStatus, ServiceScanResult
from .observability import EVENT_DATA_WHITELIST
from .store import LeaseLost, ScanStore, WorkerScan


ProgressCallback = Callable[[ScanProgress], None]
CancelCheck = Callable[[], bool]
EventCallback = Callable[[dict[str, object]], None]

_LOGGER = logging.getLogger(__name__)

_LIFECYCLE_STAGES = (
    "queued",
    "git_fetching",
    "source_checking",
    "ocr_starting",
    "ocr_running",
    "parsing",
    "persisting",
)
_LIFECYCLE_STAGE_INDEX = {stage: index for index, stage in enumerate(_LIFECYCLE_STAGES)}
_EVENT_TYPES = {"phase", "progress", "heartbeat", "warning", "error"}
_EVENT_LEVELS = {"debug", "info", "notice", "warning", "error", "critical"}
_EVENT_DATA_KEYS = set(EVENT_DATA_WHITELIST) | {"exception_type", "error_location"}
_EVENT_MESSAGE_BY_TYPE = {
    "phase": "Scan phase changed",
    "progress": "Scan progress updated",
    "heartbeat": "Worker lease renewed",
    "warning": "Scan warning recorded",
    "error": "Scan error recorded",
}
_SAFE_FAILURE_CODES = {
    "dns",
    "connect",
    "tls",
    "auth",
    "repo_missing",
    "ref_missing",
    "timeout",
    "cancel",
    "unknown",
    "limit",
}
_KNOWN_EVENT_TYPE_PREFIXES = ("file.", "llm.", "tool.")


class WorkspaceProvider(Protocol):
    def prepare(
        self,
        scan: WorkerScan,
        should_cancel: CancelCheck | None = None,
        event_callback: EventCallback | None = None,
    ) -> ContextManager[Path] | Path: ...


class OcrRunner(Protocol):
    def run(
        self,
        scan: WorkerScan,
        workspace: Path,
        progress: ProgressCallback,
        should_cancel: CancelCheck,
        event_callback: EventCallback | None = None,
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
        heartbeat_observer: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.workspace_provider = workspace_provider
        self.runner = runner
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self.lease_seconds = lease_seconds
        self.heartbeat_observer = heartbeat_observer

    def run_once(self) -> ServiceScanResult | None:
        scan = self.store.claim_next(self.worker_id, lease_seconds=self.lease_seconds)
        if scan is None:
            return None

        # A claim is also a real lease heartbeat.  The production health file
        # is updated here and on successful renewals; the main polling loop
        # separately records worker liveness while the queue is idle.
        self._notify_heartbeat()

        lease_stop = threading.Event()
        lease_lost = threading.Event()
        diagnostic_loss = threading.Event()
        current_stage: str | None = None
        last_progress: tuple[int, int, int, int, int] | None = None

        def should_cancel() -> bool:
            return lease_lost.is_set() or self.store.is_cancel_requested(scan.id)

        def report_progress(progress: ScanProgress) -> None:
            nonlocal last_progress
            if lease_lost.is_set():
                raise LeaseLost(scan.id)
            self.store.heartbeat(
                scan.id,
                self.worker_id,
                lease_seconds=self.lease_seconds,
                progress=progress,
                lease_token=scan.lease_token,
            )
            self._notify_heartbeat()
            fingerprint = (
                progress.total_files,
                progress.reviewed_files,
                progress.failed_files,
                progress.skipped_files,
                progress.percent,
            )
            if fingerprint == last_progress:
                return
            last_progress = fingerprint
            self._append_event(
                scan,
                _event(
                    type="progress",
                    source="worker",
                    stage=current_stage or "ocr_running",
                    level="info",
                    code="progress_updated",
                    data={
                        "total_files": progress.total_files,
                        "reviewed_files": progress.reviewed_files,
                        "failed_files": progress.failed_files,
                        "skipped_files": progress.skipped_files,
                        "percent": progress.percent,
                    },
                ),
                lease_lost,
                diagnostic_loss,
            )

        def record_event(event: dict[str, object]) -> None:
            """Persist integration events without allowing stale lease writes."""

            if lease_lost.is_set():
                raise LeaseLost(scan.id)
            normalized = _normalize_event(event, current_stage=current_stage)
            event_type = normalized["type"]
            if event_type == "phase":
                stage = normalized["stage"]
                if isinstance(stage, str):
                    set_stage(stage)
                # set_phase owns the transactional lifecycle event.  Keep a
                # separate sanitized event when the phase carries operational
                # configuration (for example the expected OCR deadline).
                data = normalized.get("data")
                if isinstance(data, Mapping) and data:
                    self._append_event(scan, normalized, lease_lost, diagnostic_loss)
                return
            self._append_event(scan, normalized, lease_lost, diagnostic_loss)

        def set_stage(stage: str) -> None:
            nonlocal current_stage
            if stage not in _LIFECYCLE_STAGE_INDEX:
                return
            if current_stage is not None:
                current_index = _LIFECYCLE_STAGE_INDEX.get(current_stage, -1)
                if _LIFECYCLE_STAGE_INDEX[stage] < current_index:
                    return
                if stage == current_stage:
                    return
            if lease_lost.is_set():
                raise LeaseLost(scan.id)
            self.store.set_phase(scan.id, self.worker_id, stage, lease_token=scan.lease_token)
            current_stage = stage

        def renew_lease() -> None:
            interval = max(0.1, min(self.lease_seconds / 3, 30.0))
            while not lease_stop.wait(interval):
                try:
                    self.store.heartbeat(
                        scan.id,
                        self.worker_id,
                        lease_seconds=self.lease_seconds,
                        lease_token=scan.lease_token,
                    )
                    self._notify_heartbeat()
                except LeaseLost:
                    lease_lost.set()
                    self._log_scan(logging.WARNING, "lease_lost", scan)
                    return
                except Exception:
                    # A lost lease is terminal for this attempt.  Other
                    # transient database errors are retried by the next tick.
                    self._log_scan(logging.WARNING, "heartbeat_failed", scan)

        renewer = threading.Thread(
            target=renew_lease,
            name=f"argus-lease-{scan.id[:8]}",
            daemon=True,
        )
        renewer.start()
        try:
            set_stage("git_fetching")
            prepared = self.workspace_provider.prepare(scan, should_cancel, record_event)
            context = nullcontext(prepared) if isinstance(prepared, Path) else prepared
            with context as workspace:
                workspace_path = Path(workspace).resolve()
                commit_sha = getattr(prepared, "commit_sha", None)
                if isinstance(commit_sha, str) and commit_sha:
                    self.store.record_commit(scan.id, self.worker_id, commit_sha, lease_token=scan.lease_token)
                # Providers emit this transition after the checkout.  Keep a
                # worker-side fallback for simple providers and test doubles.
                set_stage("source_checking")
                set_stage("ocr_starting")
                result = self.runner.run(scan, workspace_path, report_progress, should_cancel, record_event)
                # A runner that does not expose the optional event protocol
                # still gets the stable parsing/persisting lifecycle.
                set_stage("parsing")
                if result.commit_sha:
                    self.store.record_commit(
                        scan.id,
                        self.worker_id,
                        result.commit_sha,
                        lease_token=scan.lease_token,
                    )
                set_stage("persisting")
            if diagnostic_loss.is_set():
                result.metadata["observability"] = {
                    "events_lost": True,
                    "event_append_failed": True,
                }
            self.store.finish(scan.id, self.worker_id, result, lease_token=scan.lease_token)
            return result
        except LeaseLost:
            self._log_scan(logging.WARNING, "lease_lost", scan)
            return ServiceScanResult(status=ScanStatus.FAILED, error="worker lease lost")
        except Exception as exc:
            code = _stable_failure_code(exc)
            error = code
            failure_data = _failure_event_data(exc)
            self._log_scan(logging.ERROR, code, scan, diagnostics=failure_data)
            try:
                record_event(
                    _event(
                        type="error",
                        source="worker",
                        stage=current_stage or "git_fetching",
                        level="error",
                        code=code,
                        data=failure_data,
                    ),
                )
            except LeaseLost:
                return ServiceScanResult(status=ScanStatus.FAILED, error="worker lease lost")
            except Exception:
                self._log_scan(logging.WARNING, "event_append_failed", scan)
            try:
                self.store.fail(scan.id, self.worker_id, error, lease_token=scan.lease_token)
            except LeaseLost:
                # A recovery worker may have taken ownership.  It owns the
                # only authoritative terminal transition for this attempt.
                pass
            except Exception:
                self._log_scan(logging.ERROR, "terminal_update_failed", scan)
            return ServiceScanResult(status=ScanStatus.FAILED, error=error)
        finally:
            lease_stop.set()
            renewer.join(timeout=min(2.0, max(0.1, self.lease_seconds / 10)))

    def _append_event(
        self,
        scan: WorkerScan,
        event: dict[str, object],
        lease_lost: threading.Event,
        diagnostic_loss: threading.Event,
    ) -> None:
        if lease_lost.is_set():
            raise LeaseLost(scan.id)
        if not isinstance(scan.lease_token, str) or not scan.lease_token:
            diagnostic_loss.set()
            self._log_scan(logging.ERROR, "lease_token_missing", scan)
            raise LeaseLost(scan.id)
        try:
            appended = self.store.append_event(
                scan.id,
                self.worker_id,
                event,
                lease_token=scan.lease_token,
            )
            if isinstance(appended, Mapping) and appended.get("accepted") is False:
                diagnostic_loss.set()
                self._log_scan(logging.ERROR, "event_dropped", scan)
        except LeaseLost:
            lease_lost.set()
            raise
        except AttributeError:
            diagnostic_loss.set()
            self._log_scan(logging.ERROR, "event_store_unavailable", scan)
        except Exception:
            diagnostic_loss.set()
            # Telemetry loss must not turn a healthy scan into a false scan
            # failure, but it is visible in worker logs and result metadata.
            self._log_scan(logging.ERROR, "event_append_failed", scan)

    def _notify_heartbeat(self) -> None:
        if self.heartbeat_observer is None:
            return
        try:
            self.heartbeat_observer()
        except Exception:
            self._log_worker(logging.WARNING, "health_heartbeat_failed")

    def _log_scan(
        self,
        level: int,
        code: str,
        scan: WorkerScan,
        *,
        diagnostics: Mapping[str, object] | None = None,
    ) -> None:
        payload = {
            "scan_id": scan.id,
            "attempt": scan.attempt,
            "worker_id": self.worker_id,
            "code": code,
        }
        if isinstance(diagnostics, Mapping):
            for key in ("exception_type", "error_location"):
                value = diagnostics.get(key)
                if isinstance(value, str) and value:
                    payload[key] = value
        _LOGGER.log(
            level,
            "argus_worker_event %s",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            extra={
                "argus_scan_id": scan.id,
                "argus_attempt": scan.attempt,
                "argus_worker_id": self.worker_id,
                "argus_code": code,
                "argus_exception_type": payload.get("exception_type"),
                "argus_error_location": payload.get("error_location"),
            },
        )

    def _log_worker(self, level: int, code: str) -> None:
        payload = {"worker_id": self.worker_id, "code": code}
        _LOGGER.log(
            level,
            "argus_worker_event %s",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            extra={"argus_worker_id": self.worker_id, "argus_code": code},
        )

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
            self._notify_heartbeat()
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
    heartbeat_path = data_root / "worker.heartbeat"
    heartbeat_path.parent.mkdir(parents=True, exist_ok=True)

    def observe_heartbeat() -> None:
        heartbeat_path.touch()

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
        heartbeat_observer=observe_heartbeat,
    )
    poll_seconds = float(os.getenv("ARGUS_WORKER_POLL_SECONDS", "1"))
    try:
        while True:
            observe_heartbeat()
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


def _event(
    *,
    type: str,
    source: str,
    stage: str,
    level: str,
    code: str,
    data: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "type": type,
        "source": source,
        "stage": stage,
        "level": level,
        "code": code,
        "message": _EVENT_MESSAGE_BY_TYPE.get(type, "Scan event recorded"),
        "data": dict(data or {}),
    }


def _normalize_event(event: Mapping[str, object], *, current_stage: str | None) -> dict[str, object]:
    raw_type = event.get("type")
    event_type = _safe_event_type(raw_type) or "warning"
    raw_source = event.get("source")
    source = _safe_label(raw_source) or "worker"
    raw_stage = event.get("stage")
    stage = raw_stage if isinstance(raw_stage, str) and raw_stage in _LIFECYCLE_STAGE_INDEX else current_stage
    if stage is None:
        stage = "git_fetching"
    raw_level = event.get("level")
    level = raw_level if isinstance(raw_level, str) and raw_level in _EVENT_LEVELS else "info"
    raw_code = event.get("code")
    code = _safe_code(raw_code) or "event_recorded"
    return {
        "type": event_type,
        "source": source,
        "stage": stage,
        "level": level,
        "code": code,
        "message": _EVENT_MESSAGE_BY_TYPE.get(event_type, "Scan event recorded"),
        "data": _safe_event_data(event.get("data")),
    }


def _safe_event_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 64 or not re.fullmatch(r"[a-z][a-z0-9_.-]*", candidate):
        return None
    if candidate in _EVENT_TYPES or candidate in {"scan.inventory", "session.started"}:
        return candidate
    if candidate.startswith((*_KNOWN_EVENT_TYPE_PREFIXES, "ocr.", "scan.", "session.")):
        return candidate
    return None


def _safe_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 64 or not re.fullmatch(r"[a-z][a-z0-9_.-]*", candidate):
        return None
    return candidate


def _safe_code(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if (
        not candidate
        or len(candidate) > 128
        or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for char in candidate)
    ):
        return None
    return candidate


def _safe_event_data(value: object, *, depth: int = 0) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    if depth > 2:
        return {}
    result: dict[str, Any] = {}
    boolean_keys = {
        "available",
        "enabled",
        "event_protocol",
        "file_progress",
        "known_total",
        "llm_requests",
        "report_ready",
        "retryable",
        "truncated",
    }
    nested_keys = {"capabilities", "coverage", "progress"}
    list_text_keys = {"truncated_fields"}
    for key in _EVENT_DATA_KEYS:
        item = value.get(key)
        if key in boolean_keys:
            if isinstance(item, bool):
                result[key] = item
            continue
        if key in nested_keys:
            nested = _safe_event_data(item, depth=depth + 1)
            if nested:
                result[key] = nested
            continue
        if key in list_text_keys:
            if isinstance(item, (list, tuple)):
                safe_items = [
                    entry.strip()[:128]
                    for entry in item[:32]
                    if isinstance(entry, str) and entry.strip() and "\x00" not in entry
                ]
                if safe_items:
                    result[key] = safe_items
            continue
        if isinstance(item, bool):
            continue
        if isinstance(item, (int, float)):
            if isinstance(item, float) and not math.isfinite(item):
                continue
            if key != "exit_code" and item < 0:
                continue
            if abs(item) > 10**12:
                continue
            result[key] = item
            continue
        if isinstance(item, str) and item.strip() and "\x00" not in item and "\n" not in item and "\r" not in item:
            if key == "path" and (
                item.startswith("/") or any(part == ".." for part in item.replace("\\", "/").split("/"))
            ):
                continue
            result[key] = item.strip()[:512]
    return result


def _stable_failure_code(exc: BaseException) -> str:
    if isinstance(exc, LeaseLost):
        return "lease_lost"
    candidate = getattr(exc, "code", None)
    if isinstance(candidate, str) and candidate in _SAFE_FAILURE_CODES:
        return f"git_{candidate}"
    if isinstance(exc, RuntimeError) and str(exc) == "event_store_unavailable":
        return "event_store_unavailable"
    if isinstance(candidate, str) and re.fullmatch(r"ocr_[a-z0-9_.-]{1,64}", candidate):
        return candidate
    if isinstance(exc, TimeoutError):
        return "worker_timeout"
    if isinstance(exc, OSError):
        return "worker_io"
    if isinstance(exc, ValueError):
        return "worker_invalid"
    return "worker_unknown"


def _failure_event_data(exc: BaseException) -> dict[str, object]:
    data = _safe_event_data(getattr(exc, "event_data", None))
    retryable = getattr(exc, "retryable", None)
    if isinstance(retryable, bool):
        data["retryable"] = retryable
    suggestion = getattr(exc, "suggestion", None)
    if isinstance(suggestion, str) and suggestion.strip() and "\x00" not in suggestion:
        data["suggestion"] = " ".join(suggestion.split())[:512]
    data["exception_type"] = _safe_exception_type(exc)
    location = _safe_exception_location(exc)
    if location is not None:
        data["error_location"] = location
    return data


def _safe_exception_type(exc: BaseException) -> str:
    candidate = type(exc).__name__
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", candidate):
        return "Exception"
    return candidate


def _safe_exception_location(exc: BaseException) -> str | None:
    package_root = Path(__file__).resolve().parent.parent
    location: str | None = None
    traceback = exc.__traceback__
    while traceback is not None:
        filename = Path(traceback.tb_frame.f_code.co_filename)
        try:
            relative = filename.resolve().relative_to(package_root)
        except (OSError, ValueError):
            traceback = traceback.tb_next
            continue
        function = traceback.tb_frame.f_code.co_name
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", function):
            function = "unknown"
        line = traceback.tb_lineno
        if relative.name and isinstance(line, int) and line > 0:
            location = f"{relative.name}:{function}:{line}"
        traceback = traceback.tb_next
    return location


if __name__ == "__main__":
    main()
