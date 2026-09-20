"""Git checkout and OpenCodeReview integration for the production worker."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import inspect
import logging
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import signal
import threading
from collections.abc import Mapping
from typing import Any, Callable

from argus.ocr_adapter import OCRComment, OCRRunResult, OCRScanConfig, OCRStatus, OpenCodeReviewRunner
from argus.repositories import normalize_git_url

from .models import FindingCreate, ScanProgress, ScanStatus, ServiceScanResult
from .observability import EVENT_DATA_WHITELIST
from .store import WorkerScan


_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")
_DEFAULT_OCR_COMMIT = "1f5caf4d5b7d5324c6e4c836c971136e4010192e"
_SIMPLIFIED_CHINESE_REVIEW_INSTRUCTION = (
    "输出要求：所有审查结论、问题说明和自然语言修复建议必须使用简体中文。"
    "源码、代码标识符、文件路径、规则分类和风险等级保持原样，不要翻译代码。"
)
_MAX_GIT_CAPTURE_BYTES = 64 * 1024
_EVENT_DATA_KEYS = set(EVENT_DATA_WHITELIST)
_EVENT_TYPES = {"phase", "progress", "heartbeat", "warning", "error", "scan.inventory", "session.started"}
_KNOWN_EVENT_TYPE_PREFIXES = ("file.", "llm.", "tool.", "ocr.", "scan.", "session.")
_LIFECYCLE_STAGES = {
    "queued",
    "git_fetching",
    "source_checking",
    "ocr_starting",
    "ocr_running",
    "parsing",
    "persisting",
}
_LOGGER = logging.getLogger(__name__)

EventCallback = Callable[[dict[str, object]], None]


@dataclass(frozen=True)
class _GitFailure:
    code: str
    retryable: bool
    suggestion: str
    message: str


_GIT_FAILURES = {
    "dns": _GitFailure(
        "dns", True, "verify repository host DNS and retry", "Git repository host could not be resolved"
    ),
    "connect": _GitFailure("connect", True, "verify network access and retry", "Git repository connection failed"),
    "tls": _GitFailure(
        "tls", False, "verify TLS certificates and proxy configuration", "Git repository TLS verification failed"
    ),
    "auth": _GitFailure(
        "auth", False, "check the worker Git credential helper or SSH agent", "Git repository authentication failed"
    ),
    "repo_missing": _GitFailure(
        "repo_missing", False, "verify the repository URL and access", "Git repository was not found"
    ),
    "ref_missing": _GitFailure(
        "ref_missing", False, "verify the requested branch, tag, or commit", "Git ref was not found"
    ),
    "timeout": _GitFailure("timeout", True, "retry or increase the Git timeout", "Git repository operation timed out"),
    "cancel": _GitFailure("cancel", False, "the scan was canceled", "Git repository operation was canceled"),
    "unknown": _GitFailure(
        "unknown", False, "inspect worker configuration and retry", "Git repository operation failed"
    ),
    "limit": _GitFailure(
        "limit",
        False,
        "reduce the repository size or increase the configured limit",
        "Repository safety limit was exceeded",
    ),
}


class RepositoryFetchError(RuntimeError):
    """A repository could not be cloned or checked out."""

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str = "unknown",
        retryable: bool | None = None,
        suggestion: str | None = None,
        event_data: Mapping[str, object] | None = None,
    ) -> None:
        failure = _GIT_FAILURES.get(code, _GIT_FAILURES["unknown"])
        self.code = failure.code
        self.retryable = failure.retryable if retryable is None else retryable
        self.suggestion = suggestion or failure.suggestion
        self.event_data = _safe_event_data(event_data)
        super().__init__(message or failure.message)


class RepositoryLimitError(RepositoryFetchError):
    """A cloned repository exceeded a configured safety limit."""

    def __init__(self, message: str | None = None, *, event_data: Mapping[str, object] | None = None) -> None:
        super().__init__(message, code="limit", retryable=False, event_data=event_data)


@dataclass
class PreparedWorkspace(AbstractContextManager[Path]):
    path: Path
    commit_sha: str

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *_args: object) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


class GitWorkspaceProvider:
    """Create a disposable checkout for exactly one scan attempt."""

    def __init__(
        self,
        root: str | Path,
        *,
        timeout_seconds: int = 600,
        max_bytes: int = 1 << 30,
        max_files: int = 50_000,
    ) -> None:
        if timeout_seconds <= 0 or max_bytes <= 0 or max_files <= 0:
            raise ValueError("repository limits must be positive")
        self.root = Path(root).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.root.mkdir(parents=True, exist_ok=True)

    def prepare(
        self,
        scan: WorkerScan,
        should_cancel: Callable[[], bool] | None = None,
        event_callback: EventCallback | None = None,
    ) -> PreparedWorkspace:
        self.root.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix=f"{scan.id}-", dir=self.root))
        try:
            if should_cancel is not None and should_cancel():
                raise _repository_error("cancel")
            repository_url = normalize_git_url(scan.repository_url)
            target = scan.commit_sha or scan.ref
            clone_ref = None if target and _COMMIT.fullmatch(target) else target
            clone_args = [
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-tags",
            ]
            if clone_ref:
                clone_args.extend(["--branch", clone_ref])
            clone_args.extend(["--", repository_url, str(path)])
            self._run_git(clone_args, cancel_check=should_cancel)
            if target and _COMMIT.fullmatch(target):
                self._run_git(
                    [
                        "-c",
                        "protocol.file.allow=never",
                        "-C",
                        str(path),
                        "fetch",
                        "--depth",
                        "1",
                        "origin",
                        target,
                    ],
                    cancel_check=should_cancel,
                )
                self._run_git(
                    [
                        "-c",
                        "protocol.file.allow=never",
                        "-C",
                        str(path),
                        "checkout",
                        "--detach",
                        "FETCH_HEAD",
                    ],
                    cancel_check=should_cancel,
                )
            _emit_event(
                event_callback,
                type="phase",
                source="git",
                stage="source_checking",
                level="info",
                code="source_checkout_ready",
            )
            project_config = path / ".opencodereview"
            if project_config.is_dir():
                shutil.rmtree(project_config)
            elif project_config.exists():
                project_config.unlink()
            source_files = self._check_limits(path)
            _emit_event(
                event_callback,
                type="progress",
                source="git",
                stage="source_checking",
                level="info",
                code="source_checked",
                data={"total_files": source_files},
            )
            commit = self._run_git(
                ["-c", "protocol.file.allow=never", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True,
                cancel_check=should_cancel,
            ).stdout.strip()
            if not _COMMIT.fullmatch(commit):
                raise _repository_error("unknown")
            return PreparedWorkspace(path, commit)
        except Exception as exc:
            shutil.rmtree(path, ignore_errors=True)
            if isinstance(exc, RepositoryFetchError):
                _emit_git_error(event_callback, exc)
                raise
            wrapped = _repository_error("unknown")
            _emit_git_error(event_callback, wrapped)
            raise wrapped from exc

    def _check_limits(self, path: Path) -> int:
        files = 0
        total_bytes = 0
        for root, directories, names in os.walk(path):
            retained_directories: list[str] = []
            for name in directories:
                candidate = Path(root) / name
                if name == ".git":
                    if candidate.is_symlink():
                        raise RepositoryLimitError("repository contains an unsupported symbolic link")
                    continue
                if candidate.is_symlink():
                    raise RepositoryLimitError("repository contains an unsupported symbolic link")
                retained_directories.append(name)
            directories[:] = retained_directories
            for name in names:
                candidate = Path(root) / name
                try:
                    if candidate.is_symlink():
                        raise RepositoryLimitError("repository contains an unsupported symbolic link")
                    size = candidate.stat().st_size
                except OSError as exc:
                    raise RepositoryFetchError("repository could not be inspected") from exc
                files += 1
                total_bytes += size
                if files > self.max_files:
                    raise RepositoryLimitError("repository exceeds the maximum file count")
                if total_bytes > self.max_bytes:
                    raise RepositoryLimitError("repository exceeds the maximum source size")
        return files

    def _run_git(
        self,
        args: list[str],
        *,
        capture_output: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        source_environment = os.environ
        environment = {
            name: source_environment[name]
            for name in (
                "PATH",
                "HOME",
                "LANG",
                "LC_ALL",
                "SSH_AUTH_SOCK",
                "GIT_SSH_COMMAND",
                "GIT_SSH",
                "GIT_SSH_VARIANT",
                "GIT_CONFIG_GLOBAL",
            )
            if source_environment.get(name)
        }
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        command = ["git", *args]
        process: subprocess.Popen[bytes] | None = None
        stdout_capture = _BoundedCapture(_MAX_GIT_CAPTURE_BYTES)
        stderr_capture = _BoundedCapture(_MAX_GIT_CAPTURE_BYTES)
        readers: list[threading.Thread] = []
        timed_out = False
        canceled = False
        try:
            process = subprocess.Popen(
                command,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=True,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            readers = [
                _start_reader(process.stdout, stdout_capture),
                _start_reader(process.stderr, stderr_capture),
            ]
            deadline = time.monotonic() + self.timeout_seconds
            while process.poll() is None:
                if cancel_check is not None and cancel_check():
                    canceled = True
                    _terminate_git_process(process)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    _terminate_git_process(process)
                    break
                time.sleep(0.05)
            process.wait()
            _join_readers(readers, process)
            stdout = stdout_capture.text() if capture_output else ""
            stderr = stderr_capture.text()
            event_data = {
                "stdout_bytes": stdout_capture.total_bytes,
                "stderr_bytes": stderr_capture.total_bytes,
                "timeout_seconds": self.timeout_seconds,
            }
            if process.returncode is not None:
                event_data["exit_code"] = process.returncode
            if canceled:
                raise _repository_error("cancel", event_data=event_data)
            if timed_out:
                raise _repository_error("timeout", event_data=event_data)
            if process.returncode != 0:
                failure = _classify_git_failure(f"{stdout}\n{stderr}")
                raise _repository_error(failure.code, event_data=event_data)
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except RepositoryFetchError:
            raise
        except (OSError, subprocess.SubprocessError):
            if process is not None and process.poll() is None:
                _terminate_git_process(process)
                process.wait()
            _join_readers(readers, process)
            raise _repository_error(
                "unknown",
                event_data={
                    "stdout_bytes": stdout_capture.total_bytes,
                    "stderr_bytes": stderr_capture.total_bytes,
                    "timeout_seconds": self.timeout_seconds,
                },
            )


class _BoundedCapture:
    """Drain one subprocess pipe while retaining only a bounded prefix."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.value = bytearray()
        self.total_bytes = 0

    def append(self, value: bytes) -> None:
        self.total_bytes += len(value)
        remaining = self.limit - len(self.value)
        if remaining > 0:
            self.value.extend(value[:remaining])

    def text(self) -> str:
        return bytes(self.value).decode("utf-8", errors="replace")


def _start_reader(stream: Any, capture: _BoundedCapture) -> threading.Thread:
    thread = threading.Thread(target=_drain_pipe, args=(stream, capture), daemon=True)
    thread.start()
    return thread


def _drain_pipe(stream: Any, capture: _BoundedCapture) -> None:
    try:
        while True:
            chunk = stream.read(16 * 1024)
            if not chunk:
                return
            capture.append(chunk)
    except (OSError, ValueError):
        return


def _join_readers(readers: list[threading.Thread], process: subprocess.Popen[bytes] | None) -> None:
    for reader in readers:
        reader.join(timeout=1.0)
    if any(reader.is_alive() for reader in readers) and process is not None:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for reader in readers:
            reader.join(timeout=0.5)
    if process is not None:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _terminate_git_process(process: subprocess.Popen[bytes]) -> None:
    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def _repository_error(code: str, *, event_data: Mapping[str, object] | None = None) -> RepositoryFetchError:
    failure = _GIT_FAILURES.get(code, _GIT_FAILURES["unknown"])
    return RepositoryFetchError(
        failure.message,
        code=failure.code,
        retryable=failure.retryable,
        suggestion=failure.suggestion,
        event_data=event_data,
    )


def _classify_git_failure(diagnostic: str) -> _GitFailure:
    """Classify known Git diagnostics without retaining their text."""

    normalized = " ".join(diagnostic.lower().split())
    if any(marker in normalized for marker in ("canceled", "cancelled", "cancel requested")):
        return _GIT_FAILURES["cancel"]
    if any(marker in normalized for marker in ("timed out", "timeout", "time out")):
        return _GIT_FAILURES["timeout"]
    if any(
        marker in normalized
        for marker in (
            "could not resolve host",
            "couldn't resolve host",
            "name or service not known",
            "nodename nor servname provided",
            "temporary failure in name resolution",
            "unknown host",
        )
    ):
        return _GIT_FAILURES["dns"]
    if any(
        marker in normalized
        for marker in (
            "ssl certificate problem",
            "certificate verify failed",
            "server certificate verification failed",
            "gnutls_handshake",
            "schannel",
            "tls handshake",
            " tls ",
        )
    ):
        return _GIT_FAILURES["tls"]
    if any(
        marker in normalized
        for marker in (
            "authentication failed",
            "could not read username",
            "permission denied (publickey)",
            "terminal prompts disabled",
            "access denied",
            "http 401",
            "http 403",
            " 401 ",
            " 403 ",
        )
    ):
        return _GIT_FAILURES["auth"]
    if any(
        marker in normalized
        for marker in (
            "couldn't find remote ref",
            "could not find remote ref",
            "remote branch",
            "pathspec",
            "unknown revision",
            "bad object",
            "invalid object name",
        )
    ):
        return _GIT_FAILURES["ref_missing"]
    if any(
        marker in normalized
        for marker in (
            "repository not found",
            "remote repository not found",
            "http 404",
            " 404 ",
        )
    ):
        return _GIT_FAILURES["repo_missing"]
    if any(
        marker in normalized
        for marker in (
            "failed to connect",
            "couldn't connect",
            "could not connect",
            "connection refused",
            "connection timed out",
            "connection reset",
            "network is unreachable",
            "no route to host",
            "early eof",
        )
    ):
        return _GIT_FAILURES["connect"]
    return _GIT_FAILURES["unknown"]


def _emit_git_error(callback: EventCallback | None, error: RepositoryFetchError) -> None:
    if callback is None:
        return
    stage = "source_checking" if error.code == "limit" else "git_fetching"
    data = dict(error.event_data)
    data.update({"retryable": error.retryable, "suggestion": error.suggestion})
    _emit_event(
        callback,
        type="error",
        source="git",
        stage=stage,
        level="error",
        code=f"git_{error.code}",
        message=str(error),
        data=data,
    )


def _emit_event(
    callback: EventCallback | None,
    *,
    type: str,
    source: str,
    stage: str,
    level: str,
    code: str,
    message: str | None = None,
    data: object = None,
) -> None:
    if callback is None:
        return
    if stage not in _LIFECYCLE_STAGES:
        stage = "git_fetching"
    messages = {
        "phase": "Scan phase changed",
        "progress": "Scan progress updated",
        "heartbeat": "Worker lease renewed",
        "warning": "Scan warning recorded",
        "error": "Scan error recorded",
    }
    event_type = _safe_event_type(type) or "warning"
    event: dict[str, object] = {
        "type": event_type,
        "source": _safe_label(source) or "worker",
        "stage": stage,
        "level": level if level in {"debug", "info", "notice", "warning", "error", "critical"} else "info",
        "code": _safe_code(code) or "event_recorded",
        "message": messages.get(event_type, "Scan event recorded"),
        "data": _safe_event_data(data),
    }
    callback(event)


def _safe_event_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not candidate or len(candidate) > 64 or not re.fullmatch(r"[a-z][a-z0-9_.-]*", candidate):
        return None
    if candidate in _EVENT_TYPES or candidate.startswith(_KNOWN_EVENT_TYPE_PREFIXES):
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
    if not candidate or len(candidate) > 128:
        return None
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for char in candidate):
        return None
    return candidate


def _safe_event_data(value: object, *, depth: int = 0) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    if depth > 2:
        return {}
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
    result: dict[str, Any] = {}
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


def _safe_title(content: str) -> str:
    first = " ".join(content.splitlines()).strip()
    return first[:200] or "OpenCodeReview finding"


def _finding_from_comment(comment: OCRComment) -> FindingCreate:
    category = comment.category or "security"
    severity = comment.severity or "unknown"
    fingerprint = hashlib.sha256(
        "\0".join(
            [
                comment.path,
                str(comment.start_line or 0),
                str(comment.end_line or 0),
                category,
                comment.content,
            ]
        ).encode("utf-8")
    ).hexdigest()
    return FindingCreate(
        rule_id=f"ocr/{category}",
        title=_safe_title(comment.content),
        category=category,
        severity=severity,
        file=comment.path,
        start_line=comment.start_line,
        end_line=comment.end_line,
        message=comment.content,
        evidence=comment.existing_code or "",
        remediation=comment.suggestion_code or "",
        metadata={
            "fingerprint": fingerprint,
            "ocr_category": category,
            "ocr_severity": severity,
        },
    )


class OpenCodeReviewServiceRunner:
    """Adapt one OCR invocation to the service worker result contract."""

    def __init__(
        self,
        runner: OpenCodeReviewRunner,
        *,
        token_budget: int | None,
        timeout_minutes: int | None,
        engine_commit: str = _DEFAULT_OCR_COMMIT,
        event_protocol_enabled: bool = False,
    ) -> None:
        self.runner = runner
        self.token_budget = token_budget
        self.timeout_minutes = timeout_minutes
        self.engine_commit = engine_commit if _COMMIT.fullmatch(engine_commit) else _DEFAULT_OCR_COMMIT
        self.event_protocol_enabled = event_protocol_enabled

    @classmethod
    def from_environment(cls) -> OpenCodeReviewServiceRunner:
        environment = os.environ.copy()
        environment.pop("ARGUS_API_KEY", None)
        if environment.get("ARGUS_LLM_BASE_URL") and not environment.get("OCR_LLM_URL"):
            environment["OCR_LLM_URL"] = environment["ARGUS_LLM_BASE_URL"]
        if environment.get("ARGUS_LLM_API_KEY") and not environment.get("OCR_LLM_TOKEN"):
            environment["OCR_LLM_TOKEN"] = environment["ARGUS_LLM_API_KEY"]
        environment.pop("ARGUS_LLM_API_KEY", None)
        if environment.get("ARGUS_LLM_MODEL") and not environment.get("OCR_LLM_MODEL"):
            environment["OCR_LLM_MODEL"] = environment["ARGUS_LLM_MODEL"]
        if environment.get("ARGUS_LLM_PROTOCOL") and not environment.get("OCR_LLM_PROTOCOL"):
            environment["OCR_LLM_PROTOCOL"] = environment["ARGUS_LLM_PROTOCOL"]
        if not environment.get("OCR_LLM_PROTOCOL") and not environment.get("OCR_USE_ANTHROPIC"):
            environment["OCR_LLM_PROTOCOL"] = "openai"
        event_protocol_enabled = environment.get("ARGUS_OCR_EVENT_PROTOCOL") == "1"
        # The pipe/event protocol is deliberately opt-in.  Keep the child
        # environment canonical so a future OCR runner cannot infer enablement
        # from an arbitrary value.
        environment["ARGUS_OCR_EVENT_PROTOCOL"] = "1" if event_protocol_enabled else "0"
        ocr_home = Path(environment.get("ARGUS_DATA_DIR", "data")).resolve() / "ocr-home"
        ocr_home.mkdir(parents=True, exist_ok=True)
        environment["HOME"] = str(ocr_home)
        executable = environment.get("OCR_BINARY", "ocr")
        token_budget = _positive_int(environment.get("OCR_MAX_TOKENS_BUDGET")) or 1_000_000
        timeout_minutes = _nonnegative_int(environment.get("OCR_TIMEOUT_MINUTES"))
        if timeout_minutes is None:
            timeout_minutes = 30
        engine_commit = _configured_engine_commit(environment)
        return cls(
            OpenCodeReviewRunner(
                executable,
                environment=environment,
                structured_event_protocol=event_protocol_enabled,
            ),
            token_budget=token_budget,
            timeout_minutes=timeout_minutes,
            engine_commit=engine_commit,
            event_protocol_enabled=event_protocol_enabled,
        )

    def run(
        self,
        scan: WorkerScan,
        workspace: Path,
        progress: Callable[[ScanProgress], None],
        should_cancel: Callable[[], bool],
        event_callback: EventCallback | None = None,
    ) -> ServiceScanResult:
        if should_cancel():
            _emit_event(
                event_callback,
                type="error",
                source="ocr",
                stage="ocr_starting",
                level="warning",
                code="ocr_cancel",
            )
            return ServiceScanResult(status=ScanStatus.PARTIAL, error="ocr_canceled")

        timeout_seconds = _process_timeout_seconds()
        expected_deadline = datetime.now(UTC) + timedelta(seconds=timeout_seconds)
        engine_data = self._engine_data(timeout_seconds, expected_deadline=expected_deadline)
        _emit_event(
            event_callback,
            type="phase",
            source="ocr",
            stage="ocr_starting",
            level="info",
            code="ocr_starting",
            data=engine_data,
        )
        _emit_event(
            event_callback,
            type="phase",
            source="ocr",
            stage="ocr_running",
            level="info",
            code="ocr_running",
            data=engine_data,
        )
        config = OCRScanConfig(
            paths=scan.include,
            excludes=scan.exclude,
            background=_review_background(scan.background),
            token_budget=self.token_budget,
            timeout_minutes=self.timeout_minutes,
            process_timeout_seconds=timeout_seconds,
            no_plan=True,
            no_dedup=True,
            no_summary=True,
        )
        started = time.monotonic()
        result = self._run_engine(workspace, config, should_cancel, event_callback)
        duration_ms = max(0, int((time.monotonic() - started) * 1000))
        _emit_event(
            event_callback,
            type="phase",
            source="ocr",
            stage="parsing",
            level="info",
            code="ocr_output_received",
            data=_result_event_data(result, duration_ms=duration_ms, timeout_seconds=timeout_seconds),
        )

        comments = [_finding_from_comment(comment) for comment in result.comments]
        summary = _safe_ocr_summary(result.summary)
        reviewed_value = _coverage_value(summary, "reviewed_files", "files_reviewed")
        reviewed = reviewed_value if reviewed_value is not None else 0
        total = _coverage_value(summary, "total_files", "files_total")
        failed = _coverage_value(summary, "failed_files", "files_failed") or 0
        skipped = _coverage_value(summary, "skipped_files", "files_skipped") or 0
        warning_count = _warning_count(result.warnings)
        warning_categories = _safe_ocr_warning_categories(result.warnings)
        try:
            ocr_status = result.status if isinstance(result.status, OCRStatus) else OCRStatus(result.status)
        except (TypeError, ValueError):
            ocr_status = OCRStatus.FAILED
        safe_error: str | None = None
        if ocr_status is OCRStatus.COMPLETE and reviewed_value is None:
            warning_categories.append("incomplete_coverage")
            ocr_status = OCRStatus.PARTIAL
            safe_error = "ocr_incomplete_coverage"
        if ocr_status is OCRStatus.COMPLETE and warning_count:
            ocr_status = OCRStatus.PARTIAL
        if ocr_status is OCRStatus.FAILED:
            safe_error = _safe_ocr_error(result)
        if ocr_status is OCRStatus.PARTIAL and safe_error is None and getattr(result, "canceled", False):
            safe_error = "ocr_canceled"
        accounted = reviewed + failed + skipped
        if total is not None and total < accounted:
            total = None
            warning_categories.append("inconsistent_coverage")
            if ocr_status is OCRStatus.COMPLETE:
                ocr_status = OCRStatus.PARTIAL
                safe_error = "ocr_incomplete_coverage"
        if ocr_status is OCRStatus.COMPLETE and (failed or skipped or (total is not None and total > accounted)):
            ocr_status = OCRStatus.PARTIAL
            warning_categories.append("incomplete_coverage")
            safe_error = "ocr_incomplete_coverage"
        if total is None and ocr_status is OCRStatus.COMPLETE:
            total = accounted
        # A partial result only tells us what was processed.  It cannot
        # establish how much unreviewed work remains.  Legacy counters use 0
        # for unknown totals; the observation API exposes null explicitly.
        legacy_total = total if total is not None else 0
        progress(
            ScanProgress(
                total_files=legacy_total,
                reviewed_files=reviewed,
                failed_files=failed,
                skipped_files=skipped,
                percent=_coverage_percent(legacy_total, reviewed, failed, skipped),
            )
        )
        llm = _safe_ocr_llm(result.llm)
        session_id = _safe_identifier(result.session_id)
        metadata = {
            "ocr_status": ocr_status.value,
            "ocr_summary": summary,
            "ocr_warnings": warning_categories,
            "ocr_warning_count": warning_count,
            "coverage_total_known": total is not None,
            "ocr_llm": llm,
            "ocr_exit_code": result.exit_code if isinstance(result.exit_code, int) else None,
            "ocr_duration_ms": duration_ms,
            "ocr_timeout_seconds": timeout_seconds,
            "ocr_expected_deadline_seconds": timeout_seconds,
            "ocr_expected_deadline_at": expected_deadline.isoformat(),
            "ocr_engine": "opencodereview",
            "ocr_engine_commit": self.engine_commit,
            "ocr_output_language": "zh-CN",
            "ocr_capabilities": self._capabilities(),
            "ocr_event_protocol": self.event_protocol_enabled,
        }
        status = {
            OCRStatus.COMPLETE: ScanStatus.COMPLETED,
            OCRStatus.PARTIAL: ScanStatus.PARTIAL,
            OCRStatus.SKIPPED: ScanStatus.SKIPPED,
            OCRStatus.FAILED: ScanStatus.FAILED,
        }[ocr_status]
        return ServiceScanResult(
            status=status,
            findings=comments,
            session_id=session_id,
            total_files=legacy_total,
            reviewed_files=reviewed,
            failed_files=failed,
            skipped_files=skipped,
            metadata=metadata,
            error=safe_error,
        )

    def _run_engine(
        self,
        workspace: Path,
        config: OCRScanConfig,
        should_cancel: Callable[[], bool],
        event_callback: EventCallback | None,
    ) -> OCRRunResult:
        callback = _forward_engine_event(event_callback)
        if isinstance(self.runner, OpenCodeReviewRunner):
            # OCR writes native session transcripts under HOME. Keep those
            # per attempt and ephemeral; only normalized findings and safe
            # events are retained by Argus.
            with tempfile.TemporaryDirectory(prefix="argus-ocr-home-") as home_dir:
                environment = dict(self.runner.environment or os.environ)
                environment["HOME"] = home_dir
                environment["XDG_CONFIG_HOME"] = str(Path(home_dir) / ".config")
                scoped = OpenCodeReviewRunner(
                    self.runner.executable,
                    environment=environment,
                    structured_event_protocol=self.runner.structured_event_protocol,
                )
                return scoped.run(workspace, config, cancel_check=should_cancel, event_callback=callback)
        if _supports_event_callback(self.runner):
            return self.runner.run(
                workspace,
                config,
                cancel_check=should_cancel,
                event_callback=callback,
            )
        return self.runner.run(workspace, config, cancel_check=should_cancel)

    def _engine_data(self, timeout_seconds: float, *, expected_deadline: datetime) -> dict[str, object]:
        data: dict[str, object] = {
            "timeout_seconds": timeout_seconds,
            "deadline_at": expected_deadline.isoformat(),
            "engine_commit": self.engine_commit,
            "event_protocol": self.event_protocol_enabled,
            "capabilities": {
                "event_protocol": self.event_protocol_enabled,
                "file_progress": False,
                "llm_requests": False,
            },
        }
        environment = getattr(self.runner, "environment", None)
        if isinstance(environment, Mapping):
            provider = environment.get("OCR_LLM_PROVIDER")
            model = environment.get("OCR_LLM_MODEL")
            if isinstance(provider, str):
                data["provider"] = provider
            if isinstance(model, str):
                data["model"] = model
        return _safe_event_data(data)

    def _capabilities(self) -> dict[str, bool]:
        accepts_callback = _supports_event_callback(self.runner)
        return {
            "event_callback": accepts_callback,
            "pipe_events": bool(self.event_protocol_enabled and accepts_callback),
            "event_protocol": bool(self.event_protocol_enabled and accepts_callback),
            "file_progress": False,
            "llm_requests": False,
        }


def _review_background(background: str | None) -> str:
    """Append the service-owned output-language contract to caller context."""

    if background:
        return f"{background}\n\n{_SIMPLIFIED_CHINESE_REVIEW_INSTRUCTION}"
    return _SIMPLIFIED_CHINESE_REVIEW_INSTRUCTION


def _positive_int(value: str | None) -> int | None:
    try:
        parsed = int(value) if value is not None else 0
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed >= 0 else None


def _configured_engine_commit(environment: Mapping[str, str]) -> str:
    for name in ("ARGUS_OCR_COMMIT", "OPENCODEREVIEW_COMMIT", "OCR_COMMIT"):
        value = environment.get(name)
        if isinstance(value, str) and _COMMIT.fullmatch(value.strip()):
            return value.strip().lower()
    return _DEFAULT_OCR_COMMIT


def _supports_event_callback(runner: object) -> bool:
    try:
        signature = inspect.signature(getattr(runner, "run"))
    except (AttributeError, TypeError, ValueError):
        return False
    return "event_callback" in signature.parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()
    )


def _forward_engine_event(callback: EventCallback | None) -> Callable[[object], None] | None:
    if callback is None:
        return None

    def forward(event: object) -> None:
        if not isinstance(event, Mapping):
            return
        event_type = _safe_event_type(event.get("type")) or "warning"
        stage_value = event.get("stage")
        stage = stage_value if isinstance(stage_value, str) and stage_value in _LIFECYCLE_STAGES else "ocr_running"
        level_value = event.get("level")
        level = level_value if isinstance(level_value, str) else "info"
        source_value = event.get("source")
        source = source_value if isinstance(source_value, str) else "ocr"
        code_value = event.get("code")
        code = _safe_code(code_value) or "engine_event"
        _emit_event(
            callback,
            type=event_type,
            source=source,
            stage=stage,
            level=level,
            code=code,
            data=event.get("data"),
        )

    return forward


def _result_event_data(result: OCRRunResult, *, duration_ms: int, timeout_seconds: float) -> dict[str, object]:
    data: dict[str, object] = {
        "stdout_bytes": _byte_length(getattr(result, "stdout", "")),
        "stderr_bytes": _byte_length(getattr(result, "stderr", "")),
        "duration_ms": duration_ms,
        "timeout_seconds": timeout_seconds,
    }
    exit_code = getattr(result, "exit_code", None)
    if isinstance(exit_code, int):
        data["exit_code"] = exit_code
    for key in ("request_id", "http_status", "retry_count", "provider", "model", "session_id", "path"):
        value = getattr(result, key, None)
        if value is not None:
            data[key] = value
    llm = _safe_ocr_llm(getattr(result, "llm", None))
    data.update({key: value for key, value in llm.items() if key in {"provider", "model"}})
    return _safe_event_data(data)


def _byte_length(value: object) -> int:
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    return 0


def _coverage_value(summary: Mapping[str, int | str], *keys: str) -> int | None:
    for key in keys:
        if key in summary:
            return _nonnegative_int(summary[key])
    return None


def _coverage_percent(total: int, reviewed: int, failed: int, skipped: int) -> int:
    if total <= 0:
        return 0
    return min(100, round((reviewed + failed + skipped) * 100 / total))


def _warning_count(value: object) -> int:
    if not isinstance(value, (list, tuple)):
        return 0
    return len(value)


def _safe_ocr_warning_categories(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    categories: list[str] = []
    for item in value:
        category = _warning_category(item)
        if category not in categories:
            categories.append(category)
    return categories[:32]


def _warning_category(value: object) -> str:
    if isinstance(value, Mapping):
        parts = [value.get("type"), value.get("file"), value.get("message")]
        text = " ".join(item for item in parts if isinstance(item, str)).lower()
    elif isinstance(value, str):
        text = value.lower()
    else:
        return "invalid_warning"
    if "budget" in text:
        return "budget"
    if "cancel" in text:
        return "cancel"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "auth" in text or "credential" in text or "permission" in text:
        return "auth"
    if "429" in text or "rate limit" in text or "rate_limit" in text:
        return "rate_limit"
    if "json" in text or "schema" in text or "parse" in text or "output" in text:
        return "invalid_output"
    if "file" in text or "path" in text or "read" in text:
        return "source_read"
    return "engine_warning"


def _safe_ocr_error(result: OCRRunResult) -> str:
    if bool(getattr(result, "canceled", False)):
        return "ocr_canceled"
    if bool(getattr(result, "timed_out", False)):
        return "ocr_timeout"
    raw_error = getattr(result, "error", None)
    text = raw_error.lower() if isinstance(raw_error, str) else ""
    if "timeout" in text or "timed out" in text:
        return "ocr_timeout"
    if "cancel" in text:
        return "ocr_canceled"
    if "json" in text or "schema" in text or "no json" in text:
        return "ocr_invalid_output"
    if "start" in text or "executable" in text:
        return "ocr_start_failed"
    if "output" in text and "limit" in text:
        return "ocr_output_limit"
    return "ocr_failed"


def _safe_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 256 or "\x00" in candidate or "\n" in candidate or "\r" in candidate:
        return None
    return candidate


def _safe_ocr_summary(value: object) -> dict[str, int | str]:
    """Keep only bounded, non-sensitive coverage and usage counters."""

    if not isinstance(value, Mapping):
        return {}
    allowed = {
        "total_files",
        "files_total",
        "files_reviewed",
        "reviewed_files",
        "files_failed",
        "failed_files",
        "files_skipped",
        "skipped_files",
        "comments",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "elapsed",
    }
    summary: dict[str, int | str] = {}
    for key in allowed:
        item = value.get(key)
        if key == "elapsed":
            if isinstance(item, str) and item.strip():
                summary[key] = item.strip()[:64]
            continue
        parsed = _nonnegative_int(item)
        if parsed is not None:
            summary[key] = parsed
    return summary


def _safe_ocr_llm(value: object) -> dict[str, str]:
    """Expose provider identity only; never persist arbitrary LLM metadata."""

    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key in ("provider", "model"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            candidate = item.strip()
            if "\x00" not in candidate and "\n" not in candidate and "\r" not in candidate:
                result[key] = candidate[:256]
    return result


def _process_timeout_seconds() -> float:
    value = os.getenv("OCR_PROCESS_TIMEOUT_SECONDS", "1800")
    try:
        parsed = float(value)
    except ValueError:
        return 1800.0
    return parsed if parsed > 0 else 1800.0
