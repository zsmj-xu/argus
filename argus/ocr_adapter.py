"""Small, independent adapter for OpenCodeReview's full-file scan command.

The adapter deliberately owns only the process boundary and the JSON contract.
It does not import Argus' legacy scan, review, plugin, or control-plane code, so
the service core can use it as a replaceable scanning backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import math
import os
from pathlib import Path, PurePosixPath
import queue
import re
import signal
import subprocess
import threading
import time
from typing import Any, Callable, Mapping, Sequence


class OCRSchemaError(ValueError):
    """The OCR process returned a JSON document outside the supported contract."""


class OCRStatus(str, Enum):
    """Service-level terminal states for one OCR invocation."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class OCRScanConfig:
    """Arguments accepted by the OCR full-file scanner.

    ``timeout_minutes`` is passed to OCR's per-file ``--timeout`` option.
    ``process_timeout_seconds`` is the outer subprocess deadline and is kept
    separate because OCR's timeout is expressed in minutes.
    """

    paths: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    background: str | None = None
    provider: str | None = None
    model: str | None = None
    token_budget: int | None = None
    timeout_minutes: int | None = None
    process_timeout_seconds: float | None = 1800.0
    no_plan: bool = False
    no_dedup: bool = False
    no_summary: bool = False

    @property
    def path(self) -> tuple[str, ...]:
        """CLI-shaped alias for callers that model the singular ``--path`` flag."""

        return self.paths

    @property
    def exclude(self) -> tuple[str, ...]:
        """CLI-shaped alias for callers that model the singular ``--exclude`` flag."""

        return self.excludes

    @property
    def max_tokens_budget(self) -> int | None:
        return self.token_budget

    @property
    def timeout(self) -> int | None:
        return self.timeout_minutes

    def __post_init__(self) -> None:
        object.__setattr__(self, "paths", _validate_path_options(self.paths, "paths"))
        object.__setattr__(self, "excludes", _validate_text_options(self.excludes, "excludes"))
        _validate_optional_text(self.background, "background")
        _validate_optional_text(self.provider, "provider")
        _validate_optional_text(self.model, "model")
        if self.token_budget is not None and (
            isinstance(self.token_budget, bool) or not isinstance(self.token_budget, int) or self.token_budget <= 0
        ):
            raise ValueError("token_budget must be a positive integer")
        if self.timeout_minutes is not None and (
            isinstance(self.timeout_minutes, bool)
            or not isinstance(self.timeout_minutes, int)
            or self.timeout_minutes < 0
        ):
            raise ValueError("timeout_minutes must be a non-negative integer")
        if self.process_timeout_seconds is not None and (
            isinstance(self.process_timeout_seconds, bool)
            or not isinstance(self.process_timeout_seconds, (int, float))
            or not math.isfinite(self.process_timeout_seconds)
            or self.process_timeout_seconds <= 0
        ):
            raise ValueError("process_timeout_seconds must be a finite positive number")
        for name in ("no_plan", "no_dedup", "no_summary"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")


@dataclass(frozen=True)
class OCRComment:
    """A normalized comment from OCR's ``comments`` array."""

    path: str
    start_line: int | None
    end_line: int | None
    category: str | None
    severity: str | None
    content: str
    existing_code: str | None = None
    suggestion_code: str | None = None
    thinking: str | None = None


@dataclass(frozen=True)
class OCRRunResult:
    """Process evidence plus the normalized OCR result envelope."""

    status: OCRStatus
    comments: tuple[OCRComment, ...] = ()
    warnings: tuple[Any, ...] = ()
    summary: Mapping[str, Any] | None = None
    session_id: str | None = None
    message: str | None = None
    llm: Mapping[str, Any] | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    canceled: bool = False
    error: str | None = None
    envelope: Mapping[str, Any] | None = None

    @property
    def complete(self) -> bool:
        """Whether OCR completed every selected item without warnings."""

        return self.status is OCRStatus.COMPLETE


@dataclass(frozen=True)
class _ProcessResult:
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    canceled: bool = False
    output_limited: bool = False
    error: str | None = None


@dataclass
class _InvocationOutcome:
    """Internal outcome from the bounded process monitor."""

    timed_out: bool = False
    canceled: bool = False
    output_limited: bool = False
    force_kill: bool = False
    error: str | None = None


@dataclass
class _ProcessCapture:
    """Bounded, thread-safe process capture state.

    The child is never allowed to make the parent retain more than one bounded
    buffer per output stream.  Byte counters are intentionally separate from
    the buffers so activity reporting remains safe even after a limit is hit.
    """

    limit: int
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    event_bytes: int = 0
    structured_events_seen: int = 0
    structured_events_forwarded: int = 0
    structured_events_rejected: int = 0
    structured_events_dropped: int = 0
    output_limited: bool = False
    stream_reader_error: bool = False
    event_reader_error: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def append_stream(self, stream_name: str, chunk: bytes) -> None:
        with self.lock:
            if stream_name == "stdout":
                previous = self.stdout_bytes
                self.stdout_bytes += len(chunk)
                buffer = self.stdout
            else:
                previous = self.stderr_bytes
                self.stderr_bytes += len(chunk)
                buffer = self.stderr
            remaining = max(self.limit - previous, 0)
            if remaining:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.output_limited = True

    def append_event_bytes(self, size: int) -> None:
        with self.lock:
            self.event_bytes += size

    def record_structured_event(self, *, forwarded: bool) -> None:
        with self.lock:
            self.structured_events_seen += 1
            if forwarded:
                self.structured_events_forwarded += 1
            else:
                self.structured_events_rejected += 1

    def reject_structured_event(self) -> None:
        with self.lock:
            self.structured_events_rejected += 1

    def drop_structured_event(self) -> None:
        with self.lock:
            self.structured_events_dropped += 1

    def mark_stream_reader_error(self) -> None:
        with self.lock:
            self.stream_reader_error = True

    def mark_event_reader_error(self) -> None:
        with self.lock:
            self.event_reader_error = True

    def flags(self) -> tuple[bool, bool]:
        with self.lock:
            return self.output_limited, self.stream_reader_error

    def counters(self) -> dict[str, int]:
        with self.lock:
            return {
                "stdout_bytes": self.stdout_bytes,
                "stderr_bytes": self.stderr_bytes,
                "event_bytes": self.event_bytes,
                "structured_events": self.structured_events_forwarded,
                "structured_events_rejected": self.structured_events_rejected,
                "structured_events_dropped": self.structured_events_dropped,
            }

    def captured(self) -> tuple[bytes, bytes]:
        with self.lock:
            return bytes(self.stdout), bytes(self.stderr)


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_KNOWN_COMPLETE = {"success", "complete", "completed"}
_KNOWN_PARTIAL = {"completed_with_warnings", "completed_with_errors", "partial"}
_KNOWN_SKIPPED = {"skipped"}
_KNOWN_FAILED = {"failed", "failure", "error"}
_MAX_COMMENT_COUNT = 10_000
_MAX_WARNING_COUNT = 1_000
_MAX_COMMENT_TEXT = 20_000
_MAX_CATEGORY_TEXT = 128
_MAX_SEVERITY_TEXT = 32
_MAX_SESSION_TEXT = 256
_MAX_MESSAGE_TEXT = 2_000
_MAX_WARNING_TYPE_TEXT = 128
_MAX_WARNING_PATH_TEXT = 512
_MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_STRUCTURED_EVENT_LINE_BYTES = 8 * 1024
_MAX_STRUCTURED_EVENT_COUNT = 10_000
_MAX_STRUCTURED_EVENT_DATA_FIELDS = 32
_MAX_STRUCTURED_EVENT_QUEUE = 1_024
_MAX_STRUCTURED_EVENT_TYPE_TEXT = 128
_MAX_STRUCTURED_EVENT_LABEL_TEXT = 128
_MAX_STRUCTURED_EVENT_PATH_TEXT = 512
_MAX_STRUCTURED_EVENT_TIMESTAMP_TEXT = 64
_MAX_EVENT_NUMBER = 2**63 - 1
_OUTPUT_ACTIVITY_INTERVAL_SECONDS = 2.0
_PROCESS_POLL_INTERVAL_SECONDS = 0.02
_READER_DRAIN_TIMEOUT_SECONDS = 1.0
_READER_JOIN_TIMEOUT_SECONDS = 0.5
_MAX_STRUCTURED_EVENTS_PER_TICK = 64
_EVENT_CALLBACK_ERROR = "OCR event callback failed"
_SAFE_EVENT_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@_+\-]{0,127}$")
_SAFE_EVENT_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$")

_STRUCTURED_EVENT_METADATA: dict[str, tuple[str, str, str]] = {
    "file.started": ("info", "file_started", "OCR reported a file start."),
    "file.completed": ("info", "file_completed", "OCR reported a file completion."),
    "file.failed": ("error", "file_failed", "OCR reported a file failure."),
    "scan.inventory": ("info", "scan_inventory", "OCR reported scan inventory."),
    "llm.request.started": ("info", "llm_request_started", "OCR reported an LLM request start."),
    "llm.request.headers": ("info", "llm_request_headers", "OCR reported LLM request headers."),
    "llm.request.completed": ("info", "llm_request_completed", "OCR reported an LLM request completion."),
    "llm.request.failed": ("error", "llm_request_failed", "OCR reported an LLM request failure."),
    "llm.request.retry": ("warning", "llm_request_retry", "OCR reported an LLM request retry."),
    "tool.started": ("info", "tool_started", "OCR reported a tool start."),
    "tool.completed": ("info", "tool_completed", "OCR reported a tool completion."),
    "tool.failed": ("error", "tool_failed", "OCR reported a tool failure."),
    "session.started": ("info", "session_started", "OCR reported a session start."),
}
_STRUCTURED_EVENT_DATA_FIELDS: dict[str, frozenset[str]] = {
    "file.started": frozenset(
        {
            "index",
            "ordinal",
            "total",
            "bytes",
            "size",
            "size_bytes",
            "files_total",
            "path",
            "file_id",
        }
    ),
    "file.completed": frozenset(
        {
            "index",
            "ordinal",
            "total",
            "bytes",
            "size",
            "size_bytes",
            "duration_ms",
            "comments",
            "tokens",
            "reviewed_files",
            "files_reviewed",
            "path",
            "file_id",
        }
    ),
    "file.failed": frozenset(
        {
            "index",
            "ordinal",
            "total",
            "duration_ms",
            "exit_code",
            "status_code",
            "failed_files",
            "path",
            "file_id",
        }
    ),
    "scan.inventory": frozenset(
        {
            "files",
            "files_total",
            "directories",
            "bytes",
            "size_bytes",
            "candidates",
            "unsupported",
            "skipped",
            "count",
            "total_files",
            "reviewed_files",
            "files_reviewed",
            "failed_files",
            "files_failed",
            "skipped_files",
            "files_skipped",
            "session_id",
        }
    ),
    "llm.request.started": frozenset({"retry_count", "count", "request_id", "session_id", "provider", "model"}),
    "llm.request.headers": frozenset(
        {
            "headers_count",
            "count",
            "bytes",
            "http_status",
            "status_code",
            "request_id",
            "session_id",
            "provider",
            "model",
        }
    ),
    "llm.request.completed": frozenset(
        {
            "duration_ms",
            "status_code",
            "http_status",
            "prompt_tokens",
            "completion_tokens",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "bytes",
            "request_id",
            "session_id",
            "provider",
            "model",
        }
    ),
    "llm.request.failed": frozenset(
        {
            "duration_ms",
            "status_code",
            "http_status",
            "retry_count",
            "bytes",
            "request_id",
            "session_id",
            "provider",
            "model",
        }
    ),
    "llm.request.retry": frozenset(
        {"retry_count", "duration_ms", "count", "request_id", "session_id", "provider", "model"}
    ),
    "tool.started": frozenset({"count", "tool", "tool_id", "request_id", "session_id"}),
    "tool.completed": frozenset(
        {"duration_ms", "status_code", "exit_code", "count", "tool", "tool_id", "request_id", "session_id"}
    ),
    "tool.failed": frozenset(
        {"duration_ms", "status_code", "exit_code", "count", "tool", "tool_id", "request_id", "session_id"}
    ),
    "session.started": frozenset({"pid", "count", "session_id", "provider", "model"}),
}
_STRUCTURED_EVENT_TEXT_FIELDS: dict[str, frozenset[str]] = {
    event_type: frozenset(
        field_name
        for field_name in fields
        if field_name in {"path", "file_id", "request_id", "session_id", "provider", "model", "tool", "tool_id"}
    )
    for event_type, fields in _STRUCTURED_EVENT_DATA_FIELDS.items()
}


def _validate_optional_text(value: str | None, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value.strip() or "\x00" in value):
        raise ValueError(f"{field_name} must be a non-empty string without NUL bytes")


def _validate_text_options(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be a sequence of values")
    normalized: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value.strip()
            or "\x00" in value
            or "," in value
            or _is_absolute_or_traversal(value)
        ):
            raise ValueError(f"{field_name} entries must be safe non-empty strings without NUL bytes or commas")
        normalized.append(value.strip())
    return tuple(normalized)


def _is_absolute_or_traversal(value: str) -> bool:
    candidate = value.replace("\\", "/")
    return (
        candidate.startswith("/")
        or candidate.startswith("//")
        or bool(_WINDOWS_ABSOLUTE.match(value))
        or any(part == ".." for part in candidate.split("/"))
    )


def _normalize_relative_path(value: object, *, field_name: str = "path") -> str:
    if not isinstance(value, str) or not value.strip():
        raise OCRSchemaError(f"{field_name} must be a non-empty relative path")
    raw = value.strip()
    if "\x00" in raw or "\n" in raw or "\r" in raw or _is_absolute_or_traversal(raw):
        raise OCRSchemaError(f"{field_name} must be a relative path without traversal")
    normalized = raw.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized == ".":
        raise OCRSchemaError(f"{field_name} must identify a path")
    # PurePosixPath catches the remaining odd forms without resolving against
    # the host filesystem.  The explicit component check above is intentional:
    # a path such as ``a/../b`` must be rejected rather than silently cleaned.
    normalized = PurePosixPath(normalized).as_posix()
    if normalized in {"", "."}:
        raise OCRSchemaError(f"{field_name} must identify a path")
    return normalized


def _validate_path_options(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be a sequence of paths")
    normalized: list[str] = []
    for value in values:
        if isinstance(value, str) and "," in value:
            raise ValueError(f"{field_name} entries must not contain commas")
        try:
            normalized.append(_normalize_relative_path(value, field_name=f"{field_name} entry"))
        except OCRSchemaError as exc:
            raise ValueError(str(exc)) from exc
    return tuple(normalized)


def _optional_string(value: object, field_name: str, *, max_length: int = _MAX_COMMENT_TEXT) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise OCRSchemaError(f"{field_name} must be a string when present")
    normalized = value.strip()
    if len(normalized) > max_length:
        raise OCRSchemaError(f"{field_name} exceeds the maximum length of {max_length} characters")
    return normalized or None


def _line(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OCRSchemaError(f"{field_name} must be a positive integer")
    return value


def normalize_comment(value: object) -> OCRComment:
    """Validate and normalize one OCR comment.

    OCR legitimately emits comments without a location.  A location is either
    absent as a whole or has both positive ``start_line`` and ``end_line``;
    accepting only one endpoint would make downstream inline rendering unsafe.
    """

    if not isinstance(value, Mapping):
        raise OCRSchemaError("each OCR comment must be an object")
    path = _normalize_relative_path(value.get("path"))
    start_line = _line(value.get("start_line"), "start_line")
    end_line = _line(value.get("end_line"), "end_line")
    if (start_line is None) != (end_line is None):
        raise OCRSchemaError("start_line and end_line must be supplied together")
    if start_line is not None and end_line is not None and end_line < start_line:
        raise OCRSchemaError("end_line must be greater than or equal to start_line")

    content = value.get("content")
    if not isinstance(content, str) or not content.strip():
        raise OCRSchemaError("comment content must be a non-empty string")
    content = content.strip()
    if len(content) > _MAX_COMMENT_TEXT:
        raise OCRSchemaError(f"comment content exceeds the maximum length of {_MAX_COMMENT_TEXT} characters")
    category = _optional_string(value.get("category"), "category", max_length=_MAX_CATEGORY_TEXT)
    severity = _optional_string(value.get("severity"), "severity", max_length=_MAX_SEVERITY_TEXT)
    if category is not None:
        category = category.lower()
    if severity is not None:
        severity = severity.lower()
    existing_code = _optional_string(value.get("existing_code"), "existing_code")
    suggestion_code = _optional_string(value.get("suggestion_code"), "suggestion_code")
    # Upstream can attach long reasoning transcripts to a valid finding.
    # They are not part of the service finding contract and must never be
    # retained or make otherwise valid findings fail normalization.
    thinking = None
    return OCRComment(
        path=path,
        start_line=start_line,
        end_line=end_line,
        category=category,
        severity=severity,
        content=content,
        existing_code=existing_code,
        suggestion_code=suggestion_code,
        thinking=thinking,
    )


def _normalize_warning(value: object) -> str | dict[str, str]:
    if isinstance(value, str):
        warning_text = value.strip()
        if len(warning_text) > _MAX_MESSAGE_TEXT:
            raise OCRSchemaError(f"OCR warning exceeds the maximum length of {_MAX_MESSAGE_TEXT} characters")
        return warning_text
    if not isinstance(value, Mapping):
        raise OCRSchemaError("OCR warnings must contain strings or warning objects")
    if set(value) - {"type", "file", "message"}:
        raise OCRSchemaError("OCR warning object contains unsupported fields")
    warning_type = _optional_string(value.get("type"), "OCR warning type", max_length=_MAX_WARNING_TYPE_TEXT)
    if warning_type is not None and any(character in warning_type for character in ("\x00", "\r", "\n")):
        raise OCRSchemaError("OCR warning type contains control characters")
    warning_file_value = value.get("file")
    warning_file: str | None = None
    if warning_file_value is not None and warning_file_value != "":
        warning_file = _normalize_relative_path(warning_file_value, field_name="OCR warning file")
        if len(warning_file) > _MAX_WARNING_PATH_TEXT:
            raise OCRSchemaError(f"OCR warning file exceeds the maximum length of {_MAX_WARNING_PATH_TEXT} characters")
    warning_message = _optional_string(value.get("message"), "OCR warning message", max_length=_MAX_MESSAGE_TEXT)
    if warning_message is not None and any(character in warning_message for character in ("\x00", "\r", "\n")):
        raise OCRSchemaError("OCR warning message contains control characters")
    if warning_type is None and warning_file is None and warning_message is None:
        raise OCRSchemaError("OCR warning object must contain type, file, or message")
    normalized_warning: dict[str, str] = {}
    if warning_type is not None:
        normalized_warning["type"] = warning_type
    if warning_file is not None:
        normalized_warning["file"] = warning_file
    if warning_message is not None:
        normalized_warning["message"] = warning_message
    return normalized_warning


def parse_ocr_envelope(
    document: object,
) -> tuple[
    OCRStatus,
    tuple[OCRComment, ...],
    tuple[Any, ...],
    Mapping[str, Any] | None,
    str | None,
    str | None,
    Mapping[str, Any] | None,
]:
    """Parse OCR's top-level JSON object into service-level values."""

    if not isinstance(document, Mapping):
        raise OCRSchemaError("OCR JSON output must be a top-level object")
    raw_status = document.get("status")
    if not isinstance(raw_status, str):
        raise OCRSchemaError("OCR JSON output must contain a string status")
    status_value = raw_status.strip().lower()
    if status_value in _KNOWN_COMPLETE:
        status = OCRStatus.COMPLETE
    elif status_value in _KNOWN_PARTIAL:
        status = OCRStatus.PARTIAL
    elif status_value in _KNOWN_SKIPPED:
        status = OCRStatus.SKIPPED
    elif status_value in _KNOWN_FAILED:
        status = OCRStatus.FAILED
    else:
        raise OCRSchemaError("unsupported OCR status")

    if "comments" not in document:
        raise OCRSchemaError("OCR JSON output must contain a comments array")
    raw_comments = document["comments"]
    if not isinstance(raw_comments, list):
        raise OCRSchemaError("OCR comments must be an array")
    if len(raw_comments) > _MAX_COMMENT_COUNT:
        raise OCRSchemaError(f"OCR comments exceed the maximum count of {_MAX_COMMENT_COUNT}")
    comments = tuple(normalize_comment(item) for item in raw_comments)

    raw_warnings = document.get("warnings", [])
    if not isinstance(raw_warnings, list):
        raise OCRSchemaError("OCR warnings must be an array when present")
    if len(raw_warnings) > _MAX_WARNING_COUNT:
        raise OCRSchemaError(f"OCR warnings exceed the maximum count of {_MAX_WARNING_COUNT}")
    warnings_list: list[Any] = []
    for item in raw_warnings:
        warnings_list.append(_normalize_warning(item))
    warnings = tuple(warnings_list)
    if status is OCRStatus.COMPLETE and warnings:
        status = OCRStatus.PARTIAL

    summary = document.get("summary")
    if summary is not None and not isinstance(summary, Mapping):
        raise OCRSchemaError("OCR summary must be an object when present")
    session_id = _optional_string(document.get("session_id"), "session_id", max_length=_MAX_SESSION_TEXT)
    message = _optional_string(document.get("message"), "message", max_length=_MAX_MESSAGE_TEXT)
    llm = document.get("llm")
    if llm is not None and not isinstance(llm, Mapping):
        raise OCRSchemaError("OCR llm must be an object when present")
    return status, comments, warnings, summary, session_id, message, llm


class OpenCodeReviewRunner:
    """Run a configured OCR executable in an isolated checkout."""

    def __init__(
        self,
        executable: str | Path = "ocr",
        *,
        environment: Mapping[str, str] | None = None,
        structured_event_protocol: bool = False,
    ) -> None:
        if isinstance(executable, Path):
            executable_value = str(executable)
        elif isinstance(executable, str) and executable.strip():
            executable_value = executable.strip()
        else:
            raise ValueError("executable must be a non-empty path or command name")
        if "\x00" in executable_value:
            raise ValueError("executable must not contain NUL bytes")
        if not isinstance(structured_event_protocol, bool):
            raise ValueError("structured_event_protocol must be a boolean")
        self.executable = executable_value
        self.environment = dict(environment) if environment is not None else None
        self.structured_event_protocol = structured_event_protocol

    def build_argv(self, config: OCRScanConfig | None = None) -> list[str]:
        """Build the exact argv passed to OCR, without invoking a shell."""

        selected = config or OCRScanConfig()
        argv = [self.executable, "scan", "--format", "json", "--audience", "agent"]
        if selected.paths:
            argv.extend(["--path", ",".join(selected.paths)])
        if selected.excludes:
            argv.extend(["--exclude", ",".join(selected.excludes)])
        if selected.background is not None:
            argv.extend(["--background", selected.background])
        if selected.provider is not None:
            argv.extend(["--provider", selected.provider])
        if selected.model is not None:
            argv.extend(["--model", selected.model])
        if selected.token_budget is not None:
            argv.extend(["--max-tokens-budget", str(selected.token_budget)])
        if selected.timeout_minutes is not None:
            argv.extend(["--timeout", str(selected.timeout_minutes)])
        if selected.no_plan:
            argv.append("--no-plan")
        if selected.no_dedup:
            argv.append("--no-dedup")
        if selected.no_summary:
            argv.append("--no-summary")
        return argv

    def run(
        self,
        checkout: str | Path | None = None,
        config: OCRScanConfig | None = None,
        *,
        repo_dir: str | Path | None = None,
        paths: Sequence[str] | str | None = None,
        excludes: Sequence[str] | str | None = None,
        background: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        token_budget: int | None = None,
        timeout_minutes: int | None = None,
        process_timeout_seconds: float | None = None,
        timeout: int | None = None,
        cancel_check: Callable[[], bool] | None = None,
        should_cancel: Callable[[], bool] | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> OCRRunResult:
        """Run OCR and return process evidence plus normalized findings."""

        if checkout is not None and repo_dir is not None:
            raise ValueError("use checkout or repo_dir, not both")
        if checkout is None:
            checkout = repo_dir
        if checkout is None:
            raise ValueError("checkout must be provided")
        if cancel_check is not None and should_cancel is not None:
            raise ValueError("use cancel_check or should_cancel, not both")
        cancel_check = cancel_check or should_cancel
        checkout_path = Path(checkout)
        if not checkout_path.is_dir():
            raise ValueError("checkout must be an existing directory")
        checkout_path = checkout_path.resolve()
        overrides = (
            paths,
            excludes,
            background,
            provider,
            model,
            token_budget,
            timeout_minutes,
            process_timeout_seconds,
            timeout,
        )
        if config is not None and any(value is not None for value in overrides):
            raise ValueError("config cannot be combined with direct scan options")
        if timeout is not None:
            if timeout_minutes is not None:
                raise ValueError("use timeout or timeout_minutes, not both")
            timeout_minutes = timeout
        if config is None:
            selected = OCRScanConfig(
                paths=_as_sequence(paths),
                excludes=_as_sequence(excludes),
                background=background,
                provider=provider,
                model=model,
                token_budget=token_budget,
                timeout_minutes=timeout_minutes,
                process_timeout_seconds=process_timeout_seconds if process_timeout_seconds is not None else 1800.0,
            )
        else:
            selected = config
        event_sink = _EventSink(event_callback) if event_callback is not None else None
        process = self._invoke(checkout_path, selected, cancel_check=cancel_check, event_callback=event_sink)
        callback = event_sink
        if process.canceled:
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                canceled=True,
                error=process.error or "OpenCodeReview canceled",
            )
        if process.timed_out:
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                timed_out=True,
                error=process.error or "OpenCodeReview timed out",
            )

        if process.error is not None:
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                error=process.error,
            )

        envelope: Mapping[str, Any] | None = None
        parsed: (
            tuple[
                OCRStatus,
                tuple[OCRComment, ...],
                tuple[Any, ...],
                Mapping[str, Any] | None,
                str | None,
                str | None,
                Mapping[str, Any] | None,
            ]
            | None
        ) = None
        parse_error: str | None = None
        parse_error_code = "missing_json"
        try:
            _emit_event(
                callback,
                event_type="ocr.parse_started",
                stage="parsing",
                level="info",
                code="parse_started",
                message="Parsing OCR JSON output.",
            )
        except _EventCallbackFailure:
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                error=_EVENT_CALLBACK_ERROR,
            )
        if process.stdout.strip():
            try:
                decoded = json.loads(process.stdout)
                if not isinstance(decoded, Mapping):
                    raise OCRSchemaError("OCR JSON output must be a top-level object")
                envelope = decoded
                parsed = parse_ocr_envelope(decoded)
            except json.JSONDecodeError:
                parse_error = "invalid OCR JSON output"
                parse_error_code = "invalid_json"
            except OCRSchemaError as exc:
                parse_error = "invalid OCR JSON schema"
                parse_error_code = _schema_error_code(exc)
        else:
            parse_error = "OCR produced no JSON output"

        if parse_error is not None:
            try:
                _emit_event(
                    callback,
                    event_type="ocr.parse_error",
                    stage="parsing",
                    level="error",
                    code=parse_error_code,
                    message="OCR JSON output could not be parsed.",
                )
            except _EventCallbackFailure:
                parse_error = _EVENT_CALLBACK_ERROR
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                error=parse_error,
                envelope=envelope,
            )
        assert parsed is not None
        status, comments, warnings, summary, session_id, message, llm = parsed
        try:
            _emit_event(
                callback,
                event_type="ocr.parse_finished",
                stage="parsing",
                level="info",
                code="parse_finished",
                message="OCR JSON output parsed.",
                data={"comments": len(comments), "warnings": len(warnings)},
            )
        except _EventCallbackFailure:
            return OCRRunResult(
                status=OCRStatus.FAILED,
                stdout=process.stdout,
                stderr=process.stderr,
                exit_code=process.exit_code,
                error=_EVENT_CALLBACK_ERROR,
                envelope=envelope,
            )
        if status is OCRStatus.COMPLETE and warnings:
            status = OCRStatus.PARTIAL
        if process.exit_code not in (0, None):
            status = OCRStatus.FAILED
            error = f"OpenCodeReview exited with status {process.exit_code}"
        else:
            error = None
        return OCRRunResult(
            status=status,
            comments=comments,
            warnings=warnings,
            summary=summary,
            session_id=session_id,
            message=message,
            llm=llm,
            stdout=process.stdout,
            stderr=process.stderr,
            exit_code=process.exit_code,
            error=error,
            envelope=envelope,
        )

    # ``scan`` makes the service-facing verb explicit while keeping ``run``
    # convenient for generic worker interfaces.
    scan = run
    __call__ = run

    def _invoke(
        self,
        checkout: Path,
        config: OCRScanConfig,
        *,
        cancel_check: Callable[[], bool] | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> _ProcessResult:
        """Run OCR with bounded concurrent readers on every invocation path."""

        process: subprocess.Popen[bytes] | None = None
        event_read_stream: Any = None
        event_read_fd: int | None = None
        event_write_fd: int | None = None
        readers: list[threading.Thread] = []
        event_queue: queue.Queue[dict[str, Any]] | None = None
        capture = _ProcessCapture(_MAX_PROCESS_OUTPUT_BYTES)
        outcome = _InvocationOutcome()
        cleanup_force = False
        callback_failed = False

        try:
            if self.structured_event_protocol:
                event_read_fd, event_write_fd = os.pipe()
                event_read_stream = os.fdopen(event_read_fd, "rb", buffering=0)
                event_read_fd = None

            popen_kwargs: dict[str, Any] = {
                "cwd": str(checkout),
                "env": _child_environment(self.environment, event_write_fd),
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "shell": False,
                "text": False,
                "bufsize": 0,
                "start_new_session": True,
            }
            if event_write_fd is not None:
                # ``pass_fds`` is deliberately added only for the explicit
                # structured protocol opt-in.  The ordinary OCR process gets
                # no inherited diagnostics channel.
                popen_kwargs["pass_fds"] = (event_write_fd,)
            process = subprocess.Popen(self.build_argv(config), **popen_kwargs)
            process_deadline = (
                time.monotonic() + config.process_timeout_seconds
                if config.process_timeout_seconds is not None
                else None
            )
            if event_write_fd is not None:
                os.close(event_write_fd)
                event_write_fd = None

            if event_callback is not None:
                event_queue = queue.Queue(maxsize=_MAX_STRUCTURED_EVENT_QUEUE)
            readers.append(
                threading.Thread(
                    target=_read_bounded_stream, args=(getattr(process, "stdout", None), "stdout", capture)
                )
            )
            readers.append(
                threading.Thread(
                    target=_read_bounded_stream, args=(getattr(process, "stderr", None), "stderr", capture)
                )
            )
            if event_read_stream is not None:
                readers.append(
                    threading.Thread(
                        target=_read_structured_events,
                        args=(event_read_stream, capture, event_queue),
                    )
                )
            for reader in readers:
                reader.daemon = True
                reader.start()

            _emit_event(
                event_callback,
                event_type="ocr.started",
                stage="ocr_starting",
                level="info",
                code="process_started",
                message="OpenCodeReview process started.",
                data=_numeric_data("pid", _process_pid(process)),
            )

            outcome = _monitor_process(
                process,
                config,
                capture,
                readers,
                event_queue,
                event_callback,
                cancel_check,
                process_deadline,
            )
            cleanup_force = outcome.force_kill or _event_sink_failed(event_callback)
        except _EventCallbackFailure:
            callback_failed = True
            cleanup_force = True
            outcome = _InvocationOutcome(force_kill=True, error=_EVENT_CALLBACK_ERROR)
        except (OSError, TypeError, ValueError):
            cleanup_force = process is not None
            outcome = _InvocationOutcome(
                force_kill=cleanup_force,
                error="could not start OpenCodeReview" if process is None else "could not monitor OpenCodeReview",
            )
        except BaseException:
            cleanup_force = True
            raise
        finally:
            if event_read_fd is not None:
                _close_quietly(event_read_fd)
            if event_write_fd is not None:
                _close_quietly(event_write_fd)
            if process is not None:
                orphaned = _cleanup_process(process, readers, event_read_stream, cleanup_force)
            else:
                orphaned = False
            if event_read_stream is not None and not readers:
                _close_quietly(event_read_stream)

        if process is None:
            return _ProcessResult(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                error=outcome.error or "could not start OpenCodeReview",
            )

        stdout_bytes, stderr_bytes = capture.captured()
        exit_code = _process_returncode(process)
        if orphaned and outcome.error is None:
            outcome.error = "OpenCodeReview output readers did not terminate"
        result = _ProcessResult(
            stdout=_as_text(stdout_bytes),
            stderr=_as_text(stderr_bytes),
            exit_code=exit_code,
            timed_out=outcome.timed_out,
            canceled=outcome.canceled,
            output_limited=outcome.output_limited,
            error=outcome.error,
        )
        if callback_failed:
            return result

        try:
            terminal_data = capture.counters()
            if exit_code is not None:
                terminal_data["exit_code"] = exit_code
            if outcome.timed_out:
                _emit_event(
                    event_callback,
                    event_type="ocr.timeout",
                    stage="ocr_running",
                    level="error",
                    code="process_timeout",
                    message="OpenCodeReview process timed out.",
                    data=terminal_data,
                )
            elif outcome.canceled:
                _emit_event(
                    event_callback,
                    event_type="ocr.canceled",
                    stage="ocr_running",
                    level="warning",
                    code="process_canceled",
                    message="OpenCodeReview process was canceled.",
                    data=terminal_data,
                )
            elif outcome.output_limited:
                _emit_event(
                    event_callback,
                    event_type="ocr.output_limit",
                    stage="ocr_running",
                    level="error",
                    code="process_output_limit",
                    message="OpenCodeReview process output exceeded its limit.",
                    data=terminal_data,
                )
            _emit_event(
                event_callback,
                event_type="ocr.exited",
                stage="ocr_running",
                level="info" if exit_code == 0 else "error",
                code="process_exited",
                message="OpenCodeReview process exited.",
                data=terminal_data,
            )
        except _EventCallbackFailure:
            return _ProcessResult(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                canceled=result.canceled,
                output_limited=result.output_limited,
                error=_EVENT_CALLBACK_ERROR,
            )
        if _event_sink_failed(event_callback):
            try:
                _terminate_process(process)
            except (AttributeError, OSError, ProcessLookupError):
                pass
        return result


class _EventSink:
    """Best-effort callback boundary that disables a failing consumer."""

    def __init__(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self.callback = callback
        self.failed = False

    def __call__(self, event: dict[str, Any]) -> None:
        if self.failed:
            return
        try:
            self.callback(event)
        except BaseException:
            # Telemetry consumers must not be able to poison the authoritative
            # OCR result.  The process monitor still drains and cleans up the
            # child; the consumer is simply disabled for the rest of the run.
            self.failed = True


class _EventCallbackFailure(Exception):
    """Internal marker used after an event callback has raised."""


def _event_sink_failed(event_callback: Callable[[dict[str, Any]], None] | None) -> bool:
    return isinstance(event_callback, _EventSink) and event_callback.failed


def _call_event_callback(
    event_callback: Callable[[dict[str, Any]], None] | None,
    event: dict[str, Any],
) -> None:
    if event_callback is None:
        return
    try:
        event_callback(event)
    except BaseException:
        # Do not carry callback exception text into the process result or any
        # emitted event.  The caller receives a safe, stable failure instead.
        raise _EventCallbackFailure from None


def _emit_event(
    event_callback: Callable[[dict[str, Any]], None] | None,
    *,
    event_type: str,
    stage: str,
    level: str,
    code: str,
    message: str,
    data: Mapping[str, int] | None = None,
) -> None:
    """Emit the fixed, source-free event envelope used by the service."""

    if event_callback is None:
        return
    _call_event_callback(
        event_callback,
        {
            "source": "ocr",
            "type": event_type,
            "stage": stage,
            "level": level,
            "code": code,
            "message": message,
            "data": dict(data or {}),
        },
    )


def _numeric_data(name: str, value: int | None) -> dict[str, int]:
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return {}
    return {name: value}


def _process_pid(process: subprocess.Popen[Any]) -> int | None:
    value = getattr(process, "pid", None)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _process_returncode(process: subprocess.Popen[Any]) -> int | None:
    value = getattr(process, "returncode", None)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _child_environment(
    environment: Mapping[str, str] | None,
    event_write_fd: int | None,
) -> dict[str, str]:
    child_environment = dict(os.environ if environment is None else environment)
    # Never let a caller-provided stale descriptor value cause accidental
    # inheritance.  The protocol is enabled only by this invocation's pipe.
    child_environment.pop("ARGUS_OCR_EVENTS_FD", None)
    if event_write_fd is not None:
        child_environment["ARGUS_OCR_EVENTS_FD"] = str(event_write_fd)
    return child_environment


def _read_bounded_stream(stream: Any, stream_name: str, capture: _ProcessCapture) -> None:
    """Drain one child stream concurrently while retaining only its prefix."""

    try:
        if stream is None:
            return
        while True:
            read1 = getattr(stream, "read1", None)
            chunk = read1(64 * 1024) if callable(read1) else stream.read(64 * 1024)
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            elif isinstance(chunk, (bytearray, memoryview)):
                chunk = bytes(chunk)
            if not isinstance(chunk, bytes):
                capture.mark_stream_reader_error()
                return
            capture.append_stream(stream_name, chunk)
    except BaseException:
        capture.mark_stream_reader_error()


def _safe_event_number(key: object, value: object) -> int | None:
    if not isinstance(key, str):
        return None
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > _MAX_EVENT_NUMBER:
        return None
    if key != "exit_code" and value < 0:
        return None
    return value


def _safe_event_text(key: str, value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    if key == "path":
        if len(value) > _MAX_STRUCTURED_EVENT_PATH_TEXT:
            return None
        try:
            return _normalize_relative_path(value, field_name="event path")
        except OCRSchemaError:
            return None
    if len(value) > _MAX_STRUCTURED_EVENT_LABEL_TEXT or not _SAFE_EVENT_LABEL.fullmatch(value):
        return None
    return value


def _normalize_structured_event(line: bytes) -> dict[str, Any] | None:
    """Turn one v1 NDJSON line into a safe event, or reject it silently."""

    if len(line) > _MAX_STRUCTURED_EVENT_LINE_BYTES:
        return None
    try:
        document = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, Mapping):
        return None
    if set(document) - {"version", "type", "timestamp", "data"}:
        return None
    version = document.get("version")
    if "version" not in document or isinstance(version, bool) or version != 1:
        return None
    timestamp = document.get("timestamp")
    if timestamp is not None and (
        not isinstance(timestamp, str)
        or len(timestamp) > _MAX_STRUCTURED_EVENT_TIMESTAMP_TEXT
        or not _SAFE_EVENT_TIMESTAMP.fullmatch(timestamp)
    ):
        return None
    event_type = document.get("type")
    if not isinstance(event_type, str) or len(event_type) > _MAX_STRUCTURED_EVENT_TYPE_TEXT:
        return None
    metadata = _STRUCTURED_EVENT_METADATA.get(event_type)
    allowed_fields = _STRUCTURED_EVENT_DATA_FIELDS.get(event_type)
    if metadata is None or allowed_fields is None:
        return None
    if "data" not in document:
        return None
    raw_data = document["data"]
    if not isinstance(raw_data, Mapping) or len(raw_data) > _MAX_STRUCTURED_EVENT_DATA_FIELDS:
        return None

    safe_data: dict[str, int | str] = {}
    for key, value in raw_data.items():
        if key not in allowed_fields:
            continue
        safe_value = _safe_event_number(key, value)
        if safe_value is not None:
            safe_data[key] = safe_value
            continue
        if key not in _STRUCTURED_EVENT_TEXT_FIELDS[event_type]:
            continue
        safe_text = _safe_event_text(key, value)
        if safe_text is not None:
            safe_data[key] = safe_text
    level, code, message = metadata
    return {
        "source": "ocr",
        "type": event_type,
        "stage": "ocr_running",
        "level": level,
        "code": code,
        "message": message,
        "data": safe_data,
    }


def _consume_structured_line(
    line: bytes,
    capture: _ProcessCapture,
    event_queue: queue.Queue[dict[str, Any]] | None,
) -> None:
    with capture.lock:
        if capture.structured_events_seen >= _MAX_STRUCTURED_EVENT_COUNT:
            capture.structured_events_dropped += 1
            return
    event = _normalize_structured_event(line)
    if event is None:
        capture.record_structured_event(forwarded=False)
        return
    if event_queue is None:
        capture.record_structured_event(forwarded=True)
        return
    try:
        event_queue.put_nowait(event)
    except queue.Full:
        capture.record_structured_event(forwarded=False)
        capture.drop_structured_event()
        return
    capture.record_structured_event(forwarded=True)


def _read_structured_events(
    stream: Any,
    capture: _ProcessCapture,
    event_queue: queue.Queue[dict[str, Any]] | None,
) -> None:
    """Drain the optional event fd without retaining unbounded lines."""

    pending = bytearray()
    oversized_line = False
    try:
        if stream is None:
            return
        while True:
            read1 = getattr(stream, "read1", None)
            chunk = read1(64 * 1024) if callable(read1) else stream.read(64 * 1024)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            elif isinstance(chunk, (bytearray, memoryview)):
                chunk = bytes(chunk)
            if not isinstance(chunk, bytes):
                capture.mark_event_reader_error()
                return
            capture.append_event_bytes(len(chunk))
            pieces = chunk.split(b"\n")
            for index, piece in enumerate(pieces):
                complete = index < len(pieces) - 1
                if oversized_line:
                    if complete:
                        oversized_line = False
                    continue
                if len(pending) + len(piece) > _MAX_STRUCTURED_EVENT_LINE_BYTES:
                    pending.clear()
                    capture.reject_structured_event()
                    capture.drop_structured_event()
                    oversized_line = not complete
                    continue
                pending.extend(piece)
                if complete:
                    _consume_structured_line(bytes(pending).rstrip(b"\r"), capture, event_queue)
                    pending.clear()
        if pending and not oversized_line:
            _consume_structured_line(bytes(pending).rstrip(b"\r"), capture, event_queue)
    except BaseException:
        capture.mark_event_reader_error()


def _dispatch_structured_events(
    event_queue: queue.Queue[dict[str, Any]] | None,
    event_callback: Callable[[dict[str, Any]], None] | None,
    limit: int = _MAX_STRUCTURED_EVENTS_PER_TICK,
) -> None:
    if event_queue is None or event_callback is None:
        return
    dispatched = 0
    while dispatched < limit:
        try:
            event = event_queue.get_nowait()
        except queue.Empty:
            return
        _call_event_callback(event_callback, event)
        dispatched += 1


def _monitor_process(
    process: subprocess.Popen[bytes],
    config: OCRScanConfig,
    capture: _ProcessCapture,
    readers: Sequence[threading.Thread],
    event_queue: queue.Queue[dict[str, Any]] | None,
    event_callback: Callable[[dict[str, Any]], None] | None,
    cancel_check: Callable[[], bool] | None,
    deadline: float | None,
) -> _InvocationOutcome:
    exited_at: float | None = None
    last_activity_total = 0
    last_activity_at: float | None = None

    while True:
        _dispatch_structured_events(event_queue, event_callback)
        output_limited, reader_error = capture.flags()
        if output_limited:
            return _InvocationOutcome(
                output_limited=True,
                force_kill=True,
                error="OpenCodeReview process output exceeded the configured limit",
            )
        if reader_error:
            return _InvocationOutcome(force_kill=True, error="could not read OpenCodeReview process output")

        now = time.monotonic()
        returncode = process.poll()
        finished = False
        if returncode is None:
            if cancel_check is not None:
                try:
                    if cancel_check():
                        return _InvocationOutcome(
                            canceled=True,
                            force_kill=True,
                            error="OpenCodeReview canceled",
                        )
                except BaseException:
                    return _InvocationOutcome(force_kill=True, error="OCR cancellation callback failed")
            if deadline is not None and now >= deadline:
                return _InvocationOutcome(
                    timed_out=True,
                    force_kill=True,
                    error="OpenCodeReview subprocess timed out",
                )
        else:
            if exited_at is None:
                exited_at = now
            if not any(reader.is_alive() for reader in readers):
                _dispatch_structured_events(event_queue, event_callback, limit=_MAX_STRUCTURED_EVENT_QUEUE)
                finished = True
            if now - exited_at >= _READER_DRAIN_TIMEOUT_SECONDS:
                return _InvocationOutcome(
                    force_kill=True,
                    error="OpenCodeReview output readers did not terminate",
                )

        counters = capture.counters()
        activity_total = sum(counters.values())
        if activity_total > last_activity_total and (
            last_activity_at is None or now - last_activity_at >= _OUTPUT_ACTIVITY_INTERVAL_SECONDS
        ):
            _emit_event(
                event_callback,
                event_type="ocr.output_activity",
                stage="ocr_running",
                level="info",
                code="output_activity",
                message="OpenCodeReview produced output activity.",
                data=counters,
            )
            last_activity_total = activity_total
            last_activity_at = now
        if finished:
            break
        time.sleep(_PROCESS_POLL_INTERVAL_SECONDS)

    return _InvocationOutcome()


def _reap_process(process: subprocess.Popen[Any]) -> None:
    wait = getattr(process, "wait", None)
    if callable(wait):
        try:
            wait()
        except (ChildProcessError, OSError):
            return
        return
    communicate = getattr(process, "communicate", None)
    if callable(communicate):
        try:
            communicate()
        except (ChildProcessError, OSError):
            return


def _close_quietly(value: Any) -> None:
    try:
        if isinstance(value, int):
            os.close(value)
        else:
            value.close()
    except (AttributeError, OSError, ValueError):
        return


def _close_process_streams(process: subprocess.Popen[Any], event_read_stream: Any) -> None:
    _close_quietly(getattr(process, "stdout", None))
    _close_quietly(getattr(process, "stderr", None))
    if event_read_stream is not None:
        _close_quietly(event_read_stream)


def _join_readers(readers: Sequence[threading.Thread], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    for reader in readers:
        remaining = max(deadline - time.monotonic(), 0.0)
        reader.join(remaining)
    return any(reader.is_alive() for reader in readers)


def _cleanup_process(
    process: subprocess.Popen[Any],
    readers: Sequence[threading.Thread],
    event_read_stream: Any,
    force_kill: bool,
) -> bool:
    """Kill/reap the group when needed and always close/join process resources."""

    attempted_kill = False
    try:
        if force_kill or process.poll() is None:
            _terminate_process(process)
            attempted_kill = True
    except (OSError, ProcessLookupError, AttributeError):
        attempted_kill = True

    _reap_process(process)
    if attempted_kill:
        _close_process_streams(process, event_read_stream)

    readers_alive = _join_readers(readers, _READER_JOIN_TIMEOUT_SECONDS)
    if readers_alive:
        # A child helper can keep an inherited pipe open after the group leader
        # exits.  Kill the session group and close parent read ends before the
        # final join so no descendant or reader survives the boundary.
        try:
            _terminate_process(process)
        except (OSError, ProcessLookupError, AttributeError):
            pass
        _reap_process(process)
        _close_process_streams(process, event_read_stream)
        readers_alive = _join_readers(readers, _READER_JOIN_TIMEOUT_SECONDS)
    else:
        _close_process_streams(process, event_read_stream)
    return readers_alive


def _schema_error_code(error: OCRSchemaError) -> str:
    """Classify a parser failure without echoing upstream field values."""
    message = str(error)
    for field_name in ("category", "severity", "existing_code", "suggestion_code", "session_id", "message"):
        if message.startswith(field_name + " exceeds the maximum length"):
            return f"invalid_schema_{field_name}_too_long"
    if message.startswith("comment content exceeds"):
        return "invalid_schema_content_too_long"
    if message.startswith("path "):
        return "invalid_schema_path"
    if message.startswith(("start_line ", "end_line ")):
        return "invalid_schema_location"
    if message.startswith(("OCR warnings ", "OCR warning ")):
        return "invalid_schema_warnings"
    return "invalid_schema"


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _limit_process_result(result: _ProcessResult) -> _ProcessResult:
    stdout, stdout_limited = _limit_text(result.stdout, _MAX_PROCESS_OUTPUT_BYTES)
    stderr, stderr_limited = _limit_text(result.stderr, _MAX_PROCESS_OUTPUT_BYTES)
    if not stdout_limited and not stderr_limited:
        return result
    return _ProcessResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        canceled=result.canceled,
        output_limited=True,
        error="OpenCodeReview process output exceeded the configured limit",
    )


def _limit_text(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    """Terminate the OCR process group so child helpers do not outlive a scan."""

    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    process.kill()


def _as_sequence(value: Sequence[str] | str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


# These names make the integration boundary discoverable without coupling
# callers to a legacy Argus runner name.
OCRRunner = OpenCodeReviewRunner
OCRAdapter = OpenCodeReviewRunner
OpenCodeReviewAdapter = OpenCodeReviewRunner
OCRResult = OCRRunResult
OCRScanResult = OCRRunResult


__all__ = [
    "OCRAdapter",
    "OCRComment",
    "OCRRunResult",
    "OCRResult",
    "OCRRunner",
    "OCRScanResult",
    "OCRScanConfig",
    "OCRSchemaError",
    "OCRStatus",
    "OpenCodeReviewAdapter",
    "OpenCodeReviewRunner",
    "normalize_comment",
    "parse_ocr_envelope",
]
