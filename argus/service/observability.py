"""Bounded event hygiene, structured logging, and scan observations.

The service deliberately treats events as a small operational protocol.  The
protocol can describe progress and diagnostics, but it is not a second source
repository or an LLM transcript store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import logging
import math
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .models import ScanCapabilities, ScanCoverage, ScanErrorSummary, ScanObservation, ScanStatus


EVENT_MAX_BYTES = 8 * 1024
DEFAULT_EVENT_LIMIT = 10_000
DEFAULT_EVENT_RETENTION_DAYS = 14
DEFAULT_ACTIVITY_WARN_SECONDS = 120
DEFAULT_ACTIVITY_STALE_SECONDS = 300
DEFAULT_EVENT_ESSENTIAL_RESERVE = 100

EVENT_FIELDS = frozenset({"source", "type", "stage", "level", "code", "message", "data"})

# These are deliberately operational fields.  In particular, arbitrary keys,
# prompts, responses, source text, URLs, credentials, and process diagnostics
# are not part of the persisted event protocol.
EVENT_DATA_WHITELIST = frozenset(
    {
        "attempt",
        "available",
        "bytes",
        "cache_read_tokens",
        "candidates",
        "capabilities",
        "commit_sha",
        "comments",
        "count",
        "coverage",
        "deadline_at",
        "directories",
        "duration_ms",
        "dropped_count",
        "elapsed",
        "elapsed_seconds",
        "engine_commit",
        "enabled",
        "error_location",
        "event_bytes",
        "event_callback",
        "event_protocol",
        "event_reader_error",
        "exception_type",
        "exit_code",
        "failed",
        "failed_files",
        "file_id",
        "file_progress",
        "files",
        "files_failed",
        "files_reviewed",
        "files_skipped",
        "files_total",
        "finding_count",
        "headers_count",
        "http_status",
        "index",
        "input_tokens",
        "known_total",
        "llm_requests",
        "model",
        "original_bytes",
        "ordinal",
        "output_bytes",
        "output_limited",
        "output_tokens",
        "path",
        "pid",
        "pipe_events",
        "prompt_tokens",
        "protocol_dropped",
        "protocol_events",
        "protocol_invalid",
        "protocol_version",
        "percent",
        "progress",
        "provider",
        "report_ready",
        "request_count",
        "request_id",
        "retry_count",
        "retryable",
        "reviewed",
        "reviewed_files",
        "session_id",
        "size",
        "size_bytes",
        "skipped",
        "skipped_files",
        "status",
        "status_code",
        "stderr_bytes",
        "stdout_bytes",
        "stream_reader_error",
        "structured_events",
        "structured_events_dropped",
        "structured_events_rejected",
        "timeout_seconds",
        "tokens",
        "tool",
        "tool_id",
        "total",
        "total_files",
        "total_tokens",
        "truncated",
        "truncated_bytes",
        "truncated_fields",
        "unsupported",
        "warnings_count",
    }
)

_NUMERIC_DATA_KEYS = frozenset(
    {
        "attempt",
        "bytes",
        "cache_read_tokens",
        "candidates",
        "comments",
        "count",
        "directories",
        "duration_ms",
        "dropped_count",
        "elapsed_seconds",
        "exit_code",
        "failed",
        "failed_files",
        "files",
        "files_failed",
        "files_reviewed",
        "files_skipped",
        "files_total",
        "finding_count",
        "headers_count",
        "http_status",
        "index",
        "input_tokens",
        "original_bytes",
        "ordinal",
        "output_bytes",
        "output_tokens",
        "pid",
        "prompt_tokens",
        "protocol_dropped",
        "protocol_events",
        "protocol_invalid",
        "protocol_version",
        "percent",
        "request_count",
        "retry_count",
        "reviewed",
        "reviewed_files",
        "size",
        "size_bytes",
        "skipped",
        "skipped_files",
        "stderr_bytes",
        "stdout_bytes",
        "structured_events",
        "structured_events_dropped",
        "structured_events_rejected",
        "timeout_seconds",
        "tokens",
        "total",
        "total_files",
        "total_tokens",
        "truncated_bytes",
        "unsupported",
        "warnings_count",
    }
)
_BOOLEAN_DATA_KEYS = frozenset(
    {
        "available",
        "enabled",
        "event_callback",
        "event_protocol",
        "event_reader_error",
        "file_progress",
        "known_total",
        "llm_requests",
        "output_limited",
        "pipe_events",
        "report_ready",
        "retryable",
        "stream_reader_error",
        "truncated",
    }
)
_TEXT_DATA_KEYS = frozenset(
    {
        "commit_sha",
        "deadline_at",
        "elapsed",
        "engine_commit",
        "error_location",
        "exception_type",
        "file_id",
        "model",
        "path",
        "provider",
        "request_id",
        "session_id",
        "status",
        "tool",
        "tool_id",
    }
)
_LIST_TEXT_DATA_KEYS = frozenset({"truncated_fields"})
_NESTED_DATA_KEYS = frozenset({"capabilities", "coverage", "progress"})

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_ -]?key|access[_ -]?token|token|secret|password|passwd|authorization|credential|cookie)\b\s*[:=]\s*([^\s,;]+)"
)
_URL_CREDENTIALS = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,255}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")
_EVENT_CODE_MESSAGES = {
    "invalid_json": "OpenCodeReview output was not valid JSON.",
    "invalid_schema": "OpenCodeReview JSON fields did not match the supported contract.",
    "missing_json": "OpenCodeReview returned no JSON result.",
    "scan_created": "Scan accepted and queued.",
    "claim_acquired": "Worker claimed the scan attempt.",
    "phase_changed": "Scan entered a worker phase.",
    "commit_recorded": "The resolved commit was recorded.",
    "lease_expired": "The worker lease expired; the attempt was requeued or canceled.",
    "cancel_requested": "Cancellation was requested for the running scan.",
    "cancel_completed": "The scan stopped because cancellation was requested.",
    "retry_queued": "The scan was queued for another attempt.",
    "ocr_output": "OpenCodeReview returned a bounded result envelope.",
    "scan_queued": "Scan was queued.",
    "scan_completed": "Scan completed.",
    "scan_partial": "Scan completed with partial coverage.",
    "scan_failed": "Scan failed.",
    "scan_skipped": "Scan was skipped.",
    "event_limit": "Non-essential event history was truncated.",
    "process_started": "OpenCodeReview process started.",
    "output_activity": "The parent observed bounded process output activity.",
    "process_timeout": "OpenCodeReview process timed out.",
    "process_canceled": "OpenCodeReview process was canceled.",
    "process_output_limit": "OpenCodeReview process output reached its configured limit.",
    "process_exited": "OpenCodeReview process exited.",
    "parse_started": "OpenCodeReview output parsing started.",
    "parse_finished": "OpenCodeReview output parsing finished.",
    "ocr_starting": "OCR review is starting.",
    "ocr_running": "OCR review is running.",
    "ocr_output_received": "OCR output was received for bounded parsing.",
    "ocr_cancel": "OCR cancellation was observed.",
    "progress_updated": "Scan progress updated.",
    "source_checkout_ready": "The disposable source checkout is ready.",
    "source_checked": "The disposable source checkout passed safety checks.",
    "file_started": "OCR reported a file start.",
    "file_completed": "OCR reported a file completion.",
    "file_failed": "OCR reported a file failure.",
    "scan_inventory": "OCR reported scan inventory.",
    "llm_request_started": "OCR reported an LLM request start.",
    "llm_request_headers": "OCR reported bounded LLM request metadata.",
    "llm_request_completed": "OCR reported an LLM request completion.",
    "llm_request_failed": "OCR reported an LLM request failure.",
    "llm_request_retry": "OCR reported an LLM request retry.",
    "tool_started": "OCR reported a tool start.",
    "tool_completed": "OCR reported a tool completion.",
    "tool_failed": "OCR reported a tool failure.",
    "session_started": "OCR reported a session start.",
    "worker_timeout": "The worker timed out.",
    "worker_io": "The worker encountered an I/O boundary failure.",
    "worker_invalid": "The worker received invalid bounded input.",
    "worker_unknown": "The worker encountered an unclassified boundary failure.",
    "event_store_unavailable": "The event store was unavailable.",
    "lease_lost": "The worker lease was lost.",
    "event_recorded": "A bounded event was recorded.",
}


def _fixed_message(code: str) -> str | None:
    message = _EVENT_CODE_MESSAGES.get(code)
    if message is not None:
        return message
    for prefix, fallback in (
        ("invalid_schema_", "An OCR result field failed validation; inspect the field-specific error code."),
        ("git_", "The Git boundary reported a bounded diagnostic."),
        ("ocr_", "OCR reported a bounded diagnostic."),
        ("parse_", "OpenCodeReview parsing reported a bounded diagnostic."),
        ("process_", "The OpenCodeReview process reported a bounded diagnostic."),
        ("file_", "OCR reported a bounded file diagnostic."),
        ("llm_request_", "OCR reported a bounded LLM request diagnostic."),
        ("tool_", "OCR reported a bounded tool diagnostic."),
        ("worker_", "The worker reported a bounded diagnostic."),
    ):
        if code.startswith(prefix):
            return fallback
    return None


def _clean_text(value: object, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = _CONTROL_CHARS.sub(" ", value).strip()
    text = " ".join(text.split())
    if not text:
        return None
    text = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1=[REDACTED]", text)
    return text[:max_length]


def _clean_label(value: object, *, max_length: int) -> str | None:
    return _clean_text(value, max_length=max_length)


def _protocol_label(value: object, *, max_length: int) -> str | None:
    cleaned = _clean_label(value, max_length=max_length)
    if cleaned is None:
        return None
    normalized = cleaned.lower()
    return normalized if _LABEL.fullmatch(normalized) else None


def _json_size(value: Mapping[str, Any]) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"))


def _sanitize_data(value: object, *, depth: int = 0) -> dict[str, Any]:
    if not isinstance(value, Mapping) or depth > 2:
        return {}
    result: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            continue
        key = raw_key.strip().lower()
        if key in {"detail", "reason", "suggestion"}:
            # Human-readable diagnostics come from the code catalogue, never
            # from arbitrary provider or process text.
            continue
        if key not in EVENT_DATA_WHITELIST:
            continue
        if key in _NESTED_DATA_KEYS:
            nested = _sanitize_data(raw_value, depth=depth + 1)
            if nested:
                result[key] = nested
            continue
        if key in _BOOLEAN_DATA_KEYS:
            if isinstance(raw_value, bool):
                result[key] = raw_value
            continue
        if key in _NUMERIC_DATA_KEYS:
            if isinstance(raw_value, bool):
                continue
            lower_bound = -256 if key == "exit_code" else 0
            if isinstance(raw_value, int) and lower_bound <= raw_value <= 10**12:
                result[key] = raw_value
            elif (
                isinstance(raw_value, float)
                and key != "exit_code"
                and math.isfinite(raw_value)
                and 0 <= raw_value <= 10**12
            ):
                result[key] = raw_value
            continue
        if key in _TEXT_DATA_KEYS:
            cleaned = _clean_text(raw_value, max_length=1_024)
            if cleaned is None:
                continue
            if key in {"request_id", "session_id"}:
                if _IDENTIFIER.fullmatch(cleaned):
                    result[key] = cleaned
            elif key in {"commit_sha", "engine_commit"}:
                if _COMMIT.fullmatch(cleaned):
                    result[key] = cleaned.lower()
            elif key == "exception_type":
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", cleaned):
                    result[key] = cleaned
            elif key == "error_location":
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}:[A-Za-z_][A-Za-z0-9_]{0,128}:[1-9][0-9]{0,6}", cleaned):
                    result[key] = cleaned
            elif key == "path":
                candidate = cleaned.replace("\\", "/")
                if (
                    not candidate.startswith("/")
                    and not candidate.startswith("//")
                    and not any(part == ".." for part in candidate.split("/"))
                    and candidate not in {"", "."}
                ):
                    result[key] = candidate[:1_024]
            else:
                result[key] = cleaned
            continue
        if key in _LIST_TEXT_DATA_KEYS:
            if isinstance(raw_value, (list, tuple)):
                values = [
                    cleaned for item in raw_value[:32] if (cleaned := _clean_text(item, max_length=128)) is not None
                ]
                if values:
                    result[key] = values
    return result


def sanitize_event(event: Mapping[str, Any], *, max_bytes: int = EVENT_MAX_BYTES) -> dict[str, Any]:
    """Return only the bounded public event protocol.

    ``type`` is the only required input.  Invalid optional values are omitted;
    an invalid type is rejected because it cannot be safely routed or queried.
    Oversized content is reduced and carries an explicit truncation marker.
    """

    if not isinstance(event, Mapping):
        raise ValueError("event must be an object")
    event_type = _protocol_label(event.get("type"), max_length=128)
    if event_type is None:
        raise ValueError("event.type must be a non-empty string")
    result: dict[str, Any] = {"type": event_type.lower()}
    for key, max_length in (("source", 128), ("stage", 256), ("level", 32), ("code", 256), ("message", 2_000)):
        value = (
            _protocol_label(event.get(key), max_length=max_length)
            if key in {"source", "stage", "code"}
            else _clean_label(event.get(key), max_length=max_length)
        )
        if value is None:
            continue
        if key == "level":
            value = value.lower()
            if value not in {"debug", "info", "notice", "warning", "error", "critical"}:
                continue
        result[key] = value
    result["data"] = _sanitize_data(event.get("data", {}))
    code = result.get("code")
    if isinstance(code, str):
        fixed_message = _fixed_message(code)
        if fixed_message is not None:
            result["message"] = fixed_message
        else:
            result.pop("message", None)
    else:
        result.pop("message", None)

    original_size = _json_size(result)
    if original_size <= max_bytes:
        return result

    data = result["data"]
    if not isinstance(data, dict):
        data = {}
    removed_fields: list[str] = []
    # Remove the fields most likely to contain long human-authored details
    # before shortening the compact operational counters.
    for key in ("detail", "reason", "suggestion", "session_id", "model", "provider", "status"):
        if key in data:
            data.pop(key)
            removed_fields.append(key)
    message = result.get("message")
    if isinstance(message, str):
        result["message"] = message[:256]
        if len(message) > 256:
            removed_fields.append("message")
    data["truncated"] = True
    data["original_bytes"] = original_size
    data["truncated_fields"] = removed_fields[:32]
    result["data"] = data

    # The allowlist makes this loop rarely necessary, but it keeps the byte
    # contract true even if the allowlist is extended later.
    while _json_size(result) > max_bytes:
        removable = [key for key in data if key not in {"truncated", "original_bytes", "truncated_fields"}]
        if removable:
            key = max(removable, key=lambda item: len(json.dumps(data[item], ensure_ascii=False, default=str)))
            data.pop(key, None)
            if key not in removed_fields:
                removed_fields.append(key)
            data["truncated_fields"] = removed_fields[:32]
            continue
        message = result.get("message")
        if isinstance(message, str) and len(message) > 32:
            result["message"] = message[: max(32, len(message) // 2)]
            if "message" not in removed_fields:
                removed_fields.append("message")
            data["truncated_fields"] = removed_fields[:32]
            continue
        for key in ("code", "stage", "source", "level"):
            if key in result:
                result.pop(key)
                if key not in removed_fields:
                    removed_fields.append(key)
                data["truncated_fields"] = removed_fields[:32]
                break
        else:
            # ``type`` and the marker are both short and mandatory.  This is
            # defensive only; the normal bounded fields cannot reach here.
            result["type"] = str(result["type"])[:32]
            break
    data["truncated_bytes"] = max(0, original_size - max_bytes)
    return result


def event_is_essential(event: Mapping[str, Any]) -> bool:
    """Whether an event should use the reserved essential-event capacity."""

    if event.get("essential") is True:
        return True
    level = str(event.get("level") or "").lower()
    if level in {"warning", "error", "critical"}:
        return True
    event_type = str(event.get("type") or "").lower()
    return event_type in {
        "scan.created",
        "scan.claimed",
        "scan.completed",
        "scan.partial",
        "scan.failed",
        "scan.canceled",
        "scan.cancel_requested",
        "scan.retried",
        "scan.lease_expired",
        "observability.truncated",
    }


def _event_log_level(event: Mapping[str, Any]) -> int:
    return {
        "debug": logging.DEBUG,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }.get(str(event.get("level") or "info").lower(), logging.INFO)


event_logger = logging.getLogger("argus.service.observability")
event_logger.setLevel(logging.INFO)
event_logger.propagate = True
if not any(getattr(handler, "_argus_event_handler", False) for handler in event_logger.handlers):
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    setattr(_handler, "_argus_event_handler", True)
    event_logger.addHandler(_handler)


def log_stored_event(event_id: int, event: Mapping[str, Any]) -> None:
    """Log a committed event as one JSON line with its exact cursor."""

    safe = sanitize_event(event)
    timestamp = event.get("timestamp") or event.get("created_at")
    if isinstance(timestamp, datetime):
        timestamp = timestamp.isoformat()
    if not isinstance(timestamp, str):
        timestamp = None
    record = {
        "schema_version": 1,
        "event_id": event_id,
        "cursor": event_id,
        "scan_id": event.get("scan_id"),
        "attempt": event.get("attempt"),
        "timestamp": timestamp,
        **safe,
    }
    event_logger.log(
        _event_log_level(safe), json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )


@dataclass(frozen=True)
class StructuredEventUpdate:
    """Validated facts an OCR event is allowed to add to scan state."""

    event_protocol: bool = False
    file_progress: bool = False
    llm_requests: bool = False
    progress: bool = False
    output: bool = False
    coverage: dict[str, int | None] | None = None
    coverage_delta: bool = False


_OCR_SOURCES = frozenset({"ocr", "ocr.adapter", "ocr-adapter", "ocr_adapter", "opencodereview", "open-code-review"})
_PROGRESS_TYPES = frozenset(
    {
        "progress",
        "file_progress",
        "ocr.progress",
        "ocr.file_progress",
        "ocr.coverage",
        "scan.inventory",
        "file.started",
        "file.completed",
        "file.failed",
        "file.skipped",
    }
)
_FILE_TYPES = frozenset({"file.started", "file.completed", "file.failed", "file.skipped"})
_SESSION_TYPES = frozenset({"session.started"})
_TOOL_TYPES = frozenset({"tool.started", "tool.completed", "tool.failed"})
_CHILD_PROTOCOL_TYPES = frozenset(
    {
        "scan.inventory",
        "session.started",
        "file.started",
        "file.completed",
        "file.failed",
        "file.skipped",
        "llm.request.started",
        "llm.request.headers",
        "llm.request.completed",
        "llm.request.failed",
        "llm.request.retry",
        "tool.started",
        "tool.completed",
        "tool.failed",
    }
)
_FILE_PROGRESS_TYPES = frozenset({"scan.inventory", "file.started", "file.completed", "file.failed", "file.skipped"})
_OCR_PARENT_TYPES = frozenset(
    {
        "ocr.started",
        "ocr.phase",
        "ocr.warning",
        "ocr.finished",
        "ocr.error",
        "ocr.timeout",
        "ocr.canceled",
        "ocr.output_limit",
        "ocr.exited",
        "ocr.output_activity",
    }
)
_OUTPUT_TYPES = frozenset(
    {
        "output",
        "ocr.output",
        "ocr.output_activity",
        "ocr.result",
        "result",
        "finding",
        "ocr.finding",
    }
)
_LLM_TYPES = frozenset(
    {
        "llm_request",
        "llm_response",
        "ocr.llm_request",
        "ocr.llm_response",
        "ocr.llm_requests",
        "llm.request.started",
        "llm.request.headers",
        "llm.request.completed",
        "llm.request.failed",
        "llm.request.retry",
    }
)


def _strict_nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _coverage_payload(data: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("coverage", "progress"):
        nested = data.get(key)
        if isinstance(nested, Mapping):
            merged = dict(data)
            merged.update(nested)
            return merged
    return data


def _validated_coverage(data: object) -> dict[str, int | None] | None:
    if not isinstance(data, Mapping):
        return None
    payload = _coverage_payload(data)
    aliases = {
        "total": ("total", "files_total", "total_files"),
        "reviewed": ("reviewed", "files_reviewed", "reviewed_files"),
        "failed": ("failed", "files_failed", "failed_files"),
        "skipped": ("skipped", "files_skipped", "skipped_files"),
        "percent": ("percent",),
    }
    values: dict[str, int | None] = {}
    present = False
    for canonical, names in aliases.items():
        found = next((name for name in names if name in payload), None)
        if found is None:
            values[canonical] = None if canonical in {"total", "percent"} else 0
            continue
        present = True
        raw_value = payload[found]
        if raw_value is None and canonical == "total":
            values[canonical] = None
            continue
        parsed = _strict_nonnegative_int(raw_value)
        if parsed is None or (canonical == "percent" and parsed > 100):
            return None
        values[canonical] = parsed
    if not present:
        return None
    total = values["total"]
    count = int(values["reviewed"] or 0) + int(values["failed"] or 0) + int(values["skipped"] or 0)
    if total is not None and count > total:
        return None
    return values


def _file_event_coverage(event_type: str, data: Mapping[str, Any]) -> dict[str, int | None] | None:
    payload = _coverage_payload(data)
    total_names = ("total", "files_total", "total_files")
    total_name = next((name for name in total_names if name in payload), None)
    total: int | None = None
    if total_name is not None:
        raw_total = payload[total_name]
        if raw_total is not None:
            total = _strict_nonnegative_int(raw_total)
            if total is None:
                return None
    count_names = {
        "reviewed": ("reviewed", "files_reviewed", "reviewed_files"),
        "failed": ("failed", "files_failed", "failed_files"),
        "skipped": ("skipped", "files_skipped", "skipped_files"),
    }
    values = {"reviewed": 0, "failed": 0, "skipped": 0}
    for counter, names in count_names.items():
        found = next((name for name in names if name in payload), None)
        if found is not None:
            parsed = _strict_nonnegative_int(payload[found])
            if parsed is None:
                return None
            values[counter] = parsed
    if event_type == "file.completed" and not any(values.values()):
        values["reviewed"] = 1
    elif event_type == "file.failed" and not any(values.values()):
        values["failed"] = 1
    elif event_type == "file.skipped" and not any(values.values()):
        values["skipped"] = 1
    if total is not None and sum(values.values()) > total:
        return None
    return {"total": total, **values, "percent": None}


def structured_event_update(event: Mapping[str, Any]) -> StructuredEventUpdate | None:
    """Extract only validated OCR capability and coverage facts."""

    source = str(event.get("source") or "").lower()
    event_type = str(event.get("type") or "").lower()
    if source not in _OCR_SOURCES:
        return None
    recognized = (
        event_type in _PROGRESS_TYPES | _OUTPUT_TYPES | _LLM_TYPES | _SESSION_TYPES | _TOOL_TYPES | _OCR_PARENT_TYPES
    )
    if not recognized:
        return None
    data = event.get("data")
    data_mapping = data if isinstance(data, Mapping) else {}
    coverage = (
        _file_event_coverage(event_type, data_mapping)
        if event_type in _FILE_TYPES
        else _validated_coverage(data_mapping)
    )
    is_progress = event_type in _PROGRESS_TYPES
    valid_path = isinstance(data_mapping.get("path"), str) if event_type in _FILE_TYPES else True
    valid_request_id = isinstance(data_mapping.get("request_id"), str) if event_type in _LLM_TYPES else True
    valid_session_id = isinstance(data_mapping.get("session_id"), str) if event_type in _SESSION_TYPES else True
    if (is_progress and coverage is None) or not valid_path or not valid_request_id or not valid_session_id:
        return StructuredEventUpdate()
    capabilities = data_mapping.get("capabilities")
    direct_file_progress = data_mapping.get("file_progress")
    direct_llm_requests = data_mapping.get("llm_requests")
    file_progress = coverage is not None and event_type in _FILE_PROGRESS_TYPES
    llm_requests = event_type in _LLM_TYPES
    if isinstance(capabilities, Mapping):
        if capabilities.get("file_progress") is True:
            file_progress = True
        if capabilities.get("llm_requests") is True:
            llm_requests = True
    if direct_file_progress is True:
        file_progress = True
    if direct_llm_requests is True:
        llm_requests = True
    return StructuredEventUpdate(
        event_protocol=event_type in _CHILD_PROTOCOL_TYPES,
        file_progress=file_progress,
        llm_requests=llm_requests,
        progress=coverage is not None and event_type in _FILE_PROGRESS_TYPES,
        output=event_type in _OUTPUT_TYPES,
        coverage=coverage,
        coverage_delta=event_type in _FILE_TYPES,
    )


def has_actual_output_activity(event: Mapping[str, Any]) -> bool:
    """Whether an output-activity event contains a real reader counter."""

    if str(event.get("type") or "").lower() != "ocr.output_activity":
        return False
    data = event.get("data")
    if not isinstance(data, Mapping):
        return False
    return any(
        isinstance(data.get(key), int) and not isinstance(data.get(key), bool) and int(data[key]) > 0
        for key in ("stdout_bytes", "stderr_bytes", "event_bytes", "output_bytes")
    )


def _parsed_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _row_value(row: Any, name: str, default: object = None) -> object:
    try:
        value = row[name]
    except (IndexError, KeyError):
        return default
    return default if value is None and default is not None else value


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


def _coverage_from_row(row: Any) -> ScanCoverage:
    observed = _json_object(_row_value(row, "coverage_observation_json", "{}"))
    legacy = _json_object(_row_value(row, "coverage_json", "{}"))
    if not observed:
        observed = {
            "total": legacy.get("total_files")
            if _strict_nonnegative_int(legacy.get("total_files")) not in {None, 0}
            else None,
            "reviewed": legacy.get("reviewed_files", 0),
            "failed": legacy.get("failed_files", 0),
            "skipped": legacy.get("skipped_files", 0),
            "percent": legacy.get("percent")
            if _strict_nonnegative_int(legacy.get("total_files")) not in {None, 0}
            else None,
        }
    total = observed.get("total")
    total_value = _strict_nonnegative_int(total) if total is not None else None
    values: dict[str, int | None] = {"reviewed": 0, "failed": 0, "skipped": 0, "percent": None}
    for key in values:
        parsed = _strict_nonnegative_int(observed.get(key))
        if key == "percent":
            values[key] = parsed if parsed is not None and parsed <= 100 else None
        else:
            values[key] = parsed if parsed is not None else 0
    if total_value is not None:
        count = int(values["reviewed"] or 0) + int(values["failed"] or 0) + int(values["skipped"] or 0)
        values["percent"] = 100 if total_value == 0 else min(100, round(count * 100 / total_value))
    else:
        values["percent"] = None
    return ScanCoverage(
        total=total_value,
        reviewed=int(values["reviewed"] or 0),
        failed=int(values["failed"] or 0),
        skipped=int(values["skipped"] or 0),
        percent=values["percent"],
    )


def _capabilities_from_row(row: Any) -> ScanCapabilities:
    value = _json_object(_row_value(row, "capabilities_json", "{}"))
    return ScanCapabilities(
        file_progress=value.get("file_progress") is True,
        llm_requests=value.get("llm_requests") is True,
        event_protocol=value.get("event_protocol") is True,
    )


def _seconds(start: datetime | None, end: datetime) -> float:
    if start is None:
        return 0.0
    return round(max(0.0, (end - start).total_seconds()), 3)


def build_observation(
    row: Any,
    *,
    now: datetime | None = None,
    activity_warn_seconds: int = DEFAULT_ACTIVITY_WARN_SECONDS,
    activity_stale_seconds: int = DEFAULT_ACTIVITY_STALE_SECONDS,
) -> ScanObservation:
    """Build a truthful observation from persisted state without guessing."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    status_value = str(_row_value(row, "status", "unknown"))
    stage = str(_row_value(row, "phase", "unknown"))
    created_at = _parsed_datetime(_row_value(row, "created_at"))
    started_at = _parsed_datetime(_row_value(row, "started_at"))
    finished_at = _parsed_datetime(_row_value(row, "finished_at"))
    stage_started_at = _parsed_datetime(_row_value(row, "phase_started_at"))
    last_output_at = _parsed_datetime(_row_value(row, "last_output_at"))
    last_progress_at = _parsed_datetime(_row_value(row, "last_progress_at"))
    heartbeat_at = _parsed_datetime(_row_value(row, "heartbeat_at"))
    reference = finished_at or current
    deadline_at = _parsed_datetime(_row_value(row, "process_deadline_at"))

    history_available = bool(_row_value(row, "history_available", 0))
    event_count = _strict_nonnegative_int(_row_value(row, "event_count", 0)) or 0
    dropped_count = _strict_nonnegative_int(_row_value(row, "event_dropped_count", 0)) or 0
    truncated_count = _strict_nonnegative_int(_row_value(row, "event_truncated_count", 0)) or 0

    error_code = _row_value(row, "last_error_code")
    error_message = _row_value(row, "last_error_message") or _row_value(row, "error")
    error_source = _row_value(row, "last_error_source")
    retryable_value = _row_value(row, "last_error_retryable")
    retryable = retryable_value in {True, 1} if retryable_value is not None else None
    if error_message and retryable is None:
        retryable = status_value in {
            ScanStatus.PARTIAL.value,
            ScanStatus.FAILED.value,
            ScanStatus.CANCELED.value,
            ScanStatus.SKIPPED.value,
        }
    suggestion = _row_value(row, "last_error_suggestion")
    if error_message and not suggestion:
        suggestion = "Review the recent diagnostics and retry the scan if the input or dependency is available."
    error_summary = ScanErrorSummary(
        code=str(error_code)[:256] if error_code else None,
        message=_clean_text(error_message, max_length=2_000),
        retryable=retryable,
        suggestion=_clean_text(suggestion, max_length=2_000),
        source=str(error_source)[:128] if error_source else None,
    )

    warnings: list[str] = []
    actual_times = [value for value in (last_output_at, last_progress_at) if value is not None]
    last_actual = max(actual_times) if actual_times else None
    activity_state = "unknown"
    if history_available:
        if status_value == ScanStatus.QUEUED.value:
            activity_state = "queued"
        elif status_value == ScanStatus.RUNNING.value:
            inactivity_start = last_actual or started_at or stage_started_at or created_at
            inactivity_seconds = _seconds(inactivity_start, current)
            if inactivity_seconds >= max(activity_stale_seconds, activity_warn_seconds):
                activity_state = "stale_warning"
                warnings.append(
                    f"No progress or output has been observed for {max(activity_stale_seconds, activity_warn_seconds)} seconds; inspect diagnostics."
                )
            elif inactivity_seconds >= min(activity_warn_seconds, activity_stale_seconds):
                activity_state = "idle_warning"
                warnings.append(
                    f"No progress or output has been observed for {min(activity_warn_seconds, activity_stale_seconds)} seconds; the worker or model may still be waiting."
                )
            elif last_actual is None:
                activity_state = "starting"
            elif heartbeat_at is not None and heartbeat_at > last_actual:
                activity_state = "heartbeat_only"
            else:
                activity_state = "active"
        elif status_value in {
            item.value
            for item in (
                ScanStatus.COMPLETED,
                ScanStatus.PARTIAL,
                ScanStatus.FAILED,
                ScanStatus.CANCELED,
                ScanStatus.SKIPPED,
            )
        }:
            activity_state = status_value

    report_ready = status_value in {
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.SKIPPED.value,
    }
    elapsed_start = created_at or started_at
    stage_start = stage_started_at or created_at
    return ScanObservation(
        stage=stage,
        stage_started_at=stage_started_at,
        elapsed_seconds=_seconds(elapsed_start, reference),
        stage_elapsed_seconds=_seconds(stage_start, reference),
        last_output_at=last_output_at,
        last_progress_at=last_progress_at,
        worker_heartbeat_at=heartbeat_at,
        deadline_at=deadline_at,
        activity_state=activity_state,
        capabilities=_capabilities_from_row(row),
        coverage=_coverage_from_row(row),
        report_ready=report_ready,
        history_available=history_available,
        error_summary=error_summary,
        warnings=warnings,
        event_count=event_count,
        dropped_event_count=dropped_count,
        truncated_event_count=truncated_count,
    )


def sanitize_repository_url(value: str | None) -> str | None:
    """Remove URL userinfo, query, and fragment before diagnostics export."""

    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.netloc:
            return candidate[:512]
        hostname = parsed.hostname
        if not hostname:
            return None
        netloc = hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            netloc = f"{netloc}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))[:1_024]
    except ValueError:
        return None
