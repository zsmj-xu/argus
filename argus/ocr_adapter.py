"""Small, independent adapter for OpenCodeReview's full-file scan command.

The adapter deliberately owns only the process boundary and the JSON contract.
It does not import Argus' legacy scan, review, plugin, or control-plane code, so
the service core can use it as a replaceable scanning backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
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
    error: str | None = None


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
_MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024


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
    thinking = _optional_string(value.get("thinking"), "thinking")
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
        raise OCRSchemaError(f"unsupported OCR status: {raw_status!r}")

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
    warnings_list: list[str] = []
    for item in raw_warnings:
        if not isinstance(item, str):
            raise OCRSchemaError("OCR warnings must contain strings")
        warning = item.strip()
        if len(warning) > _MAX_MESSAGE_TEXT:
            raise OCRSchemaError(f"OCR warning exceeds the maximum length of {_MAX_MESSAGE_TEXT} characters")
        warnings_list.append(warning)
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
    ) -> None:
        if isinstance(executable, Path):
            executable_value = str(executable)
        elif isinstance(executable, str) and executable.strip():
            executable_value = executable.strip()
        else:
            raise ValueError("executable must be a non-empty path or command name")
        if "\x00" in executable_value:
            raise ValueError("executable must not contain NUL bytes")
        self.executable = executable_value
        self.environment = dict(environment) if environment is not None else None

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
        process = self._invoke(checkout_path, selected, cancel_check=cancel_check)
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
        if process.stdout.strip():
            try:
                decoded = json.loads(process.stdout)
                if not isinstance(decoded, Mapping):
                    raise OCRSchemaError("OCR JSON output must be a top-level object")
                envelope = decoded
                parsed = parse_ocr_envelope(decoded)
            except (json.JSONDecodeError, OCRSchemaError) as exc:
                parse_error = f"invalid OCR JSON output: {exc}"
        else:
            parse_error = "OCR produced no JSON output"

        if parse_error is not None:
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
    ) -> _ProcessResult:
        if cancel_check is not None:
            return self._invoke_cancellable(checkout, config, cancel_check)
        try:
            completed = subprocess.run(
                self.build_argv(config),
                cwd=str(checkout),
                shell=False,
                capture_output=True,
                text=True,
                timeout=config.process_timeout_seconds,
                check=False,
                env=self.environment,
            )
        except subprocess.TimeoutExpired as exc:
            return _limit_process_result(
                _ProcessResult(
                    stdout=_as_text(exc.stdout),
                    stderr=_as_text(exc.stderr),
                    exit_code=None,
                    timed_out=True,
                    error="OpenCodeReview subprocess timed out",
                )
            )
        except OSError as exc:
            return _ProcessResult(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                canceled=False,
                error=f"could not start OpenCodeReview: {exc}",
            )
        return _limit_process_result(
            _ProcessResult(
                stdout=_as_text(completed.stdout),
                stderr=_as_text(completed.stderr),
                exit_code=completed.returncode,
                timed_out=False,
            )
        )

    def _invoke_cancellable(
        self,
        checkout: Path,
        config: OCRScanConfig,
        cancel_check: Callable[[], bool],
    ) -> _ProcessResult:
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                self.build_argv(config),
                cwd=str(checkout),
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = (
                time.monotonic() + config.process_timeout_seconds
                if config.process_timeout_seconds is not None
                else None
            )
            while process.poll() is None:
                if cancel_check():
                    _terminate_process(process)
                    stdout, stderr = process.communicate()
                    return _limit_process_result(
                        _ProcessResult(
                            stdout=_as_text(stdout),
                            stderr=_as_text(stderr),
                            exit_code=process.returncode,
                            timed_out=False,
                            canceled=True,
                            error="OpenCodeReview canceled",
                        )
                    )
                if deadline is not None and time.monotonic() >= deadline:
                    _terminate_process(process)
                    stdout, stderr = process.communicate()
                    return _limit_process_result(
                        _ProcessResult(
                            stdout=_as_text(stdout),
                            stderr=_as_text(stderr),
                            exit_code=process.returncode,
                            timed_out=True,
                            error="OpenCodeReview subprocess timed out",
                        )
                    )
                time.sleep(0.1)
            stdout, stderr = process.communicate()
            return _limit_process_result(
                _ProcessResult(
                    stdout=_as_text(stdout),
                    stderr=_as_text(stderr),
                    exit_code=process.returncode,
                    timed_out=False,
                )
            )
        except OSError as exc:
            if process is not None and process.poll() is None:
                _terminate_process(process)
                process.communicate()
            return _ProcessResult(
                stdout="",
                stderr="",
                exit_code=None,
                timed_out=False,
                error=f"could not start OpenCodeReview: {exc}",
            )


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
        error="OpenCodeReview process output exceeded the configured limit",
    )


def _limit_text(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _terminate_process(process: subprocess.Popen[str]) -> None:
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
