"""Focused contract tests for the independent OpenCodeReview adapter."""

from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from argus.ocr_adapter import (
    OCRScanConfig,
    OCRSchemaError,
    OCRStatus,
    OpenCodeReviewRunner,
    normalize_comment,
    parse_ocr_envelope,
)


def _envelope(**overrides: Any) -> str:
    value: dict[str, Any] = {
        "status": "success",
        "summary": {"files_reviewed": 2, "comments": 1, "total_tokens": 17},
        "comments": [
            {
                "path": "src/auth.py",
                "start_line": 4,
                "end_line": 6,
                "category": "SECURITY",
                "severity": "HIGH",
                "content": "  Validate this input before using it.  ",
                "existing_code": "value = request.args['value']",
                "suggestion_code": "value = validate(request.args['value'])",
            }
        ],
        "warnings": [],
        "session_id": "session-123",
    }
    value.update(overrides)
    return json.dumps(value)


class _FakeProcess:
    def __init__(self, stdout: str | bytes = b"", stderr: str | bytes = b"", returncode: int | None = 0) -> None:
        self.stdout = io.BytesIO(stdout.encode() if isinstance(stdout, str) else stdout)
        self.stderr = io.BytesIO(stderr.encode() if isinstance(stderr, str) else stderr)
        self.returncode = returncode
        self.killed = False
        self.pid = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def _patch_fake_popen(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
    calls: list[tuple[list[str], dict[str, Any]]] | None = None,
) -> None:
    def fake_popen(argv: list[str], **kwargs: Any) -> _FakeProcess:
        if calls is not None:
            calls.append((argv, kwargs))
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)


def test_success_runs_full_file_scan_and_normalizes_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    _patch_fake_popen(monkeypatch, _FakeProcess(_envelope(), "ocr diagnostics"), calls)
    runner = OpenCodeReviewRunner("/opt/ocr-main/ocr")
    result = runner.run(
        tmp_path,
        OCRScanConfig(
            paths=("src", "README.md"),
            excludes=("**/generated/*", "*.pb.go"),
            background="Review authentication paths",
            provider="gateway",
            model="secure-model",
            token_budget=5000,
            timeout_minutes=7,
            process_timeout_seconds=42,
        ),
    )

    assert result.status is OCRStatus.COMPLETE
    assert result.complete
    assert result.exit_code == 0
    assert result.stderr == "ocr diagnostics"
    assert result.session_id == "session-123"
    assert result.summary == {"files_reviewed": 2, "comments": 1, "total_tokens": 17}
    assert result.comments[0].path == "src/auth.py"
    assert result.comments[0].category == "security"
    assert result.comments[0].severity == "high"
    assert result.comments[0].content == "Validate this input before using it."
    assert result.comments[0].suggestion_code == "value = validate(request.args['value'])"

    argv, kwargs = calls[0]
    assert argv == [
        "/opt/ocr-main/ocr",
        "scan",
        "--format",
        "json",
        "--audience",
        "agent",
        "--path",
        "src,README.md",
        "--exclude",
        "**/generated/*,*.pb.go",
        "--background",
        "Review authentication paths",
        "--provider",
        "gateway",
        "--model",
        "secure-model",
        "--max-tokens-budget",
        "5000",
        "--timeout",
        "7",
    ]
    assert kwargs["cwd"] == str(tmp_path.resolve())
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["text"] is False
    assert kwargs["bufsize"] == 0
    assert kwargs["start_new_session"] is True
    assert "pass_fds" not in kwargs


def test_warning_envelope_is_partial_and_preserves_warning_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_fake_popen(
        monkeypatch,
        _FakeProcess(_envelope(status="completed_with_warnings", warnings=["src/broken.py: agent failed"])),
    )
    result = OpenCodeReviewRunner().run(tmp_path)

    assert result.status is OCRStatus.PARTIAL
    assert result.warnings == ("src/broken.py: agent failed",)
    assert len(result.comments) == 1


def test_structured_warning_envelope_is_partial_and_safely_normalized() -> None:
    status, _comments, warnings, _summary, _session_id, _message, _llm = parse_ocr_envelope(
        {
            "status": "success",
            "comments": [],
            "warnings": [
                {
                    "type": "token_budget_reached",
                    "file": "src/main.go",
                    "message": "dispatch stopped before the next file",
                }
            ],
        }
    )

    assert status is OCRStatus.PARTIAL
    assert warnings == (
        {
            "type": "token_budget_reached",
            "file": "src/main.go",
            "message": "dispatch stopped before the next file",
        },
    )


@pytest.mark.parametrize(
    "warning",
    [
        {"type": "safe", "source": "PRIVATE"},
        {"file": "../secret.py", "message": "failed"},
        {"type": "x" * 129},
        {"message": "x" * 2001},
        {"message": "line one\nline two"},
        {"file": ["not", "a", "path"]},
        {},
    ],
)
def test_structured_warning_rejects_unsafe_shapes(warning: object) -> None:
    with pytest.raises(OCRSchemaError, match="OCR warning"):
        parse_ocr_envelope({"status": "success", "comments": [], "warnings": [warning]})


def test_reasoning_is_discarded_but_llm_identity_is_preserved() -> None:
    status, comments, warnings, summary, session_id, message, llm = parse_ocr_envelope(
        {
            "status": "success",
            "llm": {"provider": "anthropic", "model": "claude-opus-4-6"},
            "summary": {"files_reviewed": 1, "comments": 1},
            "warnings": ["one file was skipped"],
            "session_id": "sess-1",
            "comments": [
                {
                    "path": "src/app.py",
                    "content": "Use a safer parser.",
                    "start_line": 10,
                    "end_line": 10,
                    "thinking": "Private reasoning. " * 2000,
                }
            ],
        }
    )

    assert status is OCRStatus.PARTIAL
    assert comments[0].thinking is None
    assert warnings == ("one file was skipped",)
    assert summary == {"files_reviewed": 1, "comments": 1}
    assert session_id == "sess-1"
    assert message is None
    assert llm == {"provider": "anthropic", "model": "claude-opus-4-6"}


def test_skipped_envelope_is_distinct_from_complete_zero_findings() -> None:
    status, comments, warnings, summary, session_id, message, llm = parse_ocr_envelope(
        {
            "status": "skipped",
            "message": "No supported files changed.",
            "comments": [],
            "llm": {"model": "secure-model"},
        }
    )

    assert status is OCRStatus.SKIPPED
    assert comments == ()
    assert warnings == ()
    assert summary is None
    assert session_id is None
    assert message == "No supported files changed."
    assert llm == {"model": "secure-model"}


def test_failed_status_is_supported_as_a_service_failure() -> None:
    status, comments, warnings, summary, session_id, message, llm = parse_ocr_envelope(
        {"status": "failed", "comments": [], "message": "provider unavailable"}
    )

    assert status is OCRStatus.FAILED
    assert comments == ()
    assert warnings == ()
    assert summary is None
    assert session_id is None
    assert message == "provider unavailable"
    assert llm is None


def test_v1_1_9_envelope_without_newer_optional_fields_is_supported() -> None:
    status, comments, warnings, summary, session_id, message, llm = parse_ocr_envelope(
        {
            "status": "success",
            "comments": [{"path": "main.go", "content": "Handle this error.", "start_line": 12, "end_line": 12}],
        }
    )

    assert status is OCRStatus.COMPLETE
    assert comments[0].category is None
    assert comments[0].severity is None
    assert warnings == ()
    assert summary is None
    assert session_id is None
    assert message is None
    assert llm is None


def test_missing_comments_is_rejected_as_malformed_envelope() -> None:
    with pytest.raises(OCRSchemaError, match="comments array"):
        parse_ocr_envelope({"status": "success"})


def test_schema_failure_code_identifies_field_without_echoing_value(monkeypatch, tmp_path) -> None:
    import argus.ocr_adapter as adapter

    output = json.dumps({"status": "complete", "comments": [{"path": "a.py", "content": "PRIVATE" * 4000}]})
    monkeypatch.setattr(
        OpenCodeReviewRunner,
        "_invoke",
        lambda *args, **kwargs: adapter._ProcessResult(
            stdout=output,
            stderr="",
            exit_code=0,
            timed_out=False,
        ),
    )
    events = []
    result = OpenCodeReviewRunner().run(tmp_path, event_callback=events.append)
    assert result.status is OCRStatus.FAILED
    assert any(event["code"] == "invalid_schema_content_too_long" for event in events)
    assert "PRIVATE" not in json.dumps(events)


def test_ocr_comment_payload_limits_are_enforced() -> None:
    with pytest.raises(OCRSchemaError, match="maximum length"):
        normalize_comment({"path": "a.py", "content": "x" * 20_001})
    with pytest.raises(OCRSchemaError, match="maximum count"):
        parse_ocr_envelope(
            {
                "status": "success",
                "comments": [{"path": "a.py", "content": "problem"}] * 10_001,
            }
        )


def test_malformed_json_becomes_failed_with_process_evidence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_fake_popen(monkeypatch, _FakeProcess("{not-json", "warning from ocr"))
    result = OpenCodeReviewRunner().run(tmp_path)

    assert result.status is OCRStatus.FAILED
    assert result.exit_code == 0
    assert result.stderr == "warning from ocr"
    assert result.error is not None
    assert "invalid OCR JSON output" in result.error


def test_schema_parse_error_uses_generic_event_and_result_messages(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_fake_popen(monkeypatch, _FakeProcess(json.dumps({"status": "provider-secret", "comments": []})))
    events: list[dict[str, Any]] = []

    result = OpenCodeReviewRunner().run(tmp_path, event_callback=events.append)

    assert result.status is OCRStatus.FAILED
    assert result.error == "invalid OCR JSON schema"
    assert "provider-secret" not in result.error
    assert [event["type"] for event in events][-2:] == ["ocr.parse_started", "ocr.parse_error"]
    assert all("provider-secret" not in json.dumps(event) for event in events)


def test_timeout_is_failed_and_captures_partial_streams(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    process = _FakeProcess(b"partial stdout", b"partial stderr", returncode=None)
    _patch_fake_popen(monkeypatch, process)
    result = OpenCodeReviewRunner().run(tmp_path, OCRScanConfig(process_timeout_seconds=0.03))

    assert result.status is OCRStatus.FAILED
    assert result.timed_out
    assert result.exit_code == -9
    assert result.stdout == "partial stdout"
    assert result.stderr == "partial stderr"


def test_argv_omits_unconfigured_options() -> None:
    assert OpenCodeReviewRunner("ocr").build_argv() == ["ocr", "scan", "--format", "json", "--audience", "agent"]


def test_runner_accepts_repo_dir_keyword_and_is_callable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    process = _FakeProcess(_envelope())

    def fake_popen(argv: list[str], **kwargs: Any) -> _FakeProcess:
        calls.append(argv)
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = OpenCodeReviewRunner().scan(repo_dir=tmp_path)

    assert result.status is OCRStatus.COMPLETE
    assert calls


@pytest.mark.parametrize(
    "value",
    ["/etc/passwd", "../secret.py", "src/../../secret.py", r"C:\\secret.py", r"..\\secret.py"],
)
def test_paths_reject_absolute_and_traversal_values(value: str) -> None:
    with pytest.raises((ValueError, OCRSchemaError)):
        OCRScanConfig(paths=(value,))
    with pytest.raises(OCRSchemaError):
        normalize_comment({"path": value, "content": "problem"})


def test_cli_paths_reject_commas_because_the_v1_1_9_flag_is_comma_separated() -> None:
    with pytest.raises(ValueError, match="commas"):
        OCRScanConfig(paths=("src/file,name.py",))


@pytest.mark.parametrize(
    "comment",
    [
        {"path": "a.py", "start_line": 0, "end_line": 1, "content": "problem"},
        {"path": "a.py", "start_line": 8, "end_line": 7, "content": "problem"},
        {"path": "a.py", "start_line": 8, "content": "problem"},
        {"path": "a.py", "start_line": True, "end_line": 1, "content": "problem"},
    ],
)
def test_comments_reject_invalid_line_ranges(comment: dict[str, Any]) -> None:
    with pytest.raises(OCRSchemaError):
        normalize_comment(comment)


def test_comments_without_location_are_valid() -> None:
    comment = normalize_comment({"path": "docs/README.md", "content": "Consider documenting this."})
    assert comment.start_line is None
    assert comment.end_line is None


def test_nonzero_exit_is_failed_even_when_json_is_valid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_fake_popen(monkeypatch, _FakeProcess(_envelope(status="completed_with_warnings"), "fatal", returncode=1))
    result = OpenCodeReviewRunner().run(tmp_path)

    assert result.status is OCRStatus.FAILED
    assert result.comments
    assert result.error == "OpenCodeReview exited with status 1"


def test_cancel_check_kills_running_ocr_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    process = _FakeProcess(returncode=None)
    _patch_fake_popen(monkeypatch, process)
    result = OpenCodeReviewRunner("ocr").run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=10),
        cancel_check=lambda: True,
    )

    assert result.status is OCRStatus.FAILED
    assert result.canceled is True
    assert process.killed is True
