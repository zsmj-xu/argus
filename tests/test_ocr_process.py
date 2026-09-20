"""Real subprocess tests for the OCR process and diagnostics boundaries."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import textwrap
import time
from typing import Any

import pytest

import argus.ocr_adapter as ocr_adapter
from argus.ocr_adapter import OCRScanConfig, OCRStatus, OpenCodeReviewRunner


def _fake_ocr(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake-ocr"
    script.write_text(f"#!{sys.executable}\n{textwrap.dedent(body)}", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _valid_output() -> str:
    return json.dumps({"status": "success", "comments": []})


@pytest.mark.parametrize("with_cancel_check", [False, True])
def test_real_subprocess_drains_large_unnewline_bursts_from_both_streams(
    tmp_path: Path, with_cancel_check: bool
) -> None:
    script = _fake_ocr(
        tmp_path,
        f"""
        import sys
        import time

        sys.stdout.write(" " * (300 * 1024))
        sys.stdout.flush()
        sys.stderr.write("E" * (300 * 1024))
        sys.stderr.flush()
        time.sleep(1)
        sys.stdout.write({json.dumps(_valid_output())})
        sys.stdout.flush()
        """,
    )
    runner = OpenCodeReviewRunner(script)
    kwargs: dict[str, Any] = {}
    if with_cancel_check:
        kwargs["cancel_check"] = lambda: False

    result = runner.run(tmp_path, OCRScanConfig(process_timeout_seconds=20), **kwargs)

    assert result.status is OCRStatus.COMPLETE
    assert result.timed_out is False
    assert len(result.stdout) > 300 * 1024
    assert len(result.stderr) == 300 * 1024


def test_small_output_activity_is_visible_before_process_exit(tmp_path: Path) -> None:
    late_marker = tmp_path / "late.marker"
    script = _fake_ocr(
        tmp_path,
        f"""
        import json
        from pathlib import Path
        import sys
        import time

        sys.stderr.write("early")
        sys.stderr.flush()
        time.sleep(0.5)
        Path({str(late_marker)!r}).write_text("late")
        sys.stdout.write(json.dumps({{"status": "success", "comments": []}}))
        sys.stdout.flush()
        """,
    )
    activity: list[bool] = []

    def on_event(event: dict[str, Any]) -> None:
        if event["type"] == "ocr.output_activity":
            activity.append(late_marker.exists())

    result = OpenCodeReviewRunner(script).run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=10),
        event_callback=on_event,
    )

    assert result.status is OCRStatus.COMPLETE
    assert activity
    assert activity[0] is False


def test_output_overflow_is_bounded_and_kills_the_process_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    limit = 64 * 1024
    monkeypatch.setattr(ocr_adapter, "_MAX_PROCESS_OUTPUT_BYTES", limit)
    script = _fake_ocr(
        tmp_path,
        """
        import sys
        import time

        sys.stdout.write("O" * (512 * 1024))
        sys.stdout.flush()
        sys.stderr.write("E" * (512 * 1024))
        sys.stderr.flush()
        time.sleep(30)
        """,
    )
    events: list[dict[str, Any]] = []

    result = OpenCodeReviewRunner(script).run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=20),
        event_callback=events.append,
    )

    assert result.status is OCRStatus.FAILED
    assert result.timed_out is False
    assert result.canceled is False
    assert result.error == "OpenCodeReview process output exceeded the configured limit"
    assert len(result.stdout.encode()) <= limit
    assert len(result.stderr.encode()) <= limit
    assert "ocr.output_limit" in {event["type"] for event in events}
    assert all(set(event) == {"source", "type", "stage", "level", "code", "message", "data"} for event in events)
    assert all(
        isinstance(value, int) and not isinstance(value, bool)
        for event in events
        if event["type"] == "ocr.output_activity"
        for value in event["data"].values()
    )
    assert all("O" * 10 not in event["message"] and "E" * 10 not in event["message"] for event in events)


def _descendant_script(tmp_path: Path, marker: Path, pid_file: Path) -> Path:
    child_code = f"import pathlib, time; time.sleep(0.9); pathlib.Path({str(marker)!r}).write_text('descendant-alive')"
    return _fake_ocr(
        tmp_path,
        f"""
        import pathlib
        import subprocess
        import sys
        import time

        child = subprocess.Popen([sys.executable, "-c", {child_code!r}])
        pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))
        time.sleep(30)
        """,
    )


@pytest.mark.parametrize("mode", ["timeout", "cancel"])
def test_timeout_and_cancel_kill_descendants(tmp_path: Path, mode: str) -> None:
    marker = tmp_path / f"{mode}.marker"
    pid_file = tmp_path / f"{mode}.pid"
    script = _descendant_script(tmp_path, marker, pid_file)
    events: list[dict[str, Any]] = []
    started = time.monotonic()
    kwargs: dict[str, Any] = {"event_callback": events.append}
    if mode == "timeout":
        config = OCRScanConfig(process_timeout_seconds=0.2)
    else:
        config = OCRScanConfig(process_timeout_seconds=10)
        kwargs["cancel_check"] = lambda: time.monotonic() - started >= 0.2

    result = OpenCodeReviewRunner(script).run(tmp_path, config, **kwargs)

    assert pid_file.exists()
    if mode == "timeout":
        assert result.timed_out is True
        assert "ocr.timeout" in {event["type"] for event in events}
    else:
        assert result.canceled is True
        assert "ocr.canceled" in {event["type"] for event in events}
    time.sleep(1.1)
    assert not marker.exists()


def test_event_callback_failure_returns_safely_without_leaking_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "callback.marker"
    pid_file = tmp_path / "callback.pid"
    script = _descendant_script(tmp_path, marker, pid_file)

    def on_event(event: dict[str, Any]) -> None:
        if event["type"] == "ocr.output_activity":
            raise RuntimeError("diagnostic secret must not escape")

    # The descendant script has no stdout/stderr before sleeping, so trigger
    # the callback with a small, independent diagnostic write in a wrapper.
    wrapper = _fake_ocr(
        tmp_path,
        f"""
        import pathlib
        import subprocess
        import sys
        import time

        child = subprocess.Popen([sys.executable, {str(script)!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))
        sys.stderr.write("activity")
        sys.stderr.flush()
        time.sleep(0.5)
        sys.stdout.write({json.dumps(_valid_output())})
        sys.stdout.flush()
        """,
    )

    result = OpenCodeReviewRunner(wrapper).run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=10),
        event_callback=on_event,
    )

    assert result.status is OCRStatus.COMPLETE
    assert result.error is None
    time.sleep(1.1)
    assert not marker.exists()


def test_structured_event_protocol_forwards_only_safe_v1_events(tmp_path: Path) -> None:
    script = _fake_ocr(
        tmp_path,
        f"""
        import json
        import os
        import sys

        fd = int(os.environ["ARGUS_OCR_EVENTS_FD"])
        events = [
            {{"version": 1, "type": "session.started", "data": {{"session_id": "sess-1", "model": "safe-model", "secret": "drop"}}}},
            {{"version": 1, "type": "scan.inventory", "data": {{"files": 2, "session_id": "sess-1", "source": "drop"}}}},
            {{"version": 1, "type": "file.started", "data": {{"path": "src/secret.py", "file_id": "file_1", "index": 1, "total": 2, "message": "drop"}}}},
            {{"version": 1, "type": "file.completed", "data": {{"path": "src/secret.py", "duration_ms": 4, "comments": 1}}}},
            {{"version": 1, "type": "file.failed", "data": {{"path": "src/bad.py", "error": "provider secret", "exit_code": 1}}}},
            {{"version": 1, "type": "llm.request.started", "data": {{"request_id": "req-1", "session_id": "sess-1", "provider": "gateway", "model": "safe-model", "attempt": 1}}}},
            {{"version": 1, "type": "llm.request.headers", "data": {{"request_id": "req-1", "headers": {{"Authorization": "secret"}}, "headers_count": 2}}}},
            {{"version": 1, "type": "llm.request.completed", "data": {{"request_id": "req-1", "status_code": 200, "total_tokens": 9}}}},
            {{"version": 1, "type": "llm.request.failed", "data": {{"request_id": "req-2", "status_code": 500, "error": "provider diagnostic"}}}},
            {{"version": 1, "type": "llm.request.retry", "data": {{"request_id": "req-2", "retry_count": 1}}}},
            {{"version": 1, "type": "tool.started", "data": {{"tool": "read_file", "tool_id": "tool-1"}}}},
            {{"version": 1, "type": "tool.completed", "data": {{"tool": "read_file", "tool_id": "tool-1", "duration_ms": 2}}}},
            {{"version": 1, "type": "tool.failed", "data": {{"tool": "read_file", "error": "source secret"}}}},
            {{"type": "file.started", "data": {{"path": "missing-version.py"}}}},
            {{"version": 1, "type": "future.unknown", "data": {{"message": "raw secret"}}}},
        ]
        for event in events:
            os.write(fd, (json.dumps(event, separators=(",", ":")) + "\\n").encode())
        os.write(fd, b"{{malformed}}\\n")
        os.write(fd, b"{{\\\"version\\\":1,\\\"type\\\":\\\"file.started\\\",\\\"data\\\":{{\\\"path\\\":\\\"" + b"x" * 9000 + b"\\\"}}}}\\n")
        os.close(fd)
        sys.stdout.write({json.dumps(_valid_output())})
        sys.stdout.flush()
        """,
    )
    forwarded: list[dict[str, Any]] = []

    result = OpenCodeReviewRunner(script, structured_event_protocol=True).run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=10),
        event_callback=forwarded.append,
    )

    assert result.status is OCRStatus.COMPLETE
    expected_types = {
        "session.started",
        "scan.inventory",
        "file.started",
        "file.completed",
        "file.failed",
        "llm.request.started",
        "llm.request.headers",
        "llm.request.completed",
        "llm.request.failed",
        "llm.request.retry",
        "tool.started",
        "tool.completed",
        "tool.failed",
    }
    structured = [event for event in forwarded if event["type"] in expected_types]
    assert {event["type"] for event in structured} == expected_types
    assert all(
        set(event) == {"source", "type", "stage", "level", "code", "message", "data"}
        and event["source"] == "ocr"
        and event["stage"] in {"ocr_starting", "ocr_running", "parsing"}
        and "scan_id" not in event
        and "attempt" not in event
        for event in forwarded
    )
    assert all(
        isinstance(value, (int, str)) and not isinstance(value, bool)
        for event in structured
        for value in event["data"].values()
    )
    file_start = next(event for event in structured if event["type"] == "file.started")
    assert file_start["data"] == {"path": "src/secret.py", "file_id": "file_1", "index": 1, "total": 2}
    activity = [event for event in forwarded if event["type"] == "ocr.output_activity"]
    assert activity
    assert any(
        event["data"]["structured_events_rejected"] > 0 and event["data"]["structured_events_dropped"] > 0
        for event in activity
    )
    assert all(
        secret not in json.dumps(event, sort_keys=True)
        for event in forwarded
        for secret in ("raw secret", "provider secret", "Authorization", "source secret")
    )


def test_structured_event_queue_overflow_is_dropped_without_failing_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(ocr_adapter, "_MAX_STRUCTURED_EVENT_QUEUE", 4)
    script = _fake_ocr(
        tmp_path,
        f"""
        import json
        import os
        import sys

        fd = int(os.environ["ARGUS_OCR_EVENTS_FD"])
        for index in range(40):
            event = {{"version": 1, "type": "file.completed", "data": {{"index": index, "path": "src/file.py"}}}}
            os.write(fd, (json.dumps(event) + "\\n").encode())
        os.close(fd)
        sys.stdout.write({json.dumps(_valid_output())})
        sys.stdout.flush()
        """,
    )
    forwarded: list[dict[str, Any]] = []

    def on_event(event: dict[str, Any]) -> None:
        if event["type"] == "file.completed":
            time.sleep(0.02)
        forwarded.append(event)

    result = OpenCodeReviewRunner(script, structured_event_protocol=True).run(
        tmp_path,
        OCRScanConfig(process_timeout_seconds=10),
        event_callback=on_event,
    )

    assert result.status is OCRStatus.COMPLETE
    activity = [event for event in forwarded if event["type"] == "ocr.output_activity"]
    assert activity
    assert any(event["data"]["structured_events_dropped"] > 0 for event in activity)
