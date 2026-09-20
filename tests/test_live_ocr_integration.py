"""Opt-in integration test for the real OpenCodeReview binary."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from threading import Thread

import pytest
from fastapi.testclient import TestClient

from argus.ocr_adapter import OCRScanConfig, OCRStatus, OpenCodeReviewRunner
from argus.service.app import create_app
from argus.service.store import ScanStore


class _FakeOpenAIHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        type(self).requests += 1
        has_tool_result = any(message.get("role") == "tool" for message in body.get("messages", []))
        if has_tool_result:
            name = "task_done"
            arguments = {"state": "DONE"}
        else:
            name = "code_comment"
            arguments = {
                "comments": [
                    {
                        "path": "src/auth.py",
                        "content": "Validate the password before using it.",
                        "existing_code": "password = request.args.get('password')",
                        "suggestion_code": "password = validate(request.args.get('password'))",
                        "category": "security",
                        "severity": "high",
                    }
                ]
            }
        response = {
            "id": "chatcmpl-argus-test",
            "object": "chat.completion",
            "model": body.get("model", "test-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": f"call-{type(self).requests}",
                                "type": "function",
                                "function": {"name": name, "arguments": json.dumps(arguments)},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 12, "total_tokens": 32},
        }
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.mark.skipif(not os.getenv("ARGUS_OCR_TEST_BINARY"), reason="set ARGUS_OCR_TEST_BINARY for real OCR integration")
def test_real_opencode_review_full_file_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "src").mkdir(parents=True)
    (checkout / "src" / "auth.py").write_text(
        "def get_password(request):\n    password = request.args.get('password')\n    return password\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(checkout), "init", "--quiet"], check=True)
    handler = _FakeOpenAIHandler
    handler.requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = os.environ.copy()
        env.update(
            {
                "OCR_LLM_URL": f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                "OCR_LLM_TOKEN": "test-token",
                "OCR_LLM_MODEL": "test-model",
                "OCR_LLM_PROTOCOL": "openai",
                "OCR_USE_ANTHROPIC": "false",
                "HOME": str(tmp_path / "ocr-home"),
            }
        )
        runner = OpenCodeReviewRunner(os.environ["ARGUS_OCR_TEST_BINARY"], environment=env)
        result = runner.run(
            checkout,
            OCRScanConfig(
                no_plan=True,
                no_dedup=True,
                no_summary=True,
                process_timeout_seconds=120,
            ),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.status is OCRStatus.COMPLETE
    assert result.comments and result.comments[0].path == "src/auth.py"
    assert result.comments[0].start_line == 2
    assert result.comments[0].category == "security"
    assert handler.requests >= 2
    assert result.scan_result is not None
    assert result.scan_result.schema_version == "ocr.scan-result/v1"
    assert result.scan_result.outcome is OCRStatus.COMPLETE
    assert result.scan_result.coverage.total == 1
    assert result.scan_result.coverage.reviewed == 1


@pytest.mark.skipif(not os.getenv("ARGUS_OCR_TEST_BINARY"), reason="set ARGUS_OCR_TEST_BINARY for real OCR integration")
def test_argus_api_worker_uses_real_ocr_and_local_llm_stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repository"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "auth.py").write_text(
        "def get_password(request):\n    password = request.args.get('password')\n    return password\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        check=True,
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    daemon = subprocess.Popen(
        [
            "git",
            "daemon",
            "--reuseaddr",
            "--export-all",
            "--listen=127.0.0.1",
            f"--port={port}",
            f"--base-path={tmp_path}",
            str(repo),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    handler = _FakeOpenAIHandler
    handler.requests = 0
    llm_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    llm_thread = Thread(target=llm_server.serve_forever, daemon=True)
    llm_thread.start()
    worker = None
    store = ScanStore(tmp_path / "shared.sqlite3")
    monkeypatch.setenv("ARGUS_API_KEY", "test-service-key")
    client = TestClient(create_app(store))
    auth = {"Authorization": "Bearer test-service-key"}
    try:
        created = client.post(
            "/v1/scans",
            headers=auth,
            json={
                "repository_url": f"git://127.0.0.1:{port}/repository",
                "source_disclosure_confirmed": True,
            },
        )
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]
        worker_env = {
            **os.environ,
            "ARGUS_DATA_DIR": str(tmp_path / "data"),
            "ARGUS_SCAN_DB": str(tmp_path / "shared.sqlite3"),
            "OCR_BINARY": os.environ["ARGUS_OCR_TEST_BINARY"],
            "ARGUS_WORKER_POLL_SECONDS": "0.05",
            "OCR_PROCESS_TIMEOUT_SECONDS": "120",
            "ARGUS_LLM_BASE_URL": f"http://127.0.0.1:{llm_server.server_port}/v1",
            "ARGUS_LLM_API_KEY": "test-token",
            "ARGUS_LLM_MODEL": "test-model",
            "ARGUS_OCR_EVENT_PROTOCOL": "1",
        }
        worker = subprocess.Popen(
            [sys.executable, "-m", "argus.service.worker"],
            env=worker_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            scan = client.get(f"/v1/scans/{scan_id}", headers=auth).json()
            if scan["status"] in {"completed", "partial", "failed", "canceled", "skipped"}:
                break
            assert worker.poll() is None
            time.sleep(0.1)
        if scan["status"] != "completed":
            diagnostics = client.get(f"/v1/scans/{scan_id}/diagnostics", headers=auth).json()
            raise AssertionError(json.dumps({"scan": scan, "diagnostics": diagnostics}, ensure_ascii=False, indent=2))
        assert scan["finding_count"] >= 1
        assert scan["observation"]["coverage"] == {
            "total": 1,
            "reviewed": 1,
            "failed": 0,
            "skipped": 0,
            "percent": 100,
        }
        assert scan["metadata"]["ocr_engine_commit"] == "072808b6b0b12a1408b31889539c03878eff0f61"
        assert scan["metadata"]["ocr_scan_schema_version"] == "ocr.scan-result/v1"
        assert scan["metadata"]["ocr_outcome"] == "complete"
        events = client.get(f"/v1/scans/{scan_id}/events", headers=auth).json()["items"]
        event_types = {event["type"] for event in events}
        assert {"session.started", "scan.inventory", "file.started", "file.completed"} <= event_types
        assert scan["observation"]["capabilities"]["event_protocol"] is True
        assert scan["observation"]["capabilities"]["file_progress"] is True
        assert handler.requests >= 2
        report = client.get(f"/v1/scans/{scan_id}/report?format=json", headers=auth)
        assert report.status_code == 200
        assert "Validate the password" in report.text
    finally:
        if worker is not None:
            for task in store.list_scans()[0]:
                if task.status.value in {"queued", "running"}:
                    store.cancel(task.id)
            worker.terminate()
            worker.wait(timeout=10)
        llm_server.shutdown()
        llm_server.server_close()
        llm_thread.join(timeout=5)
        daemon.terminate()
        daemon.wait(timeout=5)
        store.close()
