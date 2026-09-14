"""Opt-in integration test for the real OpenCodeReview binary."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
from threading import Thread

import pytest

from argus.ocr_adapter import OCRScanConfig, OCRStatus, OpenCodeReviewRunner


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
