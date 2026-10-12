"""Real pinned OCR, local synthetic Git and local model: full -> cumulative diff."""

from http.server import ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
from threading import Thread
import time

import pytest
from fastapi.testclient import TestClient

from argus.service.app import create_app
from argus.service.integration import GitWorkspaceProvider, OpenCodeReviewServiceRunner
from argus.service.store import ScanStore
from argus.service.worker import ScanWorker
from tests.test_live_ocr_integration import _FakeOpenAIHandler


@pytest.mark.skipif(not os.getenv("ARGUS_OCR_TEST_BINARY"), reason="requires pinned OCR binary")
def test_project_full_incremental_no_changes_and_history_divergence(tmp_path: Path, monkeypatch):
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    auth_source = repository / "src" / "auth.py"
    auth_source.write_text(
        "def get_password(request):\n    password = request.args.get('password')\n    return password\n"
    )

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()

    git("init", "-b", "main", "--quiet")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")

    def commit(message):
        git("add", ".")
        git("commit", "--quiet", "-m", message)
        return git("rev-parse", "HEAD")

    baseline = commit("initial")
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
            str(repository),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _FakeOpenAIHandler.requests = 0
    _FakeOpenAIHandler.bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAIHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    store = ScanStore(tmp_path / "service.sqlite3")
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                assert daemon.poll() is None
                time.sleep(0.02)
        monkeypatch.setenv("ARGUS_API_KEY", "fixture")
        monkeypatch.setenv("OCR_BINARY", os.environ["ARGUS_OCR_TEST_BINARY"])
        monkeypatch.setenv("ARGUS_LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
        monkeypatch.setenv("ARGUS_LLM_API_KEY", "synthetic-key")
        monkeypatch.setenv("ARGUS_LLM_MODEL", "synthetic-model")
        monkeypatch.setenv("OCR_PROCESS_TIMEOUT_SECONDS", "90")
        monkeypatch.setenv("OCR_MAX_TOKENS_BUDGET", "1")  # stale deployment setting must have no effect
        for key in ("ARGUS_GITLAB_HOST", "ARGUS_GITLAB_USERNAME", "ARGUS_GITLAB_TOKEN_FILE"):
            monkeypatch.delenv(key, raising=False)
        runner = OpenCodeReviewServiceRunner.from_environment()
        assert runner.token_budget == 0
        worker = ScanWorker(store, GitWorkspaceProvider(tmp_path / "workspaces"), runner)
        client = TestClient(create_app(store))
        headers = {"Authorization": "Bearer fixture"}
        project = client.post(
            "/v1/projects",
            headers=headers,
            json={
                "name": "Synthetic project",
                "branch": "main",
                "include": ["src"],
                "repository_url": f"git://127.0.0.1:{port}/repository",
            },
        ).json()
        uri = f"/v1/projects/{project['id']}"

        def scan(mode="auto"):
            response = client.post(
                uri + "/scans", headers=headers, json={"mode": mode, "source_disclosure_confirmed": True}
            )
            assert response.status_code == 202, response.text
            identity = response.json()["id"]
            worker.run_once()
            result = client.get(f"/v1/scans/{identity}", headers=headers).json()
            assert list((tmp_path / "workspaces").iterdir()) == []
            return result

        first = scan()
        assert first["status"] == "completed", first
        assert first["commit_sha"] == baseline and first["scan_type"] == "full"
        (repository / "src" / "extra.py").write_text("def extra():\n    return 1\n")
        commit("intermediate change")
        auth_source.write_text(
            auth_source.read_text() + "\ndef another(request):\n    return request.args.get('password')\n"
        )
        # A change outside the project's selected scope must not be reviewed.
        (repository / "outside.py").write_text("value = 'out of scope'\n")
        target = commit("latest change")
        second = scan()
        assert second["status"] == "completed", second
        assert second["base_commit"] == baseline and second["commit_sha"] == target
        assert second["metadata"]["ocr_scan_schema_version"] == "ocr.run-manifest/v1"
        assert second["progress"]["total_files"] == 2
        assert "out of scope" not in str(_FakeOpenAIHandler.bodies)
        requests = _FakeOpenAIHandler.requests
        unchanged = scan()
        assert unchanged["status"] == "completed" and unchanged["metadata"]["no_changes"]
        assert _FakeOpenAIHandler.requests == requests
        assert client.get(uri + "/scans", headers=headers).json()["total"] == 3
        assert client.get(uri, headers=headers).json()["baseline_commit"] == target
        # An orphan branch creates a force-push-like disjoint history, in this fixture only.
        git("checkout", "--quiet", "--orphan", "replacement")
        commit("replacement root")
        git("branch", "-M", "main")
        divergent = scan()
        assert divergent["status"] == "failed" and divergent["error"] == "git_baseline_diverged"
        assert client.get(uri, headers=headers).json()["baseline_commit"] == target
    finally:
        server.shutdown()
        server.server_close()
        daemon.terminate()
        daemon.wait(timeout=5)
        store.close()
