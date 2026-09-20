"""Offline model substitute across API, separate worker, real Git and SQLite."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from fastapi.testclient import TestClient
import pytest

from argus.service.app import create_app
from argus.service.store import ScanStore


@pytest.mark.parametrize("structured", [False, True])
def test_api_separate_worker_git_events_and_reports(tmp_path: Path, monkeypatch, structured: bool) -> None:
    repo = tmp_path / "repository"
    repo.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (repo / ".opencodereview").mkdir()
    (repo / ".opencodereview" / "config.json").write_text("{}", encoding="utf-8")
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
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
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
    worker = None
    worker_log = tempfile.TemporaryFile(mode="w+b")
    api_store = ScanStore(tmp_path / "shared.sqlite3")
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                assert daemon.poll() is None
                time.sleep(0.02)
        else:
            raise AssertionError("local Git fixture did not start")

        simulator = tmp_path / "ocr-simulator"
        home_marker = tmp_path / "ocr-home-location"
        simulator.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, time\n"
            "assert pathlib.Path('app.py').exists()\n"
            "assert not pathlib.Path('.opencodereview').exists()\n"
            "pathlib.Path(os.environ['HOME'], 'raw-session').write_text('TRANSCRIPT_NOT_FOR_PERSISTENCE')\n"
            f"pathlib.Path({str(home_marker)!r}).write_text(os.environ['HOME'])\n"
            "def event(kind, data):\n"
            "    fd = os.environ.get('ARGUS_OCR_EVENTS_FD')\n"
            "    if fd: os.write(int(fd), (json.dumps({'version':1,'type':kind,'data':data})+'\\n').encode())\n"
            "event('scan.inventory', {'total_files':1})\n"
            "event('file.started', {'path':'app.py'})\n"
            "event('llm.request.started', {'request_id':'req-e2e','model':'synthetic'})\n"
            "os.write(2, b'x' * 262144)\n"
            "time.sleep(1)\n"
            "event('llm.request.headers', {'request_id':'req-e2e','http_status':200})\n"
            "event('llm.request.completed', {'request_id':'req-e2e','total_tokens':40})\n"
            "event('file.completed', {'path':'app.py','reviewed_files':1})\n"
            "print(json.dumps({'status':'complete','summary':{'files_reviewed':1,'comments':1},"
            "'session_id':'synthetic-e2e','comments':[{'path':'app.py','start_line':1,'end_line':1,"
            "'content':'Synthetic finding','category':'security','severity':'low'}]}))\n",
            encoding="utf-8",
        )
        simulator.chmod(0o700)
        monkeypatch.setenv("ARGUS_API_KEY", "test-service-key")
        client = TestClient(create_app(api_store))
        auth = {"Authorization": "Bearer test-service-key"}
        created = client.post(
            "/v1/scans",
            headers=auth,
            json={
                "repository_url": f"git://127.0.0.1:{port}/repository",
                "source_disclosure_confirmed": True,
            },
        )
        assert created.status_code == 202
        scan_id = created.json()["id"]
        env = {
            **os.environ,
            "ARGUS_DATA_DIR": str(tmp_path / "data"),
            "ARGUS_SCAN_DB": str(tmp_path / "shared.sqlite3"),
            "OCR_BINARY": str(simulator),
            "ARGUS_WORKER_POLL_SECONDS": "0.05",
            "OCR_PROCESS_TIMEOUT_SECONDS": "15",
            "ARGUS_LLM_BASE_URL": "http://127.0.0.1:1/v1",
            "ARGUS_LLM_API_KEY": "unused",
            "ARGUS_LLM_MODEL": "synthetic",
            "ARGUS_OCR_EVENT_PROTOCOL": "1" if structured else "0",
        }
        worker = subprocess.Popen(
            [sys.executable, "-m", "argus.service.worker"],
            env=env,
            stdout=worker_log,
            stderr=worker_log,
        )
        observed_running = False
        observed_live_events = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            scan = client.get(f"/v1/scans/{scan_id}", headers=auth).json()
            if scan["status"] == "running":
                observed_running = True
                events = client.get(f"/v1/scans/{scan_id}/events", headers=auth)
                assert events.status_code == 200
                observed_live_events |= bool(events.json()["items"])
            if scan["status"] in {"completed", "failed", "partial", "canceled", "skipped"}:
                break
            assert worker.poll() is None
            time.sleep(0.05)
        assert observed_running and observed_live_events
        assert scan["status"] == "completed", scan
        assert scan["commit_sha"] == commit
        assert scan["finding_count"] == 1
        assert scan["observation"]["report_ready"] is True
        assert scan["observation"]["history_available"] is True
        assert scan["observation"]["capabilities"]["llm_requests"] is structured
        assert scan["observation"]["capabilities"]["event_protocol"] is structured
        assert scan["observation"]["capabilities"]["file_progress"] is structured
        assert scan["observation"]["last_output_at"] is not None
        assert scan["observation"]["deadline_at"] is not None
        events = client.get(f"/v1/scans/{scan_id}/events", headers=auth).json()
        assert len(events["items"]) >= 5
        event_ids = [item["event_id"] for item in events["items"]]
        assert event_ids == sorted(set(event_ids))
        assert all(item["schema_version"] == 1 and item["attempt"] >= 0 for item in events["items"])
        assert any(item["type"] == "ocr.output_activity" for item in events["items"])
        if structured:
            requests = [item for item in events["items"] if item["type"] == "llm.request.completed"]
            assert requests and requests[0]["data"]["request_id"] == "req-e2e"
            files = [item for item in events["items"] if item["type"] == "file.completed"]
            assert files and files[0]["data"]["path"] == "app.py"
        else:
            assert not any(item["type"].startswith("llm.") for item in events["items"])
        for format_name in ("json", "markdown", "sarif"):
            report = client.get(f"/v1/scans/{scan_id}/report?format={format_name}", headers=auth)
            assert report.status_code == 200
            assert "Synthetic finding" in report.text
        export = client.get(f"/v1/scans/{scan_id}/diagnostics/export", headers=auth)
        assert export.status_code == 200
        assert "test-service-key" not in export.text
        assert "x" * 100 not in export.text
        json.loads(export.text)
        worker_log.seek(0)
        logs = worker_log.read().decode("utf-8", errors="replace")
        assert scan_id in logs
        assert "test-service-key" not in logs
        assert "x" * 100 not in logs
        logged_events = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
        assert any(item.get("scan_id") == scan_id and item.get("attempt") == 1 for item in logged_events)
        assert client.get(f"/v1/scans/{scan_id}/events").status_code == 401
        assert list((tmp_path / "data" / "workspaces").iterdir()) == []
        assert not Path(home_marker.read_text()).exists()
        reopened = TestClient(create_app(ScanStore(tmp_path / "shared.sqlite3")))
        assert reopened.get(f"/v1/scans/{scan_id}/events", headers=auth).json() == events
        missing = client.post(
            "/v1/scans",
            headers=auth,
            json={
                "repository_url": f"git://127.0.0.1:{port}/repository",
                "ref": "nonexistent-fixture-ref",
                "source_disclosure_confirmed": True,
            },
        )
        missing_id = missing.json()["id"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            failed_scan = client.get(f"/v1/scans/{missing_id}", headers=auth).json()
            if failed_scan["status"] == "failed":
                break
            time.sleep(0.05)
        assert failed_scan["status"] == "failed"
        diagnostics = client.get(f"/v1/scans/{missing_id}/diagnostics", headers=auth).json()
        assert "ref" in diagnostics["observation"]["error_summary"]["code"].lower(), diagnostics
        assert diagnostics["suggestions"]
    finally:
        if worker is not None:
            # Allow the worker to reap its independently-sessioned OCR child
            # even when an assertion fails while the scan is still running.
            for task in api_store.list_scans()[0]:
                if task.status.value in {"queued", "running"}:
                    api_store.cancel(task.id)
            cleanup_deadline = time.monotonic() + 18
            while worker.poll() is None and time.monotonic() < cleanup_deadline:
                if all(task.status.value not in {"queued", "running"} for task in api_store.list_scans()[0]):
                    break
                time.sleep(0.05)
            worker.terminate()
            worker.wait(timeout=10)
        daemon.terminate()
        daemon.wait(timeout=5)
        api_store.close()
        worker_log.close()
