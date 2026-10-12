"""Project lifecycle, durable manual statuses, and exact scan baseline behavior."""

import json

import pytest
from fastapi.testclient import TestClient

from argus.ocr_adapter import OCRScanConfig, OCRSchemaError, OCRStatus, OpenCodeReviewRunner, parse_ocr_envelope
from argus.service.app import create_app
from argus.service.execution import execution_slot
from argus.service.models import FindingCreate, ScanStatus, ServiceScanResult
from argus.service.store import ScanStore


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setenv("ARGUS_API_KEY", "project-test")
    store = ScanStore(":memory:")
    client = TestClient(create_app(store))
    headers = {"Authorization": "Bearer project-test"}
    p = client.post(
        "/v1/projects",
        headers=headers,
        json={
            "name": "A",
            "repository_url": "https://example.com/a.git",
            "branch": "main",
        },
    ).json()
    yield store, client, headers, p
    store.close()


def submit(client, headers, project, **changes):
    return client.post(
        f"/v1/projects/{project['id']}/scans", headers=headers, json={"source_disclosure_confirmed": True, **changes}
    )


def finish(store, scan_id, commit, status=ScanStatus.COMPLETED, findings=()):
    claimed = store.claim_next("test")
    assert claimed is not None and claimed.id == scan_id
    store.record_commit(scan_id, "test", commit)
    store.finish(
        scan_id,
        "test",
        ServiceScanResult(status=status, commit_sha=commit, total_files=1, reviewed_files=1, findings=list(findings)),
    )


def test_project_identity_and_validation(setup):
    _, client, auth, project = setup
    assert client.get("/v1/projects").status_code == 401
    assert (
        client.post(
            "/v1/projects",
            headers=auth,
            json={
                "name": "duplicate",
                "repository_url": "https://example.com/a",
                "branch": "main",
            },
        ).status_code
        == 409
    )
    other = client.post(
        "/v1/projects",
        headers=auth,
        json={
            "name": "other branch",
            "repository_url": "https://example.com/a.git",
            "branch": "master",
        },
    )
    assert other.status_code == 201 and other.json()["id"] != project["id"]
    assert submit(client, auth, project, source_disclosure_confirmed=False).status_code == 400
    assert (
        client.post(
            "/v1/projects",
            headers=auth,
            json={
                "name": "unsafe",
                "repository_url": "https://secret@example.com/a",
                "branch": "main",
            },
        ).status_code
        == 422
    )


def test_incremental_baseline_manual_status_and_reports(setup):
    store, client, auth, project = setup
    scan = submit(client, auth, project).json()
    assert scan["scan_type"] == "full" and scan["base_commit"] is None
    assert submit(client, auth, project).status_code == 409
    finding = FindingCreate(
        rule_id="ocr/security",
        title="Missing auth",
        category="security",
        severity="high",
        file="a.py",
        start_line=3,
        message="Missing check",
        evidence=" return read(id) ",
    )
    finish(store, scan["id"], "a" * 40, findings=[finding])
    uri = f"/v1/projects/{project['id']}"
    vulnerability = client.get(uri + "/vulnerabilities", headers=auth).json()["items"][0]
    assert (
        client.patch(
            uri + f"/vulnerabilities/{vulnerability['id']}", headers=auth, json={"status": "fixed"}
        ).status_code
        == 200
    )
    second = submit(client, auth, project).json()
    assert second["scan_type"] == "incremental" and second["base_commit"] == "a" * 40
    finish(
        store,
        second["id"],
        "b" * 40,
        findings=[finding.model_copy(update={"start_line": 90, "evidence": "return  read(id)"})],
    )
    result = client.get(uri + "/vulnerabilities", headers=auth).json()
    assert result["total"] == 1 and result["items"][0]["status"] == "fixed"
    assert result["items"][0]["start_line"] == 90
    assert client.get(uri, headers=auth).json()["baseline_commit"] == "b" * 40
    assert client.get(f"/v1/scans/{scan['id']}/findings", headers=auth).json()["items"][0]["start_line"] == 3
    for format in ("markdown", "json", "sarif"):
        report = client.get(uri + f"/report?format={format}", headers=auth)
        assert report.status_code == 200 and "Missing check" in report.text
    assert "已修复" in client.get(uri + "/report?format=markdown", headers=auth).text


def test_partial_and_config_change_do_not_advance_baseline(setup):
    store, client, auth, project = setup
    first = submit(client, auth, project).json()
    finish(store, first["id"], "a" * 40)
    partial = submit(client, auth, project).json()
    finish(store, partial["id"], "b" * 40, ScanStatus.PARTIAL)
    uri = f"/v1/projects/{project['id']}"
    assert client.get(uri, headers=auth).json()["baseline_commit"] == "a" * 40
    retry = client.post(f"/v1/scans/{partial['id']}/retry", headers=auth).json()
    assert retry["base_commit"] == "a" * 40 and retry["commit_sha"] == "b" * 40
    claimed = store.claim_next("test")
    assert claimed is not None
    assert client.patch(uri, headers=auth, json={"name": "A renamed", "include": ["src"]}).status_code == 200
    store.finish(partial["id"], "test", ServiceScanResult(commit_sha="b" * 40, total_files=1, reviewed_files=1))
    assert client.get(uri, headers=auth).json()["baseline_commit"] is None
    next_scan = submit(client, auth, project).json()
    assert next_scan["scan_type"] == "full" and next_scan["include"] == ["src"]


def test_idempotency_and_stale_retry(setup):
    store, client, auth, project = setup
    headers = {**auth, "Idempotency-Key": "stable"}
    created = submit(client, headers, project)
    assert submit(client, headers, project).status_code == 200
    assert submit(client, headers, project, mode="full").status_code == 409
    finish(store, created.json()["id"], "a" * 40)
    failed = submit(client, auth, project).json()
    finish(store, failed["id"], "b" * 40, ScanStatus.FAILED)
    newer = submit(client, auth, project).json()
    finish(store, newer["id"], "c" * 40)
    assert client.post(f"/v1/scans/{failed['id']}/retry", headers=auth).status_code == 409


def test_forced_full_scan_retry_with_existing_baseline(setup):
    store, client, auth, project = setup
    initial = submit(client, auth, project).json()
    finish(store, initial["id"], "a" * 40)
    full = submit(client, auth, project, mode="full").json()
    finish(store, full["id"], "b" * 40, ScanStatus.FAILED)
    retried = client.post(f"/v1/scans/{full['id']}/retry", headers=auth)
    assert retried.status_code == 200 and retried.json()["commit_sha"] == "b" * 40


def manifest():
    item = {"item_id": "a", "path": "a.py"}
    return {
        "status": "complete",
        "comments": [],
        "manifest": {
            "schema_version": "ocr.run-manifest/v1",
            "operation": "review",
            "terminal_state": "complete",
            "coverage": {"selected": [item], "completed": [item], "reused": [], "failed": [], "waived": []},
        },
    }


def test_review_manifest_canonical_and_reject_invalid_coverage():
    doc = manifest()
    assert parse_ocr_envelope(doc)[0] is OCRStatus.COMPLETE
    doc["manifest"]["coverage"]["completed"] = []
    with pytest.raises(OCRSchemaError):
        parse_ocr_envelope(doc)
    doc = manifest()
    doc["manifest"]["coverage"]["waived"] = doc["manifest"]["coverage"]["completed"]
    with pytest.raises(OCRSchemaError):
        parse_ocr_envelope(doc)


def test_review_command_and_unlimited_budget():
    args = OpenCodeReviewRunner("ocr").build_argv(
        OCRScanConfig(
            base_commit="a" * 40, target_commit="b" * 40, token_budget=0, no_plan=True, no_dedup=True, no_summary=True
        )
    )
    assert args[1] == "review" and args[args.index("--max-tokens-budget") + 1] == "0"
    assert "--no-plan" not in args and "--no-dedup" not in args


def test_execution_slot_does_not_clean_active_workspace(tmp_path):
    from argus.service.execution import execution_fds
    import subprocess
    import sys

    root = tmp_path / "workspaces"
    with execution_slot(root) as acquired:
        assert acquired
        checkout = root / ("a" * 32 + "-checkout")
        checkout.mkdir()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.3)"], pass_fds=execution_fds())
    try:
        with execution_slot(root) as acquired:
            assert not acquired and checkout.exists()
        child.wait(timeout=3)
        with execution_slot(root) as acquired:
            assert acquired and not checkout.exists()
    finally:
        child.wait(timeout=3)


def test_gitlab_helper_is_host_scoped_and_only_get(monkeypatch, tmp_path):
    import os
    import subprocess
    from pathlib import Path
    from argus.service.gitlab import gitlab_environment

    helper = Path(__file__).resolve().parents[2] / "scripts" / "gitlab-credential-helper.sh"
    secret = tmp_path / "secret"
    secret.write_text("synthetic-secret")
    monkeypatch.setenv("ARGUS_GITLAB_HOST", "gitlab.example.com")
    monkeypatch.setenv("ARGUS_GITLAB_USERNAME", "readonly")
    monkeypatch.setenv("ARGUS_GITLAB_TOKEN_FILE", str(secret))
    monkeypatch.setenv("ARGUS_GITLAB_HELPER", str(helper))
    environment = gitlab_environment()
    assert "synthetic-secret" not in json.dumps(environment)
    for host, operation in (("evil.example.com", "get"), ("gitlab.example.com", "store")):
        result = subprocess.run(
            [str(helper), "gitlab.example.com", operation],
            input=f"protocol=https\nhost={host}\n\n",
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0 and result.stdout == ""
    result = subprocess.run(
        [str(helper), "gitlab.example.com", "get"],
        input="protocol=https\nhost=gitlab.example.com\n\n",
        text=True,
        capture_output=True,
    )
    assert result.stdout == "password=synthetic-secret\n"
    filled = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=gitlab.example.com\n\n",
        text=True,
        capture_output=True,
        env={
            **os.environ,
            **environment,
            "HOME": str(tmp_path),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    assert filled.returncode == 0
    assert "username=readonly" in filled.stdout and "password=synthetic-secret" in filled.stdout
