from fastapi.testclient import TestClient

from argus.service.app import create_app
from argus.service.models import FindingCreate, ScanStatus, ServiceScanResult
from argus.service.store import ScanStore


def test_api_auth_idempotency_and_reports(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")
    monkeypatch.setenv("OCR_BINARY", "/usr/bin/true")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "llm-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "test-model")
    store = ScanStore(":memory:")
    client = TestClient(create_app(store))

    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    assert client.get("/v1/scans").status_code == 401

    headers = {"Authorization": "Bearer test-key", "Idempotency-Key": "scan-1"}
    payload = {
        "repository_url": "https://github.com/example/project.git",
        "ref": "main",
        "background": "Review authentication and authorization.",
        "source_disclosure_confirmed": True,
    }
    created = client.post("/v1/scans", json=payload, headers=headers)
    repeated = client.post("/v1/scans", json=payload, headers=headers)
    assert created.status_code == 202
    assert repeated.status_code == 200
    scan_id = created.json()["id"]
    assert repeated.json()["id"] == scan_id

    claimed = store.claim_next("worker-1")
    assert claimed is not None
    store.finish(
        scan_id,
        "worker-1",
        ServiceScanResult(
            status=ScanStatus.COMPLETED,
            commit_sha="a" * 40,
            total_files=4,
            reviewed_files=4,
            findings=[
                FindingCreate(
                    rule_id="ocr/security",
                    title="Missing authorization check",
                    category="security",
                    severity="high",
                    file="src/auth.py",
                    start_line=12,
                    end_line=14,
                    message="The resource owner is not checked.",
                    evidence="return store.get(resource_id)",
                    remediation="Check the authenticated owner's access before reading the resource.",
                )
            ],
        ),
    )

    auth = {"Authorization": "Bearer test-key"}
    detail = client.get(f"/v1/scans/{scan_id}", headers=auth)
    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"
    assert detail.json()["commit_sha"] == "a" * 40
    findings = client.get(f"/v1/scans/{scan_id}/findings", headers=auth)
    assert findings.status_code == 200
    assert findings.json()["total"] == 1
    assert findings.json()["items"][0]["start_line"] == 12
    markdown = client.get(f"/v1/scans/{scan_id}/report?format=markdown", headers=auth)
    assert markdown.status_code == 200 and "Missing authorization check" in markdown.text
    sarif = client.get(f"/v1/scans/{scan_id}/report/sarif", headers=auth)
    assert sarif.json()["version"] == "2.1.0"
    assert sarif.json()["runs"][0]["results"][0]["ruleId"] == "ocr/security"


def test_api_cancel_retry_and_idempotency_conflict(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")
    monkeypatch.setenv("OCR_BINARY", "/usr/bin/true")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "llm-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "test-model")
    store = ScanStore(":memory:")
    client = TestClient(create_app(store))
    headers = {"Authorization": "Bearer test-key", "Idempotency-Key": "same-key"}

    created = client.post(
        "/v1/scans",
        json={"repository_url": "https://example.com/a.git", "source_disclosure_confirmed": True},
        headers=headers,
    )
    scan_id = created.json()["id"]
    assert client.post(f"/v1/scans/{scan_id}/cancel", headers=headers).json()["status"] == "canceled"
    assert client.post(f"/v1/scans/{scan_id}/retry", headers=headers).json()["status"] == "queued"
    conflict = client.post(
        "/v1/scans",
        json={"repository_url": "https://example.com/b.git", "source_disclosure_confirmed": True},
        headers=headers,
    )
    assert conflict.status_code == 409

    rejected = client.post(
        "/v1/scans",
        json={"repository_url": "https://example.com/no-consent.git"},
        headers={"Authorization": "Bearer test-key"},
    )
    assert rejected.status_code == 400


def test_api_reports_full_queue(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")
    monkeypatch.setenv("OCR_BINARY", "/usr/bin/true")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "llm-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "test-model")
    store = ScanStore(":memory:", max_queue=1)
    client = TestClient(create_app(store))
    headers = {"Authorization": "Bearer test-key"}
    assert (
        client.post(
            "/v1/scans",
            json={"repository_url": "https://example.com/a.git", "source_disclosure_confirmed": True},
            headers=headers,
        ).status_code
        == 202
    )
    response = client.post(
        "/v1/scans",
        json={"repository_url": "https://example.com/b.git", "source_disclosure_confirmed": True},
        headers=headers,
    )
    assert response.status_code == 429
