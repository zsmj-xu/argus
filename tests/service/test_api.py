from fastapi.testclient import TestClient

from argus.service.app import create_app
from argus.service.models import FindingCreate, ScanStatus, ServiceScanResult
from argus.service.store import ScanStore


def test_api_serves_built_frontend(monkeypatch, tmp_path) -> None:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text('<main id="root">modern-spa</main>', encoding="utf-8")
    (assets / "app.js").write_text("window.ARGUS_FRONTEND = true;", encoding="utf-8")
    monkeypatch.setenv("ARGUS_FRONTEND_DIR", str(dist))

    client = TestClient(create_app(ScanStore(":memory:")))

    assert "modern-spa" in client.get("/").text
    assert "ARGUS_FRONTEND" in client.get("/assets/app.js").text


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
    assert "# Argus 白盒扫描报告" in markdown.text
    assert "- 代码仓库：" in markdown.text
    assert "### 代码证据" in markdown.text
    assert "### 修复建议" in markdown.text
    assert "This is a static white-box review" not in markdown.text
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


def test_api_findings_pagination_over_50(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "test-key")
    store = ScanStore(":memory:")
    client = TestClient(create_app(store))
    headers = {"Authorization": "Bearer test-key"}

    from argus.service.models import ScanCreateRequest

    scan, _ = store.create_scan(
        ScanCreateRequest(
            repository_url="https://example.com/project.git",
            source_disclosure_confirmed=True,
        )
    )
    claimed = store.claim_next("worker-1")
    assert claimed is not None

    findings = [
        FindingCreate(
            rule_id=f"ocr/rule-{i}",
            title=f"Finding issue {i}",
            category="security" if i % 2 == 0 else "correctness",
            severity="high" if i < 10 else "medium",
            file=f"src/file_{i}.py",
            start_line=i + 1,
            message=f"Description for finding {i}",
        )
        for i in range(55)
    ]
    store.finish(
        scan.id,
        "worker-1",
        ServiceScanResult(status=ScanStatus.COMPLETED, total_files=10, findings=findings),
    )

    page1 = client.get(f"/v1/scans/{scan.id}/findings?limit=50&offset=0", headers=headers)
    assert page1.status_code == 200
    data1 = page1.json()
    assert data1["total"] == 55
    assert len(data1["items"]) == 50

    page2 = client.get(f"/v1/scans/{scan.id}/findings?limit=50&offset=50", headers=headers)
    assert page2.status_code == 200
    data2 = page2.json()
    assert data2["total"] == 55
    assert len(data2["items"]) == 5

    titles_p1 = {item["title"] for item in data1["items"]}
    titles_p2 = {item["title"] for item in data2["items"]}
    assert len(titles_p1) == 50
    assert len(titles_p2) == 5
    assert titles_p1.isdisjoint(titles_p2)
    assert titles_p1.union(titles_p2) == {f"Finding issue {i}" for i in range(55)}
