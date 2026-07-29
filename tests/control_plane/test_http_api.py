from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
from typing import Any

from argus.web import make_server

from .test_service import _seed


def _request(
    server: ThreadingHTTPServer,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str, bytes]:
    host, port = server.server_address[:2]
    connection = HTTPConnection(str(host), int(port), timeout=5)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    media_type = response.getheader("Content-Type") or ""
    status = response.status
    connection.close()
    return status, media_type, data


def _running_server(tmp_path: Path) -> tuple[ThreadingHTTPServer, threading.Thread]:
    ui_root = Path(__file__).parents[2] / "argus" / "web_ui"
    server = make_server(
        host="127.0.0.1",
        port=0,
        project_root=tmp_path,
        runs_root=tmp_path / "runs",
        ui_root=ui_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_project_crud_routes_are_json_and_persistent(tmp_path: Path) -> None:
    server, thread = _running_server(tmp_path)
    try:
        status, media_type, raw = _request(
            server,
            "POST",
            "/api/projects",
            {
                "name": "http-demo",
                "repository_path": str(tmp_path),
                "default_config": {"analysisMode": "v2"},
            },
        )
        created = json.loads(raw)
        assert status == 201
        assert media_type.startswith("application/json")

        status, _, raw = _request(server, "GET", "/api/projects")
        assert status == 200
        assert json.loads(raw)["projects"][0]["id"] == created["id"]

        status, _, raw = _request(
            server,
            "PATCH",
            f"/api/projects/{created['id']}",
            {"name": "http-renamed"},
        )
        assert status == 200
        assert json.loads(raw)["name"] == "http-renamed"

        status, _, _ = _request(
            server,
            "GET",
            "/api/projects/not-a-uuid",
        )
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_scan_resource_routes_and_verified_artifact_download(
    tmp_path: Path,
) -> None:
    _project, scan, _task, artifact = _seed(tmp_path)
    server, thread = _running_server(tmp_path)
    try:
        for resource, key in (
            ("", "id"),
            ("/tasks", "tasks"),
            ("/events", "events"),
            ("/artifacts", "artifacts"),
            ("/findings", "findings"),
        ):
            status, media_type, raw = _request(
                server,
                "GET",
                f"/api/scans/{scan.id}{resource}",
            )
            assert status == 200
            assert media_type.startswith("application/json")
            assert key in json.loads(raw)

        status, _, raw = _request(
            server,
            "GET",
            f"/api/artifacts/{artifact.id}",
        )
        detail = json.loads(raw)
        assert status == 200
        assert "storage_uri" not in detail
        assert detail["preview"]["available"] is True

        status, media_type, raw = _request(
            server,
            "GET",
            f"/api/artifacts/{artifact.id}?download=1",
        )
        assert status == 200
        assert media_type == "application/json"
        assert json.loads(raw) == {
            "kind": "finding",
            "value": "safe preview",
        }

        status, _, raw = _request(
            server,
            "GET",
            json.loads(_request(server, "GET", f"/api/scans/{scan.id}/findings")[2])["findings"][0]["graph_slice_url"],
        )
        assert status == 200
        assert json.loads(raw)["graph_slice"]["seed_ids"] == ["sir:route:get-order"]

        status, _, _ = _request(
            server,
            "GET",
            "/api/artifacts/../../etc/passwd",
        )
        assert status in {400, 404}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_m8_verification_profile_and_missing_input_routes(tmp_path: Path) -> None:
    project, scan, _task, _artifact = _seed(tmp_path)
    server, thread = _running_server(tmp_path)
    try:
        status, _, raw = _request(
            server,
            "POST",
            f"/api/projects/{project.id}/verification/environments",
            {
                "kind": "existing_url",
                "target_base_url": "https://test.example.local",
                "scope_allowlist": [
                    {
                        "scheme": "https",
                        "host": "test.example.local",
                        "path_prefix": "/api/",
                    }
                ],
                "capabilities": ["readonly_http"],
            },
        )
        assert status == 201
        assert json.loads(raw)["target_base_url"] == "https://test.example.local"

        status, _, raw = _request(
            server,
            "POST",
            f"/api/projects/{project.id}/verification/identities",
            {
                "handle": "owner",
                "role": "owner",
                "credential_ref": "env:ARGUS_TEST_OWNER_TOKEN",
            },
        )
        assert status == 201
        assert json.loads(raw)["credential_ref"] == "env:ARGUS_TEST_OWNER_TOKEN"

        status, _, raw = _request(
            server,
            "GET",
            f"/api/projects/{project.id}/verification/identities",
        )
        assert status == 200
        assert len(json.loads(raw)["identities"]) == 1

        finding_id = json.loads(_request(server, "GET", f"/api/scans/{scan.id}/findings")[2])["findings"][0]["id"]
        status, _, raw = _request(
            server,
            "POST",
            f"/api/findings/{finding_id}/verification/requirements",
            {
                "declaration": {
                    "verifier_id": "authorization_differential_read",
                    "supported_vuln_classes": ["authorization"],
                    "required_environment_capabilities": ["readonly_http"],
                    "required_identity_roles": ["owner", "peer"],
                    "required_test_data": ["resource_id"],
                },
                "test_data_keys": [],
            },
        )
        assert status == 201
        assert json.loads(raw)["missing_fields"] == [
            "identity.role:peer",
            "test_data:resource_id",
        ]

        status, _, raw = _request(
            server,
            "GET",
            f"/api/findings/{finding_id}/verification",
        )
        assert status == 200
        summary = json.loads(raw)
        assert summary["status"] == "disabled"
        assert summary["network_execution_available"] is False
        assert summary["missing_fields"] == [
            "identity.role:peer",
            "test_data:resource_id",
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
