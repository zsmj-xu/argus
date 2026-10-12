"""FastAPI boundary for the internal Argus white-box scanning service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
from typing import Annotated, Callable, TypeVar

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, Security, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from argus import __version__

from .models import (
    ReportFormat,
    ScanCreateRequest,
    ScanDiagnosticsResponse,
    ScanEventsResponse,
    ScanListResponse,
    ScanReport,
    ScanResponse,
    ProjectCreateRequest,
    ProjectUpdateRequest,
    ProjectScanRequest,
    VulnerabilityUpdateRequest,
    FindingResponse,
)
from .projects import ProjectService
from .reports import render_report, render_project_report
from .store import (
    IdempotencyConflict,
    QueueFull,
    ScanNotFound,
    ScanStateError,
    ScanStore,
    resolve_scan_database,
)


T = TypeVar("T")


def create_app(store: ScanStore | None = None) -> FastAPI:
    if store is None:
        store = ScanStore(
            resolve_scan_database(),
            max_queue=_positive_env_int("ARGUS_MAX_QUEUE", 100),
        )
    app = FastAPI(
        title="Argus White-box Scan Service",
        version=__version__,
        description="Internal API for repository/branch projects, full-file and incremental OpenCodeReview scans.",
    )
    app.state.scan_store = store

    bearer_scheme = HTTPBearer(
        auto_error=False,
        scheme_name="BearerAuth",
        description="Use the Argus API key as a Bearer token.",
    )

    def require_auth(credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme)) -> None:
        expected = os.getenv("ARGUS_API_KEY")
        if not expected:
            raise HTTPException(status_code=503, detail="ARGUS_API_KEY is not configured")
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="Bearer API key required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        supplied = credentials.credentials.strip()
        if not supplied or not hmac.compare_digest(
            hashlib.sha256(supplied.encode("utf-8")).digest(),
            hashlib.sha256(expected.encode("utf-8")).digest(),
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    auth = Depends(require_auth)
    projects = ProjectService(store)

    @app.post("/v1/projects", status_code=201, dependencies=[auth])
    def create_project(payload: ProjectCreateRequest) -> dict[str, object]:
        try:
            return projects.create(payload)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "a project for this repository and branch already exists") from exc

    @app.get("/v1/projects", dependencies=[auth])
    def list_projects(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> dict[str, object]:
        return projects.list(limit, offset)

    @app.get("/v1/projects/{project_id}", dependencies=[auth])
    def get_project(project_id: str) -> dict[str, object]:
        return _not_found(lambda: projects.get(project_id))

    @app.patch("/v1/projects/{project_id}", dependencies=[auth])
    def update_project(project_id: str, payload: ProjectUpdateRequest) -> dict[str, object]:
        return _not_found(lambda: projects.update(project_id, payload))

    @app.get("/v1/projects/{project_id}/scans", dependencies=[auth])
    def project_scans(
        project_id: str, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)
    ) -> dict[str, object]:
        return _not_found(lambda: projects.scans(project_id, limit, offset))

    @app.post("/v1/projects/{project_id}/scans", response_model=ScanResponse, status_code=202, dependencies=[auth])
    def scan_project(
        project_id: str,
        payload: ProjectScanRequest,
        response: Response,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ScanResponse:
        project = _not_found(lambda: projects.get(project_id))
        request = ScanCreateRequest(
            repository_url=str(project["repository_url"]),
            project_id=project_id,
            mode=payload.mode,
            source_disclosure_confirmed=payload.source_disclosure_confirmed,
        )
        return submit_scan(request, response, idempotency_key)

    @app.get("/v1/projects/{project_id}/vulnerabilities", dependencies=[auth])
    def project_vulnerabilities(
        project_id: str,
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        status: str | None = Query(None, max_length=32),
        severity: str | None = Query(None, max_length=32),
        category: str | None = Query(None, max_length=128),
        search: str | None = Query(None, max_length=256),
    ) -> dict[str, object]:
        return _not_found(
            lambda: projects.vulnerabilities(project_id, limit, offset, status, severity, category, search)
        )

    @app.patch("/v1/projects/{project_id}/vulnerabilities/{vulnerability_id}", dependencies=[auth])
    def update_vulnerability(
        project_id: str, vulnerability_id: str, payload: VulnerabilityUpdateRequest
    ) -> dict[str, object]:
        return _not_found(lambda: projects.set_status(project_id, vulnerability_id, payload.status.value))

    @app.get("/v1/projects/{project_id}/report", dependencies=[auth])
    def project_report(project_id: str, format: ReportFormat = Query(ReportFormat.JSON)) -> Response:
        project = _not_found(lambda: projects.get(project_id))
        vulnerabilities = projects.vulnerabilities(project_id, limit=1_000_000)["items"]
        if format is ReportFormat.JSON:
            return Response(
                json.dumps({"project": project, "vulnerabilities": vulnerabilities}, ensure_ascii=False),
                media_type="application/json",
            )
        scan_list = projects.scans(project_id, 1, 0)["items"]
        if not scan_list:
            raise HTTPException(409, "project has no scan yet")
        findings = [
            FindingResponse.model_validate(
                {
                    **{k: value for k, value in v.items() if k not in {"project_id", "status", "updated_at"}},
                    "scan_id": scan_list[0].id,
                    "metadata": {**v["metadata"], "manual_status": v["status"]},
                }
            )
            for v in vulnerabilities
        ]
        content, media_type = render_project_report(project, ScanReport(scan=scan_list[0], findings=findings), format)
        return Response(content, media_type=media_type)

    frontend_dir = os.getenv("ARGUS_FRONTEND_DIR")
    dist_path = (
        Path(frontend_dir).resolve() if frontend_dir else Path(__file__).resolve().parents[2] / "frontend" / "dist"
    )
    if (dist_path / "index.html").is_file():
        assets_dir = dist_path / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/shield.svg", include_in_schema=False)
        def shield_svg() -> Response:
            shield_file = dist_path / "shield.svg"
            if shield_file.is_file():
                return FileResponse(shield_file)
            raise HTTPException(status_code=404)

        @app.get("/", include_in_schema=False)
        def index() -> Response:
            return FileResponse(dist_path / "index.html")
    else:

        @app.get("/", include_in_schema=False)
        def index() -> HTMLResponse:
            return HTMLResponse(_INDEX_HTML)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> Response:
        try:
            if not os.getenv("ARGUS_API_KEY"):
                raise RuntimeError("ARGUS_API_KEY is not configured")
            argus_llm = all(os.getenv(name) for name in ("ARGUS_LLM_BASE_URL", "ARGUS_LLM_API_KEY", "ARGUS_LLM_MODEL"))
            ocr_llm = all(os.getenv(name) for name in ("OCR_LLM_URL", "OCR_LLM_TOKEN", "OCR_LLM_MODEL"))
            if not argus_llm and not ocr_llm:
                raise RuntimeError("LLM endpoint is not configured")
            store.ready()
            executable = os.getenv("OCR_BINARY", "ocr")
            if Path(executable).is_absolute():
                if not Path(executable).is_file() or not os.access(executable, os.X_OK):
                    raise RuntimeError("OCR_BINARY is not executable")
            elif shutil.which(executable) is None:
                raise RuntimeError("OCR_BINARY is not on PATH")
        except Exception as exc:
            return JSONResponse(status_code=503, content={"status": "not_ready", "detail": str(exc)})
        return JSONResponse(content={"status": "ready"})

    @app.post(
        "/v1/scans",
        response_model=ScanResponse,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[auth],
    )
    def create_scan(
        payload: ScanCreateRequest,
        response: Response,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ScanResponse:
        raise HTTPException(410, "create a project and use /v1/projects/{id}/scans")

    def submit_scan(payload: ScanCreateRequest, response: Response, idempotency_key: str | None) -> ScanResponse:
        if not payload.source_disclosure_confirmed:
            raise HTTPException(
                status_code=400,
                detail="source_disclosure_confirmed must be true before source is sent to the configured LLM",
            )
        try:
            scan, created = store.create_scan(payload, idempotency_key)
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except QueueFull as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except ScanStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not created:
            response.status_code = status.HTTP_200_OK
        return scan

    @app.get(
        "/v1/scans",
        response_model=ScanListResponse,
        dependencies=[auth],
    )
    def list_scans(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> ScanListResponse:
        scans, total = store.list_scans(limit=limit, offset=offset)
        return ScanListResponse(items=scans, total=total)

    @app.get("/v1/scans/{scan_id}", response_model=ScanResponse, dependencies=[auth])
    def get_scan(scan_id: str) -> ScanResponse:
        return _not_found(lambda: store.get_scan(scan_id))

    @app.get(
        "/v1/scans/{scan_id}/events",
        response_model=ScanEventsResponse,
        dependencies=[auth],
    )
    def get_events(
        scan_id: str,
        after: int = Query(default=0),
        limit: int = Query(default=100),
    ) -> ScanEventsResponse:
        if after < 0 or limit < 1 or limit > 500:
            raise HTTPException(
                status_code=400, detail="after must be non-negative and limit must be between 1 and 500"
            )
        try:
            return ScanEventsResponse.model_validate(store.list_events(scan_id, after=after, limit=limit))
        except ScanNotFound as exc:
            raise HTTPException(status_code=404, detail="scan not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(
        "/v1/scans/{scan_id}/diagnostics",
        response_model=ScanDiagnosticsResponse,
        dependencies=[auth],
    )
    def get_diagnostics(scan_id: str) -> ScanDiagnosticsResponse:
        return _not_found(lambda: store.get_diagnostics(scan_id))

    @app.get("/v1/scans/{scan_id}/diagnostics/export", dependencies=[auth])
    @app.get("/v1/scans/{scan_id}/export", dependencies=[auth])
    def export_diagnostics(scan_id: str) -> Response:
        try:
            document = store.export_diagnostics(scan_id)
        except ScanNotFound as exc:
            raise HTTPException(status_code=404, detail="scan not found") from exc
        content = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "", scan_id)[:64] or "scan"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="argus-{safe_id}-diagnostics.json"'},
        )

    @app.get(
        "/v1/scans/{scan_id}/findings",
        response_model=dict,
        dependencies=[auth],
    )
    def get_findings(
        scan_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        severity: str | None = Query(default=None, max_length=32),
        category: str | None = Query(default=None, max_length=128),
    ) -> dict[str, object]:
        try:
            findings, total = store.list_findings(
                scan_id,
                limit=limit,
                offset=offset,
                severity=severity,
                category=category,
            )
        except ScanNotFound as exc:
            raise HTTPException(status_code=404, detail="scan not found") from exc
        return {"items": findings, "total": total}

    @app.get("/v1/scans/{scan_id}/report", dependencies=[auth])
    def get_report(
        scan_id: str,
        format: ReportFormat = Query(default=ReportFormat.JSON),
    ) -> Response:
        return _render_report(store, scan_id, format)

    @app.get("/v1/scans/{scan_id}/report/{format}", dependencies=[auth])
    def get_report_by_path(scan_id: str, format: ReportFormat) -> Response:
        return _render_report(store, scan_id, format)

    @app.post("/v1/scans/{scan_id}/cancel", response_model=ScanResponse, dependencies=[auth])
    def cancel_scan(scan_id: str) -> ScanResponse:
        try:
            return store.cancel(scan_id)
        except ScanNotFound as exc:
            raise HTTPException(status_code=404, detail="scan not found") from exc

    @app.post("/v1/scans/{scan_id}/retry", response_model=ScanResponse, dependencies=[auth])
    def retry_scan(scan_id: str) -> ScanResponse:
        try:
            return store.retry(scan_id)
        except ScanNotFound as exc:
            raise HTTPException(status_code=404, detail="scan not found") from exc
        except ScanStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    return app


def _not_found(call: Callable[[], T]) -> T:
    try:
        return call()
    except ScanNotFound as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc


def _render_report(store: ScanStore, scan_id: str, report_format: ReportFormat) -> Response:
    try:
        scan = store.get_scan(scan_id)
        findings, total = store.list_findings(scan_id, limit=100_000)
    except ScanNotFound as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc
    if total > len(findings):
        scan = scan.model_copy(
            update={
                "metadata": {
                    **scan.metadata,
                    "report_truncated": True,
                    "report_finding_total": total,
                }
            }
        )
    content, media_type = render_report(ScanReport(scan=scan, findings=findings), report_format)
    return Response(content=content, media_type=media_type)


_INDEX_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>Argus</title><main><h1>Argus</h1><p>前端尚未构建。请构建前端或使用完整 Docker 镜像。</p></main></html>"""


def _positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
