"""Repository/branch projects and manually managed, deduplicated findings."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .models import FindingCreate, ProjectCreateRequest, ProjectUpdateRequest, ServiceScanResult

if TYPE_CHECKING:
    from .store import ScanStore


def initialize_projects(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, repository_url TEXT NOT NULL,
        branch TEXT NOT NULL, repository_key TEXT NOT NULL, include_json TEXT NOT NULL, exclude_json TEXT NOT NULL,
        background TEXT, baseline_commit TEXT, baseline_scan_id TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(repository_key, branch))""")
    columns = {row[1] for row in db.execute("PRAGMA table_info(projects)")}
    if "repository_key" not in columns:
        db.execute("ALTER TABLE projects ADD COLUMN repository_key TEXT")
        db.execute("UPDATE projects SET repository_key = repository_url")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_project_identity ON projects(repository_key, branch)")
    db.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
        fingerprint TEXT NOT NULL, finding_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(project_id, fingerprint))""")


def project_from_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["include"] = json.loads(data.pop("include_json"))
    data["exclude"] = json.loads(data.pop("exclude_json"))
    return data


def fingerprint(finding: FindingCreate) -> str:
    content = " ".join((finding.evidence or finding.message).split())
    identity = [finding.file, finding.category.lower().strip(), content]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()


def reconcile_project(db: sqlite3.Connection, row: sqlite3.Row, result: ServiceScanResult, now: str) -> None:
    project_id = row["project_id"]
    if not project_id:
        return
    for finding in result.findings:
        db.execute(
            """INSERT INTO vulnerabilities
            (id, project_id, fingerprint, finding_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, fingerprint) DO UPDATE SET
                finding_json = excluded.finding_json, updated_at = excluded.updated_at""",
            (uuid4().hex, project_id, fingerprint(finding), finding.model_dump_json(), now, now),
        )
    if result.status.value == "completed" and not result.failed_files and not result.skipped_files:
        # Configuration edits made during a run invalidate that run as a new baseline.
        db.execute(
            """UPDATE projects SET baseline_commit = ?, baseline_scan_id = ?, updated_at = ?
            WHERE id = ? AND include_json = ? AND exclude_json = ? AND background IS ?""",
            (
                result.commit_sha or row["commit_sha"],
                row["id"],
                now,
                project_id,
                row["include_json"],
                row["exclude_json"],
                row["background"],
            ),
        )


class ProjectService:
    def __init__(self, store: ScanStore) -> None:
        self.store = store

    def get(self, project_id: str) -> dict[str, Any]:
        from .store import ScanNotFound

        with self.store._db() as db:
            row = db.execute(
                """SELECT p.*, (SELECT id FROM scans WHERE project_id = p.id
                AND status IN ('queued', 'running') LIMIT 1) AS active_scan_id
                FROM projects p WHERE id = ?""",
                (project_id,),
            ).fetchone()
        if row is None:
            raise ScanNotFound(project_id)
        return project_from_row(row)

    def list(self, limit: int, offset: int) -> dict[str, Any]:
        with self.store._db() as db:
            rows = db.execute(
                """SELECT p.*, (SELECT COUNT(*) FROM vulnerabilities v
                WHERE v.project_id = p.id) AS vulnerability_count FROM projects p
                ORDER BY created_at DESC, id LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
            total = db.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        return {"items": [project_from_row(row) for row in rows], "total": total}

    def create(self, request: ProjectCreateRequest) -> dict[str, Any]:
        project_id = uuid4().hex
        now = datetime.now(UTC).isoformat()
        # Normalize the common HTTPS clone suffix without folding case-sensitive paths.
        url = request.repository_url.rstrip("/")
        key = url.removesuffix(".git")
        with self.store._db() as db:
            db.execute(
                """INSERT INTO projects
                (id, name, repository_url, branch, repository_key, include_json, exclude_json, background, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    project_id,
                    request.name.strip(),
                    url,
                    request.branch,
                    key,
                    json.dumps(request.include, ensure_ascii=False),
                    json.dumps(request.exclude, ensure_ascii=False),
                    request.background,
                    now,
                    now,
                ),
            )
        return self.get(project_id)

    def update(self, project_id: str, request: ProjectUpdateRequest) -> dict[str, Any]:
        self.get(project_id)
        now = datetime.now(UTC).isoformat()
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                previous = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
                assert previous is not None
                include = json.dumps(request.include, ensure_ascii=False)
                exclude = json.dumps(request.exclude, ensure_ascii=False)
                changed = (include, exclude, request.background) != (
                    previous["include_json"],
                    previous["exclude_json"],
                    previous["background"],
                )
                db.execute(
                    """UPDATE projects SET name = ?, include_json = ?, exclude_json = ?, background = ?,
                    baseline_commit = CASE WHEN ? THEN NULL ELSE baseline_commit END,
                    baseline_scan_id = CASE WHEN ? THEN NULL ELSE baseline_scan_id END, updated_at = ? WHERE id = ?""",
                    (request.name.strip(), include, exclude, request.background, changed, changed, now, project_id),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
        return self.get(project_id)

    def scans(self, project_id: str, limit: int, offset: int) -> dict[str, Any]:
        self.get(project_id)
        with self.store._db() as db:
            rows = db.execute(
                "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
                (project_id, limit, offset),
            ).fetchall()
            total = db.execute("SELECT COUNT(*) FROM scans WHERE project_id = ?", (project_id,)).fetchone()[0]
        return {"items": [self.store._scan_from_row(row) for row in rows], "total": total}

    def vulnerabilities(
        self,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        search: str | None = None,
    ) -> dict[str, Any]:
        self.get(project_id)
        where = ["project_id = ?"]
        params: list[Any] = [project_id]
        for value, field in ((status, "status"), (severity, "severity"), (category, "category")):
            if value:
                where.append("status = ?" if field == "status" else f"json_extract(finding_json, '$.{field}') = ?")
                params.append(value)
        if search:
            where.append(
                "(json_extract(finding_json, '$.title') LIKE ? OR json_extract(finding_json, '$.file') LIKE ?)"
            )
            params.extend([f"%{search}%"] * 2)
        clause = " AND ".join(where)
        with self.store._db() as db:
            rows = db.execute(
                f"SELECT * FROM vulnerabilities WHERE {clause} ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            total = db.execute(f"SELECT COUNT(*) FROM vulnerabilities WHERE {clause}", params).fetchone()[0]
        return {"items": [self._vulnerability(row) for row in rows], "total": total}

    @staticmethod
    def _vulnerability(row: sqlite3.Row) -> dict[str, Any]:
        return {
            **json.loads(row["finding_json"]),
            **{key: row[key] for key in ("id", "project_id", "status", "created_at", "updated_at")},
        }

    def set_status(self, project_id: str, vulnerability_id: str, status: str) -> dict[str, Any]:
        from .store import ScanNotFound

        with self.store._db() as db:
            cursor = db.execute(
                "UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                (status, datetime.now(UTC).isoformat(), vulnerability_id, project_id),
            )
            if cursor.rowcount != 1:
                raise ScanNotFound(vulnerability_id)
            row = db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vulnerability_id,)).fetchone()
        assert row is not None
        return self._vulnerability(row)
