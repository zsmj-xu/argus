from __future__ import annotations

import json
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from argus.control.db import Database, make_engine, upgrade_database
from argus.control.orm import Base
from argus.control.repositories import Repositories

from .helpers import make_finding, make_project, make_scan, make_task

EXPECTED_TABLES = {
    "alembic_version",
    "artifacts",
    "events",
    "findings",
    "projects",
    "review_requests",
    "scans",
    "source_snapshots",
    "task_plans",
    "task_attempts",
    "tasks",
    "verification_approvals",
    "verification_attempts",
    "verification_environments",
    "verification_identities",
    "verification_plans",
    "verification_requirements",
    "verification_evidence",
}


def test_migration_creates_schema_from_empty_database(tmp_path: Path) -> None:
    path = tmp_path / "control.db"

    upgrade_database(path)
    engine = make_engine(path)
    try:
        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    finally:
        engine.dispose()


def test_migration_is_repeatable(tmp_path: Path) -> None:
    path = tmp_path / "control.db"

    upgrade_database(path)
    upgrade_database(path)
    engine = make_engine(path)
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()
        assert version == "0007_http_verification"
    finally:
        engine.dispose()


def test_migration_matches_orm_metadata(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path)
    engine = make_engine(path)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection)
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_m2_migration_preserves_existing_m1_records(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path, "0001_control_store")
    database = Database(path)
    repositories = Repositories(database)
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    database.close()

    upgrade_database(path)
    reopened = Database(path)
    repositories = Repositories(reopened)
    try:
        assert repositories.projects.get(project.id) == project
        assert repositories.scans.get(scan.id) == scan
        assert repositories.snapshots.list(project_id=project.id) == []
    finally:
        reopened.close()


def test_m3_migration_preserves_existing_m2_records(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path, "0002_source_snapshots")
    database = Database(path)
    repositories = Repositories(database)
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    database.close()

    upgrade_database(path)
    reopened = Database(path)
    repositories = Repositories(reopened)
    try:
        assert repositories.projects.get(project.id) == project
        assert repositories.scans.get(scan.id) == scan
    finally:
        reopened.close()


def test_m4_migration_preserves_m3_tasks_with_safe_policy_defaults(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path, "0003_task_plans")
    database = Database(path)
    repositories = Repositories(database)
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    task = make_task(scan)
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            INSERT INTO tasks (
                id, scan_id, plan_id, plugin_id, plugin_version, kind,
                depends_on, required_capabilities, expected_capabilities,
                config_hash, cache_key, status, created_at, started_at,
                finished_at, error_code, error_message, version
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
            """,
            (
                str(task.id),
                str(task.scan_id),
                task.plugin_id,
                task.plugin_version,
                task.kind,
                "[]",
                '["code.graph.codegraph.v1"]',
                '["legacy.findings.authz.v1"]',
                task.config_hash,
                task.cache_key,
                task.status.value,
                task.created_at.isoformat(),
                task.version,
            ),
        )
    database.close()

    upgrade_database(path)
    reopened = Database(path)
    repositories = Repositories(reopened)
    try:
        migrated = repositories.tasks.get(task.id)
        assert migrated.optional_capabilities == []
        assert migrated.continue_on_failure is False
        assert migrated.max_attempts == 1
    finally:
        reopened.close()


def test_m5_detection_migration_preserves_existing_findings(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path, "0004_local_executor")
    database = Database(path)
    repositories = Repositories(database)
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    finding = make_finding(scan)
    with database.engine.begin() as connection:
        connection.exec_driver_sql(
            """
            INSERT INTO findings (
                id, fingerprint, scan_id, snapshot_id, rule_id, rule_version,
                title, weakness_id, vuln_class, severity, static_confidence,
                status, locations, source_node_ids, sink_node_ids,
                graph_slice_artifact_id, evidence_artifact_ids, preconditions,
                rationale, remediation, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                str(finding.id),
                finding.fingerprint,
                str(finding.scan_id),
                str(finding.snapshot_id),
                finding.rule_id,
                finding.rule_version,
                finding.title,
                finding.weakness_id,
                finding.vuln_class,
                finding.severity.value,
                finding.static_confidence.value,
                finding.status.value,
                json.dumps([location.model_dump(mode="json") for location in finding.locations]),
                json.dumps(finding.source_node_ids),
                json.dumps(finding.sink_node_ids),
                json.dumps([]),
                json.dumps(finding.preconditions),
                finding.rationale,
                finding.remediation,
                finding.created_at.isoformat(),
                finding.updated_at.isoformat(),
            ),
        )
    database.close()

    upgrade_database(path)
    reopened = Database(path)
    repositories = Repositories(reopened)
    try:
        migrated = repositories.findings.get(finding.id)
        assert migrated.title == finding.title
        assert migrated.root_cause_key is None
    finally:
        reopened.close()


def test_opening_database_does_not_create_application_tables(tmp_path: Path) -> None:
    path = tmp_path / "control.db"
    database = Database(path)
    try:
        assert inspect(database.engine).get_table_names() == []
    finally:
        database.close()
