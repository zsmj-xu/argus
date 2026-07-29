"""Create a V2 scan, immutable snapshot, plan, and initial Artifact."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import JsonValue, TypeAdapter

from argus.artifacts.schemas import ArtifactPublication
from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactPublisher
from argus.control.db import Database, control_db_path, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.config import validate_config
from argus.domain.enums import ScanEngine, ScanStatus, TaskStatus
from argus.domain.errors import ConflictError, SchemaValidationError
from argus.domain.hashing import sha256_digest
from argus.domain.models import Project, Scan, Task
from argus.execution.local import LocalPlanExecutor, build_execution_registry
from argus.graph.build import codegraph_provider_version
from argus.planning.persistence import TaskPlanPersistence
from argus.planning.planner import PlanningRequest, TaskOrdering, TaskPlanner
from argus.plugins.legacy_adapter import (
    SOURCE_CAPABILITY,
    legacy_analyzer_order,
    legacy_selected_plugin_ids,
)
from argus.snapshots.service import SnapshotService, git_identity
from argus.security.redaction import safe_error_summary

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])


def _json_config(
    config: dict[str, Any],
    *,
    workspace: str,
) -> dict[str, JsonValue]:
    try:
        enriched = validate_config(config)
    except ValueError as exc:
        raise SchemaValidationError(str(exc)) from exc
    execution = enriched.get("execution")
    execution_config = dict(execution) if isinstance(execution, dict) else {}
    execution_config["workspace"] = workspace
    enriched["execution"] = execution_config
    try:
        return _JSON_OBJECT.validate_python(enriched)
    except ValueError as exc:
        raise SchemaValidationError(f"V2 scan config is not JSON-compatible: {exc}") from exc


def _source_ignore(config: dict[str, JsonValue]) -> list[str]:
    source = config.get("source")
    if source is None:
        return []
    if not isinstance(source, dict):
        raise SchemaValidationError("source config must be an object")
    ignore = source.get("ignore", [])
    if not isinstance(ignore, list) or any(not isinstance(item, str) for item in ignore):
        raise SchemaValidationError("source.ignore must be a list of strings")
    return [item for item in ignore if isinstance(item, str)]


def _project(
    repositories: Repositories,
    *,
    repository_path: str,
    workspace: str,
    config: dict[str, JsonValue],
) -> Project:
    existing = repositories.projects.find_by_repository_path(repository_path)
    if existing is not None:
        return existing
    project = Project(
        name=workspace,
        repository_path=repository_path,
        default_config=config,
    )
    try:
        return repositories.projects.create(project)
    except ConflictError:
        return repositories.projects.create(
            project.model_copy(
                update={
                    "id": uuid4(),
                    "name": f"{workspace}-{project.id.hex[:8]}",
                }
            )
        )


def create_v2_scan(
    *,
    repository_path: str,
    workspace: str,
    config: dict[str, Any],
    runs_root: str | Path = "runs",
) -> Scan:
    original_repository = str(Path(repository_path).resolve())
    json_config = _json_config(config, workspace=workspace)
    database_path = control_db_path(runs_root)
    upgrade_database(database_path)
    database = Database(database_path)
    repositories = Repositories(database)
    services = ControlServices(repositories)
    events = EventService(repositories.events)
    scan: Scan | None = None
    snapshot_task: Task | None = None
    try:
        project = _project(
            repositories,
            repository_path=original_repository,
            workspace=workspace,
            config=json_config,
        )
        snapshot_id = uuid4()
        manifest_artifact_id = uuid4()
        config_hash = sha256_digest(json_config)
        scan = repositories.scans.create(
            Scan(
                project_id=project.id,
                snapshot_id=snapshot_id,
                config=json_config,
                config_hash=config_hash,
                engine=ScanEngine.V2,
            )
        )
        events.append(
            "scan.created",
            project_id=project.id,
            scan_id=scan.id,
            payload={"engine": ScanEngine.V2.value, "workspace": workspace},
        )
        scan = services.scans.transition(scan.id, ScanStatus.SNAPSHOTTING)
        snapshot_task = repositories.tasks.create(
            Task(
                scan_id=scan.id,
                plugin_id="source.snapshot",
                plugin_version="1.0.0",
                kind="snapshot",
                expected_capabilities=[SOURCE_CAPABILITY],
                config_hash=config_hash,
                cache_key=sha256_digest({"scan_id": str(scan.id), "snapshot_id": str(snapshot_id)}),
            )
        )
        snapshot_task = services.tasks.transition(
            snapshot_task.id,
            TaskStatus.READY,
        )
        snapshot_task = services.tasks.transition(
            snapshot_task.id,
            TaskStatus.RUNNING,
        )
        result = SnapshotService(runs_root).create(
            project_id=project.id,
            repository_path=original_repository,
            snapshot_id=snapshot_id,
            manifest_artifact_id=manifest_artifact_id,
            ignore=_source_ignore(json_config),
            vcs_identity=git_identity(original_repository),
        )
        repositories.snapshots.create(result.snapshot)
        ArtifactPublisher(
            ArtifactStore(runs_root),
            repositories.artifacts,
        ).publish_json(
            result.manifest,
            ArtifactPublication(
                scan_id=scan.id,
                snapshot_id=snapshot_id,
                task_id=snapshot_task.id,
                artifact_type="source.snapshot.manifest.v1",
                schema_version="1.0",
                capabilities=[SOURCE_CAPABILITY],
                producer_plugin_id="source.snapshot",
                producer_plugin_version="1.0.0",
                media_type="application/json",
                artifact_id=manifest_artifact_id,
                metadata={"tree_hash": result.snapshot.tree_hash},
            ),
        )
        services.tasks.transition(snapshot_task.id, TaskStatus.SUCCEEDED)
        scan = services.scans.transition(scan.id, ScanStatus.PLANNING)

        registry = build_execution_registry()
        analyzer_ids = {
            plugin.spec.id.removeprefix("legacy.analyzer."): plugin.spec.id
            for plugin in registry.all()
            if plugin.spec.id.startswith("legacy.analyzer.")
        }
        selected = legacy_selected_plugin_ids(json_config, analyzer_ids)
        graph_config: dict[str, JsonValue] = {}
        configured_graph = json_config.get("codegraph")
        if isinstance(configured_graph, dict):
            graph_config.update(configured_graph)
        graph_config["provider_binary_identity"] = codegraph_provider_version()
        plugin_config = {plugin_id: json_config for plugin_id in selected}
        plugin_config["graph.codegraph"] = graph_config
        plan = TaskPlanner(registry).compile(
            PlanningRequest(
                scan_id=scan.id,
                selected_plugin_ids=selected,
                initial_capabilities={SOURCE_CAPABILITY},
                plugin_config=plugin_config,
                ordering_constraints=[
                    TaskOrdering(
                        before_plugin_id=before,
                        after_plugin_id=after,
                    )
                    for before, after in legacy_analyzer_order(
                        json_config,
                        analyzer_ids,
                    )
                ],
            )
        )
        TaskPlanPersistence(
            repositories,
            runs_root=runs_root,
        ).persist(plan, snapshot_id=snapshot_id)
        LocalPlanExecutor(
            repositories,
            runs_root=runs_root,
            registry=registry,
        ).prepare(plan)
        return repositories.scans.get(scan.id)
    except Exception as exc:
        if snapshot_task is not None:
            current_task = repositories.tasks.get(snapshot_task.id)
            if current_task.status is TaskStatus.RUNNING:
                services.tasks.transition(
                    current_task.id,
                    TaskStatus.FAILED,
                    error_code=type(exc).__name__,
                    error_message=safe_error_summary(exc),
                )
        if scan is not None:
            current_scan = repositories.scans.get(scan.id)
            if current_scan.status not in {
                ScanStatus.COMPLETED,
                ScanStatus.FAILED,
                ScanStatus.CANCELED,
            }:
                services.scans.transition(
                    current_scan.id,
                    ScanStatus.FAILED,
                    error_code=type(exc).__name__,
                    error_message=safe_error_summary(exc),
                )
        raise
    finally:
        database.close()
