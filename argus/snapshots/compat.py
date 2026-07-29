"""M2 compatibility bridge that runs the legacy Pipeline on a SourceSnapshot."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, JsonValue, TypeAdapter

from argus.artifacts.schemas import ArtifactPublication
from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactPublisher
from argus.control.db import Database, control_db_path, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import ScanEngine, ScanStatus, TaskStatus
from argus.domain.errors import ConflictError, SchemaValidationError
from argus.domain.hashing import canonical_json_bytes, sha256_digest
from argus.domain.models import Project, Scan, Task
from argus.graph.build import CODEGRAPH_PROVIDER_ID, codegraph_provider_version
from argus.snapshots.service import SnapshotService, git_identity

_JSON_ADAPTER: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
_LEGACY_VERSION = "1.0.0"
_LINK_FILENAME = "control-link.json"


class LegacyControlLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: UUID
    scan_id: UUID
    snapshot_id: UUID
    original_repository_path: str
    materialized_path: str | None = None
    tree_hash: str | None = None
    graph_cache_key: str | None = None
    graph_provider_version: str | None = None
    snapshot_task_id: UUID
    graph_task_id: UUID
    enrichment_task_id: UUID
    findings_task_id: UUID
    report_task_id: UUID
    manifest_artifact_id: UUID
    graph_artifact_id: UUID | None = None
    enrichment_artifact_id: UUID | None = None
    findings_artifact_id: UUID | None = None
    report_artifact_id: UUID | None = None


def _link_path(workspace: str, runs_root: str | Path) -> Path:
    return Path(runs_root).resolve() / workspace / _LINK_FILENAME


def _write_link(link: LegacyControlLink, workspace: str, runs_root: str | Path) -> None:
    path = _link_path(workspace, runs_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".control-link.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(link))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_legacy_link(workspace: str, runs_root: str | Path = "runs") -> LegacyControlLink | None:
    path = _link_path(workspace, runs_root)
    try:
        return LegacyControlLink.model_validate_json(path.read_bytes())
    except FileNotFoundError:
        return None


def _json_config(config: dict[str, Any]) -> dict[str, JsonValue]:
    try:
        value = _JSON_ADAPTER.validate_python(config)
    except ValueError as exc:
        raise SchemaValidationError(f"legacy scan config is not JSON-compatible: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaValidationError("legacy scan config must be a JSON object")
    return value


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


def _project_for_repository(
    repositories: Repositories,
    events: EventService,
    *,
    repository_path: str,
    workspace: str,
    default_config: dict[str, JsonValue],
) -> Project:
    existing = repositories.projects.find_by_repository_path(repository_path)
    if existing is not None:
        return existing
    project = Project(
        name=workspace,
        repository_path=repository_path,
        default_config=default_config,
    )
    try:
        created = repositories.projects.create(project)
    except ConflictError:
        concurrent = repositories.projects.find_by_repository_path(repository_path)
        created = concurrent or repositories.projects.create(
            project.model_copy(update={"id": uuid4(), "name": f"{workspace}-{project.id.hex[:8]}"})
        )
    events.append("project.created", project_id=created.id, payload={"name": created.name})
    return created


def _task(
    *,
    task_id: UUID,
    scan_id: UUID,
    plugin_id: str,
    kind: str,
    required_capabilities: list[str],
    expected_capability: str,
    depends_on: list[UUID],
    config_hash: str,
    cache_key: str,
    plugin_version: str = _LEGACY_VERSION,
) -> Task:
    return Task(
        id=task_id,
        scan_id=scan_id,
        plugin_id=plugin_id,
        plugin_version=plugin_version,
        kind=kind,
        depends_on=depends_on,
        required_capabilities=required_capabilities,
        expected_capabilities=[expected_capability],
        config_hash=config_hash,
        cache_key=cache_key,
    )


def _advance_task_to_succeeded(repositories: Repositories, task_id: UUID) -> Task:
    services = ControlServices(repositories)
    task = repositories.tasks.get(task_id)
    if task.status is TaskStatus.PENDING:
        task = services.tasks.transition(task.id, TaskStatus.READY)
    if task.status is TaskStatus.READY:
        task = services.tasks.transition(task.id, TaskStatus.RUNNING)
    if task.status in {TaskStatus.RUNNING, TaskStatus.WAITING_REVIEW}:
        task = services.tasks.transition(task.id, TaskStatus.SUCCEEDED)
    return task


def _publication(
    link: LegacyControlLink,
    *,
    task_id: UUID,
    artifact_type: str,
    capability: str,
    producer_plugin_id: str,
    media_type: str,
    metadata: dict[str, JsonValue] | None = None,
    artifact_id: UUID | None = None,
    producer_plugin_version: str = _LEGACY_VERSION,
) -> ArtifactPublication:
    return ArtifactPublication(
        scan_id=link.scan_id,
        snapshot_id=link.snapshot_id,
        task_id=task_id,
        artifact_type=artifact_type,
        schema_version="1.0",
        capabilities=[capability],
        producer_plugin_id=producer_plugin_id,
        producer_plugin_version=producer_plugin_version,
        media_type=media_type,
        metadata=metadata or {},
        artifact_id=artifact_id,
    )


def _graph_cache_key(
    *,
    tree_hash: str,
    provider_version: str,
    provider_config_hash: str,
) -> str:
    return sha256_digest(
        {
            "tree_hash": tree_hash,
            "provider_id": CODEGRAPH_PROVIDER_ID,
            "provider_version": provider_version,
            "provider_config_hash": provider_config_hash,
        }
    )


def prepare_legacy_scan(
    *,
    repository_path: str,
    workspace: str,
    config: dict[str, Any],
    runs_root: str | Path = "runs",
) -> LegacyControlLink:
    """Create V2 records and an immutable snapshot before invoking V1."""
    original_repository = str(Path(repository_path).resolve())
    source_vcs_identity = git_identity(original_repository)
    json_config = _json_config(config)
    database_path = control_db_path(runs_root)
    upgrade_database(database_path)
    database = Database(database_path)
    repositories = Repositories(database)
    services = ControlServices(repositories)
    events = EventService(repositories.events)
    scan: Scan | None = None
    try:
        project = _project_for_repository(
            repositories,
            events,
            repository_path=original_repository,
            workspace=workspace,
            default_config=json_config,
        )
        config_hash = sha256_digest(json_config)
        snapshot_id = uuid4()
        task_ids = [uuid4() for _ in range(5)]
        manifest_artifact_id = uuid4()
        scan = repositories.scans.create(
            Scan(
                project_id=project.id,
                snapshot_id=snapshot_id,
                config=json_config,
                config_hash=config_hash,
                engine=ScanEngine.LEGACY,
            )
        )
        events.append(
            "scan.created",
            project_id=project.id,
            scan_id=scan.id,
            payload={"engine": ScanEngine.LEGACY.value, "workspace": workspace},
        )
        link = LegacyControlLink(
            project_id=project.id,
            scan_id=scan.id,
            snapshot_id=snapshot_id,
            original_repository_path=original_repository,
            snapshot_task_id=task_ids[0],
            graph_task_id=task_ids[1],
            enrichment_task_id=task_ids[2],
            findings_task_id=task_ids[3],
            report_task_id=task_ids[4],
            manifest_artifact_id=manifest_artifact_id,
        )
        _write_link(link, workspace, runs_root)
        scan = services.scans.transition(scan.id, ScanStatus.SNAPSHOTTING)
        snapshot_task = repositories.tasks.create(
            _task(
                task_id=link.snapshot_task_id,
                scan_id=scan.id,
                plugin_id="source.snapshot",
                kind="snapshot",
                required_capabilities=[],
                expected_capability="source.snapshot.v1",
                depends_on=[],
                config_hash=config_hash,
                cache_key=sha256_digest({"scan_id": str(scan.id), "snapshot_id": str(snapshot_id)}),
            )
        )
        services.tasks.transition(snapshot_task.id, TaskStatus.READY)
        services.tasks.transition(snapshot_task.id, TaskStatus.RUNNING)

        snapshot_result = SnapshotService(runs_root).create(
            project_id=project.id,
            repository_path=original_repository,
            snapshot_id=snapshot_id,
            manifest_artifact_id=manifest_artifact_id,
            ignore=_source_ignore(json_config),
            vcs_identity=source_vcs_identity,
        )
        repositories.snapshots.create(snapshot_result.snapshot)
        link = link.model_copy(
            update={
                "materialized_path": snapshot_result.snapshot.materialized_path,
                "tree_hash": snapshot_result.snapshot.tree_hash,
            }
        )
        publisher = ArtifactPublisher(ArtifactStore(runs_root), repositories.artifacts)
        publisher.publish_json(
            snapshot_result.manifest,
            _publication(
                link,
                task_id=link.snapshot_task_id,
                artifact_type="source.snapshot.manifest.v1",
                capability="source.snapshot.v1",
                producer_plugin_id="source.snapshot",
                media_type="application/json",
                artifact_id=manifest_artifact_id,
            ),
        )
        services.tasks.transition(snapshot_task.id, TaskStatus.SUCCEEDED)
        events.append(
            "snapshot.completed",
            project_id=project.id,
            scan_id=scan.id,
            task_id=snapshot_task.id,
            payload={
                "snapshot_id": str(snapshot_id),
                "tree_hash": snapshot_result.snapshot.tree_hash,
            },
        )

        scan = services.scans.transition(scan.id, ScanStatus.PLANNING)
        provider_version = codegraph_provider_version()
        provider_config = json_config.get("codegraph", {})
        provider_config_hash = sha256_digest(_JSON_ADAPTER.validate_python(provider_config))
        graph_cache_key = _graph_cache_key(
            tree_hash=snapshot_result.snapshot.tree_hash,
            provider_version=provider_version,
            provider_config_hash=provider_config_hash,
        )
        link = link.model_copy(
            update={
                "graph_cache_key": graph_cache_key,
                "graph_provider_version": provider_version,
            }
        )
        tasks = (
            _task(
                task_id=link.graph_task_id,
                scan_id=scan.id,
                plugin_id=CODEGRAPH_PROVIDER_ID,
                kind="graph_provider",
                required_capabilities=["source.snapshot.v1"],
                expected_capability="code.graph.codegraph.v1",
                depends_on=[link.snapshot_task_id],
                config_hash=provider_config_hash,
                cache_key=graph_cache_key,
                plugin_version=provider_version,
            ),
            _task(
                task_id=link.enrichment_task_id,
                scan_id=scan.id,
                plugin_id="legacy.enrichment.aggregate",
                kind="legacy_adapter",
                required_capabilities=["code.graph.codegraph.v1"],
                expected_capability="legacy.enrichment.aggregate.v1",
                depends_on=[link.graph_task_id],
                config_hash=config_hash,
                cache_key=sha256_digest({"snapshot": snapshot_result.snapshot.tree_hash, "phase": "enrichment"}),
            ),
            _task(
                task_id=link.findings_task_id,
                scan_id=scan.id,
                plugin_id="legacy.findings.aggregate",
                kind="legacy_adapter",
                required_capabilities=[
                    "code.graph.codegraph.v1",
                    "legacy.enrichment.aggregate.v1",
                ],
                expected_capability="legacy.findings.aggregate.v1",
                depends_on=[link.graph_task_id, link.enrichment_task_id],
                config_hash=config_hash,
                cache_key=sha256_digest({"snapshot": snapshot_result.snapshot.tree_hash, "phase": "findings"}),
            ),
            _task(
                task_id=link.report_task_id,
                scan_id=scan.id,
                plugin_id="legacy.report.markdown",
                kind="reporter",
                required_capabilities=["legacy.findings.aggregate.v1"],
                expected_capability="legacy.report.markdown.v1",
                depends_on=[link.findings_task_id],
                config_hash=config_hash,
                cache_key=sha256_digest({"snapshot": snapshot_result.snapshot.tree_hash, "phase": "report"}),
            ),
        )
        for task in tasks:
            repositories.tasks.create(task)

        cached_graph = repositories.artifacts.find_latest_by_metadata(
            artifact_type="code.graph.codegraph.v1",
            metadata_key="graph_cache_key",
            metadata_value=graph_cache_key,
        )
        if cached_graph is not None:
            graph_path = Path(snapshot_result.snapshot.materialized_path) / ".codegraph" / "codegraph.db"
            ArtifactStore(runs_root).materialize(
                cached_graph.content_hash,
                graph_path,
                expected_size=cached_graph.size_bytes,
            )

        scan = services.scans.transition(scan.id, ScanStatus.READY)
        services.scans.transition(scan.id, ScanStatus.RUNNING)
        _write_link(link, workspace, runs_root)
        return link
    except Exception:
        if scan is not None:
            events.append(
                "scan.failed",
                project_id=scan.project_id,
                scan_id=scan.id,
                payload={"stage": "snapshot_preparation"},
            )
            current = repositories.scans.get(scan.id)
            if current.status not in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED}:
                services.scans.transition(
                    scan.id,
                    ScanStatus.FAILED,
                    error_code="snapshot_preparation_failed",
                    error_message="Legacy scan preparation failed",
                )
        raise
    finally:
        database.close()


def _load_json_artifact(path: Path) -> JsonValue:
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
        return _JSON_ADAPTER.validate_python(raw)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SchemaValidationError(f"legacy JSON artifact is invalid: {path}: {exc}") from exc


def sync_legacy_artifacts(
    *,
    workspace: str,
    runs_root: str | Path = "runs",
) -> LegacyControlLink | None:
    """Register every V1 artifact currently present, without duplicating metadata."""
    link = load_legacy_link(workspace, runs_root)
    if link is None:
        return None
    if link.materialized_path is None or link.tree_hash is None or link.graph_cache_key is None:
        raise SchemaValidationError("legacy control link is incomplete")

    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    publisher = ArtifactPublisher(ArtifactStore(runs_root), repositories.artifacts)
    events = EventService(repositories.events)
    workspace_path = Path(runs_root).resolve() / workspace
    try:
        graph_path = Path(link.materialized_path) / ".codegraph" / "codegraph.db"
        if graph_path.is_file() and link.graph_artifact_id is None:
            _advance_task_to_succeeded(repositories, link.graph_task_id)
            graph = publisher.publish_file(
                graph_path,
                _publication(
                    link,
                    task_id=link.graph_task_id,
                    artifact_type="code.graph.codegraph.v1",
                    capability="code.graph.codegraph.v1",
                    producer_plugin_id=CODEGRAPH_PROVIDER_ID,
                    media_type="application/vnd.sqlite3",
                    metadata={
                        "graph_cache_key": link.graph_cache_key,
                        "tree_hash": link.tree_hash,
                        "provider_id": CODEGRAPH_PROVIDER_ID,
                        "provider_version": link.graph_provider_version or "unknown",
                    },
                    producer_plugin_version=link.graph_provider_version or "unknown",
                ),
            )
            link = link.model_copy(update={"graph_artifact_id": graph.id})
            _write_link(link, workspace, runs_root)

        artifact_specs = (
            (
                "enrichment_artifact_id",
                workspace_path / "enriched-graph.json",
                link.enrichment_task_id,
                "legacy.enrichment.aggregate.v1",
                "legacy.enrichment.aggregate",
            ),
            (
                "findings_artifact_id",
                workspace_path / "findings.json",
                link.findings_task_id,
                "legacy.findings.aggregate.v1",
                "legacy.findings.aggregate",
            ),
        )
        for field_name, path, task_id, artifact_type, producer in artifact_specs:
            if path.is_file() and getattr(link, field_name) is None:
                _advance_task_to_succeeded(repositories, task_id)
                artifact = publisher.publish_json(
                    _load_json_artifact(path),
                    _publication(
                        link,
                        task_id=task_id,
                        artifact_type=artifact_type,
                        capability=artifact_type,
                        producer_plugin_id=producer,
                        media_type="application/json",
                    ),
                )
                link = link.model_copy(update={field_name: artifact.id})
                _write_link(link, workspace, runs_root)

        report_path = workspace_path / "report.md"
        if report_path.is_file() and link.report_artifact_id is None:
            _advance_task_to_succeeded(repositories, link.report_task_id)
            artifact = publisher.publish_text(
                report_path.read_text(encoding="utf-8"),
                _publication(
                    link,
                    task_id=link.report_task_id,
                    artifact_type="legacy.report.markdown.v1",
                    capability="legacy.report.markdown.v1",
                    producer_plugin_id="legacy.report.markdown",
                    media_type="text/markdown",
                ),
            )
            link = link.model_copy(update={"report_artifact_id": artifact.id})
            _write_link(link, workspace, runs_root)

        events.append(
            "artifact.legacy_projection_synced",
            project_id=link.project_id,
            scan_id=link.scan_id,
            payload={"workspace": workspace},
        )
        return link
    finally:
        database.close()


def resume_legacy_scan_record(workspace: str, runs_root: str | Path = "runs") -> LegacyControlLink | None:
    link = load_legacy_link(workspace, runs_root)
    if link is None:
        return None
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.get(link.scan_id)
        if scan.status is ScanStatus.WAITING_REVIEW:
            ControlServices(repositories).scans.transition(scan.id, ScanStatus.RUNNING)
        return link
    finally:
        database.close()


def update_legacy_scan_config(
    workspace: str,
    config: dict[str, Any],
    runs_root: str | Path = "runs",
) -> None:
    """Persist review-time config changes and re-key tasks that have not run."""
    link = load_legacy_link(workspace, runs_root)
    if link is None:
        return
    json_config = _json_config(config)
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.get(link.scan_id)
        if scan.config == json_config:
            return
        graph_task = repositories.tasks.get(link.graph_task_id)
        if graph_task.status is TaskStatus.SUCCEEDED and (
            scan.config.get("codegraph", {}) != json_config.get("codegraph", {})
            or scan.config.get("source", {}) != json_config.get("source", {})
        ):
            raise SchemaValidationError("source/codegraph config cannot change after the snapshot graph has completed")
        config_hash = sha256_digest(json_config)
        repositories.scans.update(scan.model_copy(update={"config": json_config, "config_hash": config_hash}))
        if link.tree_hash is None:
            raise SchemaValidationError("legacy control link has no tree hash")
        pending_tasks = (
            (link.enrichment_task_id, "enrichment"),
            (link.findings_task_id, "findings"),
            (link.report_task_id, "report"),
        )
        for task_id, phase in pending_tasks:
            task = repositories.tasks.get(task_id)
            if task.status is TaskStatus.PENDING:
                repositories.tasks.update(
                    task.model_copy(
                        update={
                            "config_hash": config_hash,
                            "cache_key": sha256_digest(
                                {
                                    "snapshot": link.tree_hash,
                                    "phase": phase,
                                    "config_hash": config_hash,
                                }
                            ),
                        }
                    )
                )
    finally:
        database.close()


def record_legacy_interruption(
    workspace: str,
    error_type: str,
    runs_root: str | Path = "runs",
) -> None:
    """Record a recoverable V1 interruption without inventing M4 retry states."""
    link = load_legacy_link(workspace, runs_root)
    if link is None:
        return
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        EventService(repositories.events).append(
            "scan.legacy_interrupted",
            project_id=link.project_id,
            scan_id=link.scan_id,
            payload={"error_type": error_type},
        )
    finally:
        database.close()


def finish_legacy_scan_record(
    *,
    workspace: str,
    paused: bool,
    runs_root: str | Path = "runs",
) -> None:
    link = load_legacy_link(workspace, runs_root)
    if link is None:
        return
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    services = ControlServices(repositories)
    events = EventService(repositories.events)
    try:
        scan = repositories.scans.get(link.scan_id)
        if paused and scan.status is ScanStatus.RUNNING:
            services.scans.transition(scan.id, ScanStatus.WAITING_REVIEW)
            events.append(
                "review.requested",
                project_id=link.project_id,
                scan_id=link.scan_id,
                payload={"kind": "legacy_checkpoint"},
            )
        elif not paused and scan.status is ScanStatus.RUNNING:
            services.scans.transition(scan.id, ScanStatus.STATIC_COMPLETED)
            services.scans.transition(scan.id, ScanStatus.COMPLETED)
            events.append(
                "scan.completed",
                project_id=link.project_id,
                scan_id=link.scan_id,
                payload={"engine": ScanEngine.LEGACY.value},
            )
    finally:
        database.close()
