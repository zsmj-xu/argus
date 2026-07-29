from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from argus.artifacts.store import ArtifactStore
from argus.control.db import Database, control_db_path, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.control_plane.service import (
    ArtifactAccessDenied,
    ControlPlaneInputError,
    ControlPlaneService,
)
from argus.domain.enums import (
    AttemptStatus,
    PluginKind,
    ReviewStatus,
    ScanStatus,
    TaskStatus,
)
from argus.domain.models import Artifact, Project, Scan, Task, TaskAttempt, utc_now
from argus.planning.persistence import TaskPlanPersistence
from argus.planning.planner import PlanningRequest, TaskPlanner
from argus.plugins.contracts import CapabilityDeclaration, PluginSpec
from argus.plugins.registry import PluginOrigin, PluginRegistry
from argus.verification.models import ApprovalDecision

from tests.control.helpers import make_finding

SHA = "a" * 64


def _seed(
    tmp_path: Path,
) -> tuple[Project, Scan, Task, Artifact]:
    runs_root = tmp_path / "runs"
    upgrade_database(control_db_path(runs_root))
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    project = repositories.projects.create(
        Project(
            name="demo",
            repository_path=str(tmp_path),
            default_config={
                "checkpoints": True,
                "api_key": "must-never-leak",
            },
        )
    )
    scan = repositories.scans.create(
        Scan(
            project_id=project.id,
            snapshot_id=uuid4(),
            config={
                "analysisMode": "v2",
                "execution": {"workspace": "demo-scan"},
                "credentials": {"token": "must-never-leak"},
            },
            config_hash=SHA,
        )
    )
    task = repositories.tasks.create(
        Task(
            scan_id=scan.id,
            plugin_id="detector.authorization",
            plugin_version="1.0.0",
            kind="detector",
            expected_capabilities=["finding.static.authorization.v2"],
            config_hash=SHA,
            cache_key="b" * 64,
            max_attempts=2,
        )
    )
    blob = ArtifactStore(runs_root).put_json({"kind": "finding", "value": "safe preview"})
    artifact = repositories.artifacts.create(
        Artifact(
            scan_id=scan.id,
            snapshot_id=scan.snapshot_id,
            task_id=task.id,
            artifact_type="finding.static.v2",
            schema_version="2.0",
            capabilities=["finding.static.authorization.v2"],
            producer_plugin_id=task.plugin_id,
            producer_plugin_version=task.plugin_version,
            media_type="application/json",
            content_hash=blob.content_hash,
            size_bytes=blob.size_bytes,
            storage_uri=blob.storage_uri,
            metadata={"api_key": "must-never-leak", "fixture": True},
        )
    )
    graph_slice_blob = ArtifactStore(runs_root).put_json(
        {
            "seed_ids": ["sir:route:get-order"],
            "nodes": [],
            "edges": [],
            "truncated": False,
            "max_nodes": 60,
            "radius": 2,
        }
    )
    graph_slice_artifact = repositories.artifacts.create(
        Artifact(
            scan_id=scan.id,
            snapshot_id=scan.snapshot_id,
            task_id=task.id,
            artifact_type="graph.slice.v1",
            schema_version="1.0",
            capabilities=["graph.slice.authorization.v1"],
            producer_plugin_id=task.plugin_id,
            producer_plugin_version=task.plugin_version,
            media_type="application/json",
            content_hash=graph_slice_blob.content_hash,
            size_bytes=graph_slice_blob.size_bytes,
            storage_uri=graph_slice_blob.storage_uri,
        )
    )
    finding = make_finding(scan).model_copy(
        update={
            "graph_slice_artifact_id": graph_slice_artifact.id,
            "evidence_artifact_ids": [artifact.id],
        }
    )
    repositories.findings.upsert(finding)
    EventService(repositories.events).append(
        "fixture.created",
        project_id=project.id,
        scan_id=scan.id,
        payload={
            "authorization": "must-never-leak",
            "prompt": "full source prompt must not leak",
            "safe": "visible",
        },
    )
    database.close()
    return project, scan, task, artifact


def test_control_plane_survives_service_restart_and_redacts_secrets(
    tmp_path: Path,
) -> None:
    project, scan, task, _artifact = _seed(tmp_path)

    first = ControlPlaneService(tmp_path / "runs")
    second = ControlPlaneService(tmp_path / "runs")

    listed = first.list_projects()
    overview = second.get_scan(scan.id)
    tasks = second.tasks(scan.id)
    events = second.events(scan.id)

    assert listed[0]["id"] == str(project.id)
    assert listed[0]["default_config"]["api_key"] == "[REDACTED]"
    assert overview["id"] == str(scan.id)
    assert overview["config"]["credentials"] == "[REDACTED]"
    assert tasks[0]["id"] == str(task.id)
    assert events[0]["payload"]["authorization"] == "[REDACTED]"
    assert events[0]["payload"]["prompt"] == "[REDACTED]"
    assert events[0]["payload"]["safe"] == "visible"


def test_project_create_patch_and_mutation_events_are_persistent(
    tmp_path: Path,
) -> None:
    service = ControlPlaneService(tmp_path / "runs")
    created = service.create_project(
        {
            "name": "control-plane-demo",
            "repository_path": str(tmp_path),
            "default_config": {"analysisMode": "v2"},
        }
    )
    updated = service.update_project(
        UUID(str(created["id"])),
        {"name": "renamed-demo", "archived": True},
    )

    assert updated["name"] == "renamed-demo"
    assert updated["archived_at"] is not None
    persisted = ControlPlaneService(tmp_path / "runs").get_project(
        UUID(str(created["id"])),
    )
    assert persisted["name"] == "renamed-demo"
    database = Database(control_db_path(tmp_path / "runs"))
    try:
        events = Repositories(database).events.list(
            project_id=UUID(str(created["id"])),
        )
        assert [event.event_type for event in events] == [
            "project.created",
            "project.updated",
        ]
    finally:
        database.close()


def test_project_rejects_credentials_in_new_default_config(tmp_path: Path) -> None:
    service = ControlPlaneService(tmp_path / "runs")

    with pytest.raises(ControlPlaneInputError, match="credentials"):
        service.create_project(
            {
                "name": "unsafe",
                "repository_path": str(tmp_path),
                "default_config": {"provider": {"credentials": {"api_key": "secret"}}},
            }
        )


def test_artifact_preview_and_download_use_verified_content_address(
    tmp_path: Path,
) -> None:
    _project, _scan, _task, artifact = _seed(tmp_path)
    service = ControlPlaneService(tmp_path / "runs")

    detail = service.artifact(artifact.id)
    content = service.artifact_content(artifact.id)

    assert "storage_uri" not in detail
    assert detail["metadata"]["api_key"] == "[REDACTED]"
    assert detail["preview"] == {
        "available": True,
        "truncated": False,
        "value": {"kind": "finding", "value": "safe preview"},
    }
    assert content.path.is_file()
    assert content.path.read_bytes() == b'{"kind":"finding","value":"safe preview"}'
    assert content.path.is_relative_to((tmp_path / "runs" / "_data" / "artifacts").resolve())


def test_sensitive_prompt_artifact_cannot_be_previewed_or_downloaded(
    tmp_path: Path,
) -> None:
    _project, scan, task, _artifact = _seed(tmp_path)
    runs_root = tmp_path / "runs"
    store = ArtifactStore(runs_root)
    blob = store.put_text("full sensitive prompt")
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    prompt_artifact = repositories.artifacts.create(
        Artifact(
            scan_id=scan.id,
            snapshot_id=scan.snapshot_id,
            task_id=task.id,
            artifact_type="llm.prompt.audit.v1",
            schema_version="1.0",
            capabilities=["audit.llm.prompt.v1"],
            producer_plugin_id="fixture",
            producer_plugin_version="1.0.0",
            media_type="text/plain",
            content_hash=blob.content_hash,
            size_bytes=blob.size_bytes,
            storage_uri=blob.storage_uri,
        )
    )
    database.close()
    service = ControlPlaneService(runs_root)

    detail = service.artifact(prompt_artifact.id)

    assert detail["preview"]["available"] is False
    with pytest.raises(ArtifactAccessDenied):
        service.artifact_content(prompt_artifact.id)


def test_finding_projection_separates_static_review_and_dynamic_verification(
    tmp_path: Path,
) -> None:
    project, scan, task, _artifact = _seed(tmp_path)
    service = ControlPlaneService(tmp_path / "runs")
    finding = service.list_findings(scan.id)[0]

    review = service.create_review(
        {
            "scan_id": str(scan.id),
            "task_id": str(task.id),
            "subject_type": "finding_set",
            "subject_ids": [finding["id"]],
        }
    )
    decided = service.decide_review(
        UUID(str(review["id"])),
        ReviewStatus.APPROVED,
        {"reviewer": "alice", "reason": "Static evidence accepted."},
    )
    refreshed = service.finding(
        UUID(str(finding["id"])),
    )

    assert decided["status"] == "approved"
    assert refreshed["static_review"]["status"] == "approved"
    assert refreshed["dynamic_verification"]["available"] is False
    assert refreshed["dynamic_verification"]["status"] == "disabled"
    assert refreshed["dynamic_verification"]["network_execution_available"] is False
    assert refreshed["graph_slice_url"].endswith("/graph-slice")
    graph_slice = service.graph_slice_artifact(UUID(str(refreshed["graph_slice_artifact_id"])))
    assert graph_slice["graph_slice"]["seed_ids"] == ["sir:route:get-order"]
    database = Database(control_db_path(tmp_path / "runs"))
    try:
        events = Repositories(database).events.list(scan_id=scan.id)
        assert "review.created" in [event.event_type for event in events]
        assert "review.approved" in [event.event_type for event in events]
        assert all(event.project_id in {None, project.id} for event in events)
    finally:
        database.close()


def test_finding_patch_is_static_only_and_audited(tmp_path: Path) -> None:
    _project, scan, _task, _artifact = _seed(tmp_path)
    service = ControlPlaneService(tmp_path / "runs")
    finding_id = service.list_findings(scan.id)[0]["id"]

    updated = service.update_finding(
        UUID(str(finding_id)),
        {
            "title": "Reviewed static title",
            "status": "static_supported",
            "static_confidence": "medium",
        },
    )

    assert updated["title"] == "Reviewed static title"
    assert updated["status"] == "static_supported"
    assert updated["dynamic_verification"]["status"] == "disabled"
    events = service.events(scan.id)
    event = next(item for item in events if item["event_type"] == "finding.updated")
    assert event["payload"]["static_only"] is True
    assert event["payload"]["dynamic_verification_changed"] is False


def test_reconcile_marks_dead_worker_recoverable_from_persistent_state(
    tmp_path: Path,
) -> None:
    project, scan, task, _artifact = _seed(tmp_path)
    database = Database(control_db_path(tmp_path / "runs"))
    repositories = Repositories(database)
    services = ControlServices(repositories)
    scan = services.scans.transition(scan.id, ScanStatus.PLANNING)
    scan = services.scans.transition(scan.id, ScanStatus.READY)
    scan = services.scans.transition(scan.id, ScanStatus.RUNNING)
    task = services.tasks.transition(task.id, TaskStatus.READY)
    task = services.tasks.transition(task.id, TaskStatus.RUNNING)
    repositories.attempts.create(
        TaskAttempt(
            scan_id=scan.id,
            task_id=task.id,
            attempt_number=1,
            status=AttemptStatus.RUNNING,
            plugin_id=task.plugin_id,
            plugin_version=task.plugin_version,
            config_hash=task.config_hash,
            worker_pid=2_000_000_000,
            heartbeat_at=utc_now(),
        )
    )
    database.close()

    reconciled = ControlPlaneService(tmp_path / "runs").reconcile_running_scans()

    assert reconciled == [str(scan.id)]
    reopened = Database(control_db_path(tmp_path / "runs"))
    try:
        repositories = Repositories(reopened)
        recovered = repositories.tasks.get(task.id)
        attempts = repositories.attempts.list(task_id=task.id)
        assert recovered.status is TaskStatus.READY
        assert attempts[-1].status is AttemptStatus.INTERRUPTED
        events = repositories.events.list(scan_id=scan.id)
        assert events[-1].event_type == "web.reconciled_lost_workers"
        assert events[-1].project_id == project.id
    finally:
        reopened.close()


def test_task_plan_api_returns_persisted_dag_and_artifact(
    tmp_path: Path,
) -> None:
    _project, scan, _task, _artifact = _seed(tmp_path)
    database = Database(control_db_path(tmp_path / "runs"))
    repositories = Repositories(database)
    registry = PluginRegistry()
    registry.register(
        PluginSpec(
            id="detector.plan-fixture",
            version="1.0.0",
            kind=PluginKind.DETECTOR,
            entrypoint="tests.control_plane.test_service:noop",
            produces=[
                CapabilityDeclaration(
                    capability="finding.plan-fixture.v1",
                    artifact_type="finding.plan-fixture",
                    schema_version="1.0",
                )
            ],
        ),
        origin=PluginOrigin.BUILTIN,
    )
    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=scan.id,
            selected_plugin_ids=["detector.plan-fixture"],
        )
    )
    artifact = TaskPlanPersistence(
        repositories,
        runs_root=tmp_path / "runs",
    ).persist(plan, snapshot_id=scan.snapshot_id)
    database.close()

    projection = ControlPlaneService(tmp_path / "runs").plan(scan.id)

    assert projection["id"] == str(plan.id)
    assert projection["artifact_id"] == str(artifact.id)
    assert projection["tasks"][0]["plugin_id"] == "detector.plan-fixture"


def test_m8_control_plane_shows_missing_inputs_and_hash_bound_approval(
    tmp_path: Path,
) -> None:
    project, scan, _task, _artifact = _seed(tmp_path)
    database = Database(control_db_path(tmp_path / "runs"))
    repositories = Repositories(database)
    scan = repositories.scans.update(
        scan.model_copy(
            update={
                "config": {
                    **scan.config,
                    "verification": {
                        "enabled": True,
                        "allow_safe_read": True,
                        "allow_reversible_write": False,
                    },
                }
            }
        )
    )
    finding = repositories.findings.list(scan_id=scan.id)[0]
    database.close()
    service = ControlPlaneService(tmp_path / "runs")

    environment = service.create_verification_environment(
        project.id,
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
            "source_snapshot_binding": str(scan.snapshot_id),
        },
    )
    identities = [
        service.create_verification_identity(
            project.id,
            {
                "handle": handle,
                "role": role,
                "credential_ref": credential_ref,
            },
        )
        for handle, role, credential_ref in (
            ("owner", "owner", "env:ARGUS_TEST_OWNER_TOKEN"),
            ("peer", "peer", "env:ARGUS_TEST_PEER_TOKEN"),
        )
    ]
    declaration = {
        "verifier_id": "authorization_differential_read",
        "supported_vuln_classes": ["authorization"],
        "required_environment_capabilities": ["readonly_http"],
        "required_identity_roles": ["owner", "peer"],
        "required_test_data": ["resource_id"],
    }
    missing = service.resolve_verification_requirement(
        finding.id,
        {"declaration": declaration, "test_data_keys": []},
    )
    assert missing["missing_fields"] == ["test_data:resource_id"]
    assert service.verification_summary(finding.id)["status"] == "missing_inputs"

    ready = service.resolve_verification_requirement(
        finding.id,
        {"declaration": declaration, "test_data_keys": ["resource_id"]},
    )
    assert ready["missing_fields"] == []
    payload = {
        "environment_id": environment["id"],
        "identity_ids": [item["id"] for item in identities],
        "actions": [
            {
                "id": "owner_read",
                "method": "GET",
                "resource_path": "/api/orders/{resource_id}",
                "identity_handle": "owner",
                "test_data_refs": ["resource_id"],
                "observation_ids": ["owner_result"],
            }
        ],
        "request_budget": {
            "max_requests": 1,
            "max_response_bytes": 64_000,
            "timeout_seconds": 10,
        },
        "expected_observations": [
            {
                "id": "owner_result",
                "description": "Owner reads the fixture.",
                "predicate": "status == 200",
            }
        ],
        "expected_side_effects": [],
        "rollback_strategy": {"mode": "none", "instructions": []},
        "health_checks": [],
        "abort_conditions": [
            {
                "id": "server_error",
                "description": "Abort on 5xx.",
            }
        ],
        "risk_class": "R1_SAFE_READ",
    }
    plan = service.compile_verification_plan(finding.id, payload)
    approval = service.request_verification_approval(UUID(str(plan["id"])))
    decided = service.decide_verification_approval(
        UUID(str(approval["id"])),
        ApprovalDecision.APPROVED,
        {"reviewer": "alice", "reason": "Reviewed declarative plan."},
    )
    assert decided["plan_hash"] == plan["plan_hash"]
    assert service.verification_summary(finding.id)["status"] == "approved"

    revised = service.compile_verification_plan(
        finding.id,
        {
            **payload,
            "request_budget": {
                "max_requests": 2,
                "max_response_bytes": 64_000,
                "timeout_seconds": 10,
            },
        },
    )
    assert revised["plan_hash"] != plan["plan_hash"]
    old = service.list_verification_approvals(plan_id=UUID(str(plan["id"])))[0]
    assert old["decision"] == "superseded"
    assert service.verification_summary(finding.id)["network_execution_available"] is False


def test_m8_identity_attributes_cannot_store_credentials(tmp_path: Path) -> None:
    project, _scan, _task, _artifact = _seed(tmp_path)

    with pytest.raises(ControlPlaneInputError, match="credentials"):
        ControlPlaneService(tmp_path / "runs").create_verification_identity(
            project.id,
            {
                "handle": "owner",
                "role": "owner",
                "credential_ref": "env:ARGUS_TEST_OWNER_TOKEN",
                "attributes": {"nested": {"api_key": "plaintext"}},
            },
        )


def noop() -> None:
    pass
