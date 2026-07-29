from __future__ import annotations

from pathlib import Path

from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactView
from argus.control.repositories import Repositories
from argus.domain.enums import PluginKind, TaskStatus
from argus.planning.persistence import TaskPlanPersistence
from argus.planning.planner import PlanningRequest, TaskPlanner
from argus.plugins.contracts import CapabilityDeclaration, PluginSpec
from argus.plugins.registry import PluginOrigin, PluginRegistry

from .helpers import make_project, make_scan


def test_compiled_plan_is_linked_to_scan_tasks_event_and_artifact(
    tmp_path: Path,
    repositories: Repositories,
) -> None:
    project = repositories.projects.create(make_project())
    scan = repositories.scans.create(make_scan(project))
    registry = PluginRegistry()
    registry.register(
        PluginSpec(
            id="detector.demo",
            version="1.0.0",
            kind=PluginKind.DETECTOR,
            entrypoint="tests.control.test_task_plans:noop",
            produces=[
                CapabilityDeclaration(
                    capability="candidate.demo.v1",
                    artifact_type="candidate.demo",
                    schema_version="1.0",
                )
            ],
        ),
        origin=PluginOrigin.BUILTIN,
    )
    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=scan.id,
            selected_plugin_ids=["detector.demo"],
        )
    )

    artifact = TaskPlanPersistence(repositories, runs_root=tmp_path).persist(
        plan,
        snapshot_id=scan.snapshot_id,
    )

    assert repositories.scans.get(scan.id).plan_id == plan.id
    persisted = repositories.plans.get(plan.id)
    assert persisted.plan_hash == plan.plan_hash
    assert persisted.tasks == plan.tasks
    assert repositories.plans.artifact_id(plan.id) == artifact.id
    tasks = repositories.tasks.list(scan_id=scan.id)
    assert {task.plugin_id: task.status for task in tasks} == {
        "core.plan-compiler": TaskStatus.SUCCEEDED,
        "detector.demo": TaskStatus.PENDING,
    }
    payload = ArtifactView(ArtifactStore(tmp_path)).read_json(artifact)
    assert isinstance(payload, dict)
    assert payload["plan_hash"] == plan.plan_hash
    assert artifact.capabilities == ["task.plan.v1"]
    events = repositories.events.list(scan_id=scan.id)
    assert events[-1].event_type == "plan.compiled"


def noop() -> None:
    pass
