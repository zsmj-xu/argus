"""Persist a compiled plan without executing its tasks."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid5

from argus.artifacts.schemas import ArtifactPublication
from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactPublisher
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import TaskStatus
from argus.domain.hashing import sha256_digest
from argus.domain.models import Artifact, Task, TaskPlan
from argus.planning.serialization import serialize_plan

PLAN_COMPILER_ID = "core.plan-compiler"
PLAN_COMPILER_VERSION = "1.0.0"


class TaskPlanPersistence:
    def __init__(
        self,
        repositories: Repositories,
        *,
        runs_root: str | Path = "runs",
    ) -> None:
        self.repositories = repositories
        self.services = ControlServices(repositories)
        self.events = EventService(repositories.events)
        self.publisher = ArtifactPublisher(
            ArtifactStore(runs_root),
            repositories.artifacts,
        )

    def persist(self, plan: TaskPlan, *, snapshot_id: UUID) -> Artifact:
        scan = self.repositories.scans.get(plan.scan_id)
        if scan.plan_id is not None:
            raise ValueError(f"scan {scan.id} already has plan {scan.plan_id}")

        for planned in plan.tasks:
            self.repositories.tasks.create(
                Task(
                    id=planned.id,
                    scan_id=plan.scan_id,
                    plan_id=plan.id,
                    plugin_id=planned.plugin_id,
                    plugin_version=planned.plugin_version,
                    kind=planned.kind.value,
                    depends_on=planned.depends_on,
                    required_capabilities=planned.required_capabilities,
                    optional_capabilities=planned.optional_capabilities,
                    expected_capabilities=planned.expected_capabilities,
                    config_hash=planned.config_hash,
                    cache_key=planned.cache_key,
                    continue_on_failure=planned.continue_on_failure,
                    max_attempts=planned.max_attempts,
                )
            )

        compiler_id = uuid5(plan.id, PLAN_COMPILER_ID)
        compiler = self.repositories.tasks.create(
            Task(
                id=compiler_id,
                scan_id=plan.scan_id,
                plan_id=plan.id,
                plugin_id=PLAN_COMPILER_ID,
                plugin_version=PLAN_COMPILER_VERSION,
                kind="planner",
                expected_capabilities=["task.plan.v1"],
                config_hash=sha256_digest({}),
                cache_key=plan.plan_hash,
            )
        )
        compiler = self.services.tasks.transition(compiler.id, TaskStatus.READY)
        compiler = self.services.tasks.transition(compiler.id, TaskStatus.RUNNING)
        artifact = self.publisher.publish_json(
            serialize_plan(plan),
            ArtifactPublication(
                scan_id=plan.scan_id,
                snapshot_id=snapshot_id,
                task_id=compiler.id,
                artifact_type="task.plan.v1",
                schema_version="1.0",
                capabilities=["task.plan.v1"],
                producer_plugin_id=PLAN_COMPILER_ID,
                producer_plugin_version=PLAN_COMPILER_VERSION,
                media_type="application/json",
                metadata={"plan_hash": plan.plan_hash},
            ),
        )
        self.repositories.plans.create(plan, artifact_id=artifact.id)
        self.repositories.scans.update(scan.model_copy(update={"plan_id": plan.id}))
        self.services.tasks.transition(compiler.id, TaskStatus.SUCCEEDED)
        self.events.append(
            "plan.compiled",
            project_id=scan.project_id,
            scan_id=scan.id,
            task_id=compiler.id,
            payload={
                "plan_id": str(plan.id),
                "plan_hash": plan.plan_hash,
                "task_count": len(plan.tasks),
                "artifact_id": str(artifact.id),
            },
        )
        return artifact
