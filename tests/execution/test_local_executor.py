from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

from argus.artifacts.schemas import ArtifactPublication
from argus.artifacts.store import ArtifactStore
from argus.artifacts.views import ArtifactPublisher
from argus.control.db import Database, upgrade_database
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import (
    AttemptStatus,
    PluginKind,
    ReviewStatus,
    ScanEngine,
    ScanStatus,
    TaskStatus,
    VcsType,
)
from argus.domain.errors import ConflictError, InvalidTransitionError
from argus.domain.models import (
    Project,
    Scan,
    SourceSnapshot,
    Task,
    TaskAttempt,
    utc_now,
)
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput
from argus.execution.local import LocalPlanExecutor
from argus.planning.persistence import TaskPlanPersistence
from argus.planning.planner import PlanningRequest, TaskPlanner
from argus.plugins.contracts import (
    CapabilityDeclaration,
    CapabilityRequirement,
    IsolationMode,
    NetworkPermission,
    PermissionSpec,
    PluginSpec,
    RuntimeSpec,
    SecretsPermission,
)
from argus.plugins.registry import PluginOrigin, PluginRegistry

SHA = "a" * 64
RUNTIME_CALLS: dict[str, int] = {}
SLOW_STARTED = threading.Event()


def producer_runtime(
    _context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    RUNTIME_CALLS["producer"] = RUNTIME_CALLS.get("producer", 0) + 1
    return [
        RuntimeOutput(
            capability="data.produced.v1",
            artifact_type="data.produced",
            schema_version="1.0",
            media_type="application/json",
            json_value={"value": 7},
        )
    ]


def consumer_runtime(
    _context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    RUNTIME_CALLS["consumer"] = RUNTIME_CALLS.get("consumer", 0) + 1
    assert "data.produced.v1" in inputs
    return [
        RuntimeOutput(
            capability="data.consumed.v1",
            artifact_type="data.consumed",
            schema_version="1.0",
            media_type="application/json",
            json_value={"consumed": True},
        )
    ]


def flaky_runtime(
    _context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    RUNTIME_CALLS["flaky"] = RUNTIME_CALLS.get("flaky", 0) + 1
    if RUNTIME_CALLS["flaky"] == 1:
        raise RuntimeError("retry me")
    return [
        RuntimeOutput(
            capability="data.flaky.v1",
            artifact_type="data.flaky",
            schema_version="1.0",
            media_type="application/json",
            json_value={"ok": True},
        )
    ]


def always_fail_runtime(
    _context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    RUNTIME_CALLS["failure"] = RUNTIME_CALLS.get("failure", 0) + 1
    raise RuntimeError("expected failure")


def optional_consumer_runtime(
    _context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    assert "data.optional.v1" not in inputs
    return [
        RuntimeOutput(
            capability="data.optional-result.v1",
            artifact_type="data.optional-result",
            schema_version="1.0",
            media_type="application/json",
            json_value={"continued": True},
        )
    ]


def review_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    source = inputs["data.produced.v1"]
    return [
        RuntimeOutput(
            capability="data.reviewed.v1",
            artifact_type="data.reviewed",
            schema_version="1.0",
            media_type=source.artifact.media_type,
            payload=source.payload,
            metadata={"review_task": str(context.task.id)},
        )
    ]


def reviewed_consumer_runtime(
    _context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    assert "data.reviewed.v1" in inputs
    return [
        RuntimeOutput(
            capability="data.final.v1",
            artifact_type="data.final",
            schema_version="1.0",
            media_type="application/json",
            json_value={"done": True},
        )
    ]


def invalid_schema_runtime(
    _context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    return [
        RuntimeOutput(
            capability="data.schema.v1",
            artifact_type="data.schema",
            schema_version="1.0",
            media_type="application/json",
            json_value={"value": "not-an-integer"},
        )
    ]


def slow_runtime(
    _context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    SLOW_STARTED.set()
    time.sleep(0.35)
    return [
        RuntimeOutput(
            capability="data.slow.v1",
            artifact_type="data.slow",
            schema_version="1.0",
            media_type="application/json",
            json_value={"done": True},
        )
    ]


def _spec(
    plugin_id: str,
    entrypoint: str,
    *,
    consumes: tuple[str, ...] = (),
    optional: tuple[str, ...] = (),
    produces: tuple[str, ...],
    kind: PluginKind = PluginKind.DETECTOR,
    max_attempts: int = 1,
    continue_on_failure: bool = False,
) -> PluginSpec:
    return PluginSpec(
        id=plugin_id,
        version="1.0.0",
        kind=kind,
        entrypoint=f"tests.execution.test_local_executor:{entrypoint}",
        consumes=[CapabilityRequirement(capability=capability) for capability in consumes],
        optional_consumes=[CapabilityRequirement(capability=capability, required=False) for capability in optional],
        produces=[
            CapabilityDeclaration(
                capability=capability,
                artifact_type=capability.removesuffix(".v1"),
                schema_version="1.0",
            )
            for capability in produces
        ],
        max_attempts=max_attempts,
        continue_on_failure=continue_on_failure,
        runtime=RuntimeSpec(isolation=IsolationMode.IN_PROCESS),
    )


def _registry(*specs: PluginSpec) -> PluginRegistry:
    registry = PluginRegistry()
    for spec in specs:
        registry.register(spec, origin=PluginOrigin.BUILTIN)
    return registry


def _base_registry() -> PluginRegistry:
    return _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            consumes=("source.snapshot.v1",),
            produces=("data.produced.v1",),
        ),
        _spec(
            "fixture.consumer",
            "consumer_runtime",
            consumes=("data.produced.v1",),
            produces=("data.consumed.v1",),
        ),
    )


def _prepared_scan(
    tmp_path: Path,
    registry: PluginRegistry,
    selected: list[str],
    *,
    checkpoints: bool = False,
) -> tuple[Database, Repositories, Scan]:
    database_path = tmp_path / "control.db"
    upgrade_database(database_path)
    database = Database(database_path)
    repositories = Repositories(database)
    services = ControlServices(repositories)
    repository_path = str(tmp_path / "source")
    project = repositories.projects.find_by_repository_path(repository_path)
    if project is None:
        project = repositories.projects.create(
            Project(
                name=f"fixture-{uuid4().hex[:8]}",
                repository_path=repository_path,
            )
        )
    snapshot_id = uuid4()
    scan = repositories.scans.create(
        Scan(
            project_id=project.id,
            snapshot_id=snapshot_id,
            config={
                "checkpoints": checkpoints,
                "execution": {"workspace": "fixture-run"},
            },
            config_hash=SHA,
            engine=ScanEngine.V2,
        )
    )
    scan = services.scans.transition(scan.id, ScanStatus.PLANNING)
    source_task = repositories.tasks.create(
        Task(
            scan_id=scan.id,
            plugin_id="source.snapshot",
            plugin_version="1.0.0",
            kind="snapshot",
            expected_capabilities=["source.snapshot.v1"],
            config_hash=SHA,
            cache_key=SHA,
        )
    )
    source_task = services.tasks.transition(source_task.id, TaskStatus.READY)
    source_task = services.tasks.transition(source_task.id, TaskStatus.RUNNING)
    manifest_id = uuid4()
    ArtifactPublisher(
        ArtifactStore(tmp_path),
        repositories.artifacts,
    ).publish_json(
        {"files": []},
        ArtifactPublication(
            scan_id=scan.id,
            snapshot_id=snapshot_id,
            task_id=source_task.id,
            artifact_type="source.snapshot.manifest.v1",
            schema_version="1.0",
            capabilities=["source.snapshot.v1"],
            producer_plugin_id="source.snapshot",
            producer_plugin_version="1.0.0",
            media_type="application/json",
            artifact_id=manifest_id,
        ),
    )
    services.tasks.transition(source_task.id, TaskStatus.SUCCEEDED)
    source_path = tmp_path / "source"
    source_path.mkdir(exist_ok=True)
    repositories.snapshots.create(
        SourceSnapshot(
            id=snapshot_id,
            project_id=project.id,
            repository_path=str(source_path),
            vcs_type=VcsType.DIRECTORY,
            tree_hash=SHA,
            dirty=False,
            materialized_path=str(source_path),
            manifest_artifact_id=manifest_id,
        )
    )
    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=scan.id,
            selected_plugin_ids=selected,
            initial_capabilities={"source.snapshot.v1"},
        )
    )
    TaskPlanPersistence(repositories, runs_root=tmp_path).persist(
        plan,
        snapshot_id=snapshot_id,
    )
    LocalPlanExecutor(
        repositories,
        runs_root=tmp_path,
        registry=registry,
    ).prepare(plan)
    return database, repositories, repositories.scans.get(scan.id)


def test_executes_dag_serially_and_persists_attempts(tmp_path: Path) -> None:
    RUNTIME_CALLS.clear()
    registry = _base_registry()
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.consumer"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.COMPLETED
        assert [task.plugin_id for task in status.tasks] == [
            "fixture.producer",
            "fixture.consumer",
        ]
        assert all(task.status is TaskStatus.SUCCEEDED for task in status.tasks)
        attempts = repositories.attempts.list(scan_id=scan.id)
        assert [attempt.status for attempt in attempts] == [
            AttemptStatus.SUCCEEDED,
            AttemptStatus.SUCCEEDED,
        ]
        assert attempts[1].input_hashes.keys() == {"data.produced.v1"}
        assert RUNTIME_CALLS == {"producer": 1, "consumer": 1}
    finally:
        database.close()


def test_retry_budget_is_persisted_per_attempt(tmp_path: Path) -> None:
    RUNTIME_CALLS.clear()
    registry = _registry(
        _spec(
            "fixture.flaky",
            "flaky_runtime",
            produces=("data.flaky.v1",),
            max_attempts=2,
        )
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.flaky"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.COMPLETED
        assert [item.status for item in repositories.attempts.list(task_id=status.tasks[0].id)] == [
            AttemptStatus.FAILED_RETRYABLE,
            AttemptStatus.SUCCEEDED,
        ]
        assert RUNTIME_CALLS["flaky"] == 2
    finally:
        database.close()


def test_identical_successful_tasks_reuse_content_after_restart(
    tmp_path: Path,
) -> None:
    RUNTIME_CALLS.clear()
    registry = _base_registry()
    first_database, first_repositories, first_scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.consumer"],
    )
    first_status = LocalPlanExecutor(
        first_repositories,
        runs_root=tmp_path,
        registry=registry,
    ).run_ready_tasks(first_scan.id)
    assert first_status.scan.status is ScanStatus.COMPLETED
    first_database.close()
    assert RUNTIME_CALLS == {"producer": 1, "consumer": 1}

    second_database, second_repositories, second_scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.consumer"],
    )
    try:
        second_status = LocalPlanExecutor(
            second_repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(second_scan.id)

        assert second_status.scan.status is ScanStatus.COMPLETED
        assert RUNTIME_CALLS == {"producer": 1, "consumer": 1}
        reused = [
            event
            for event in second_repositories.events.list(scan_id=second_scan.id)
            if event.event_type == "task.cache_reused"
        ]
        assert len(reused) == 2
    finally:
        second_database.close()


def test_required_failure_fails_scan_and_skips_dependent(tmp_path: Path) -> None:
    RUNTIME_CALLS.clear()
    registry = _registry(
        _spec(
            "fixture.failure",
            "always_fail_runtime",
            produces=("data.produced.v1",),
        ),
        _spec(
            "fixture.consumer",
            "consumer_runtime",
            consumes=("data.produced.v1",),
            produces=("data.consumed.v1",),
        ),
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.consumer"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.FAILED
        assert {task.plugin_id: task.status for task in status.tasks} == {
            "fixture.failure": TaskStatus.FAILED,
            "fixture.consumer": TaskStatus.SKIPPED,
        }
    finally:
        database.close()


def test_invalid_output_schema_commits_no_artifact(tmp_path: Path) -> None:
    spec = _spec(
        "fixture.schema",
        "invalid_schema_runtime",
        produces=("data.schema.v1",),
    ).model_copy(
        update={
            "output_schemas": {
                "data.schema.v1": {
                    "type": "object",
                    "required": ["value"],
                    "properties": {"value": {"type": "integer"}},
                    "additionalProperties": False,
                }
            }
        }
    )
    registry = _registry(spec)
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.schema"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.FAILED
        assert all(
            "data.schema.v1" not in artifact.capabilities for artifact in repositories.artifacts.list(scan_id=scan.id)
        )
    finally:
        database.close()


def test_optional_failure_can_continue_when_plan_explicitly_allows_it(
    tmp_path: Path,
) -> None:
    registry = _registry(
        _spec(
            "fixture.optional",
            "always_fail_runtime",
            produces=("data.optional.v1",),
            continue_on_failure=True,
        ),
        _spec(
            "fixture.optional-consumer",
            "optional_consumer_runtime",
            optional=("data.optional.v1",),
            produces=("data.optional-result.v1",),
        ),
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.optional", "fixture.optional-consumer"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.COMPLETED
        assert {task.plugin_id: task.status for task in status.tasks} == {
            "fixture.optional": TaskStatus.FAILED,
            "fixture.optional-consumer": TaskStatus.SUCCEEDED,
        }
    finally:
        database.close()


def test_review_approval_survives_executor_restart(tmp_path: Path) -> None:
    registry = _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            consumes=("source.snapshot.v1",),
            produces=("data.produced.v1",),
        ),
        _spec(
            "fixture.review",
            "review_runtime",
            consumes=("data.produced.v1",),
            produces=("data.reviewed.v1",),
            kind=PluginKind.REVIEW_GATE,
        ),
        _spec(
            "fixture.reviewed-consumer",
            "reviewed_consumer_runtime",
            consumes=("data.reviewed.v1",),
            produces=("data.final.v1",),
        ),
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.reviewed-consumer"],
        checkpoints=True,
    )
    status = LocalPlanExecutor(
        repositories,
        runs_root=tmp_path,
        registry=registry,
    ).run_ready_tasks(scan.id)
    assert status.scan.status is ScanStatus.WAITING_REVIEW
    assert len(status.open_review_ids) == 1
    review_id = status.open_review_ids[0]
    database.close()

    reopened = Database(tmp_path / "control.db")
    repositories = Repositories(reopened)
    try:
        review = ControlServices(repositories).reviews.decide(
            review_id,
            ReviewStatus.APPROVED,
            reviewer="alice",
            reason="fixture accepted",
        )
        assert review.subject_hash
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).resume(scan.id)
        assert status.scan.status is ScanStatus.COMPLETED
        assert repositories.reviews.get(review_id).reviewer == "alice"
    finally:
        reopened.close()


def test_review_approval_is_superseded_when_subject_changes(
    tmp_path: Path,
) -> None:
    registry = _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            consumes=("source.snapshot.v1",),
            produces=("data.produced.v1",),
        ),
        _spec(
            "fixture.review",
            "review_runtime",
            consumes=("data.produced.v1",),
            produces=("data.reviewed.v1",),
            kind=PluginKind.REVIEW_GATE,
        ),
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.review"],
        checkpoints=True,
    )
    executor = LocalPlanExecutor(
        repositories,
        runs_root=tmp_path,
        registry=registry,
    )
    status = executor.run_ready_tasks(scan.id)
    first_id = status.open_review_ids[0]
    ControlServices(repositories).reviews.decide(
        first_id,
        ReviewStatus.APPROVED,
        reviewer="alice",
        reason="first subject accepted",
    )
    producer = next(task for task in status.tasks if task.plugin_id == "fixture.producer")
    ArtifactPublisher(
        ArtifactStore(tmp_path),
        repositories.artifacts,
    ).publish_json(
        {"value": 8},
        ArtifactPublication(
            scan_id=scan.id,
            snapshot_id=scan.snapshot_id,
            task_id=producer.id,
            artifact_type="data.produced",
            schema_version="1.0",
            capabilities=["data.produced.v1"],
            producer_plugin_id=producer.plugin_id,
            producer_plugin_version=producer.plugin_version,
            media_type="application/json",
        ),
    )
    try:
        resumed = executor.resume(scan.id)

        assert resumed.scan.status is ScanStatus.WAITING_REVIEW
        assert repositories.reviews.get(first_id).status is ReviewStatus.SUPERSEDED
        assert len(resumed.open_review_ids) == 1
        assert resumed.open_review_ids[0] != first_id
    finally:
        database.close()


def test_stale_running_attempt_is_interrupted_then_retried(
    tmp_path: Path,
) -> None:
    RUNTIME_CALLS.clear()
    registry = _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            produces=("data.produced.v1",),
            max_attempts=2,
        )
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.producer"],
    )
    services = ControlServices(repositories)
    scan = services.scans.transition(scan.id, ScanStatus.RUNNING)
    task = repositories.tasks.list(scan_id=scan.id)
    planned = next(item for item in task if item.plan_id == scan.plan_id and item.plugin_id != "core.plan-compiler")
    claimed = services.tasks.transition(planned.id, TaskStatus.RUNNING)
    old = utc_now() - timedelta(hours=1)
    repositories.attempts.create(
        TaskAttempt(
            scan_id=scan.id,
            task_id=claimed.id,
            attempt_number=1,
            plugin_id=claimed.plugin_id,
            plugin_version=claimed.plugin_version,
            config_hash=claimed.config_hash,
            worker_pid=999999,
            started_at=old,
            heartbeat_at=old,
        )
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
            stale_after=timedelta(seconds=1),
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.COMPLETED
        assert [item.status for item in repositories.attempts.list(task_id=claimed.id)] == [
            AttemptStatus.INTERRUPTED,
            AttemptStatus.SUCCEEDED,
        ]
    finally:
        database.close()


def test_restart_recovers_persisted_failed_retryable_task(
    tmp_path: Path,
) -> None:
    registry = _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            produces=("data.produced.v1",),
            max_attempts=2,
        )
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.producer"],
    )
    services = ControlServices(repositories)
    scan = services.scans.transition(scan.id, ScanStatus.RUNNING)
    task = next(
        item
        for item in repositories.tasks.list(scan_id=scan.id)
        if item.plan_id == scan.plan_id and item.plugin_id != "core.plan-compiler"
    )
    task = services.tasks.transition(task.id, TaskStatus.RUNNING)
    now = utc_now()
    repositories.attempts.create(
        TaskAttempt(
            scan_id=scan.id,
            task_id=task.id,
            attempt_number=1,
            status=AttemptStatus.FAILED_RETRYABLE,
            plugin_id=task.plugin_id,
            plugin_version=task.plugin_version,
            config_hash=task.config_hash,
            worker_pid=999999,
            started_at=now,
            heartbeat_at=now,
            finished_at=now,
            error_code="RuntimeError",
            error_message="simulated crash window",
        )
    )
    services.tasks.transition(
        task.id,
        TaskStatus.FAILED_RETRYABLE,
        error_code="RuntimeError",
        error_message="simulated crash window",
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.COMPLETED
        assert [item.status for item in repositories.attempts.list(task_id=task.id)] == [
            AttemptStatus.FAILED_RETRYABLE,
            AttemptStatus.SUCCEEDED,
        ]
    finally:
        database.close()


def test_running_plugin_heartbeat_prevents_false_recovery(
    tmp_path: Path,
) -> None:
    SLOW_STARTED.clear()
    registry = _registry(
        _spec(
            "fixture.slow",
            "slow_runtime",
            produces=("data.slow.v1",),
        )
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.slow"],
    )
    errors: list[BaseException] = []
    executor = LocalPlanExecutor(
        repositories,
        runs_root=tmp_path,
        registry=registry,
        stale_after=timedelta(seconds=0.15),
    )

    def run() -> None:
        try:
            executor.run_ready_tasks(scan.id)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    assert SLOW_STARTED.wait(timeout=2)
    time.sleep(0.22)
    LocalPlanExecutor(
        repositories,
        runs_root=tmp_path,
        registry=registry,
        stale_after=timedelta(seconds=0.15),
    ).recover_stale(scan.id)
    worker.join(timeout=2)
    try:
        assert not worker.is_alive()
        assert errors == []
        attempts = repositories.attempts.list(scan_id=scan.id)
        assert [item.status for item in attempts] == [AttemptStatus.SUCCEEDED]
        assert repositories.scans.get(scan.id).status is ScanStatus.COMPLETED
    finally:
        database.close()


def test_concurrent_task_claim_has_single_winner(tmp_path: Path) -> None:
    registry = _registry(
        _spec(
            "fixture.producer",
            "producer_runtime",
            produces=("data.produced.v1",),
        )
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.producer"],
    )
    task = next(
        item
        for item in repositories.tasks.list(scan_id=scan.id)
        if item.plan_id == scan.plan_id and item.plugin_id != "core.plan-compiler"
    )
    barrier = threading.Barrier(2)
    winners: list[TaskStatus] = []
    losers: list[type[BaseException]] = []

    def claim() -> None:
        barrier.wait()
        try:
            claimed, _attempt = repositories.tasks.claim_with_attempt(
                task.id,
                TaskAttempt(
                    scan_id=scan.id,
                    task_id=task.id,
                    attempt_number=1,
                    plugin_id=task.plugin_id,
                    plugin_version=task.plugin_version,
                    config_hash=task.config_hash,
                    worker_pid=999999,
                ),
            )
            winners.append(claimed.status)
        except (ConflictError, InvalidTransitionError) as exc:
            losers.append(type(exc))

    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)
    try:
        assert winners == [TaskStatus.RUNNING]
        assert len(losers) == 1
        assert repositories.tasks.get(task.id).status is TaskStatus.RUNNING
        assert len(repositories.attempts.list(task_id=task.id)) == 1
    finally:
        database.close()


def test_cancel_persists_scan_and_pending_task_state(tmp_path: Path) -> None:
    registry = _base_registry()
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.consumer"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).cancel(scan.id)

        assert status.scan.status is ScanStatus.CANCELED
        assert all(task.status is TaskStatus.CANCELED for task in status.tasks)
    finally:
        database.close()


def test_process_plugin_isolated_from_network_secrets_subprocess_and_host_writes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    external = tmp_path / "external" / "isolated"
    external.mkdir(parents=True)
    unrelated = ArtifactStore(tmp_path).put_bytes(b"not-an-input")
    (external / "plugin.yaml").write_text(
        """\
apiVersion: argus.security/v2
kind: detector
metadata:
  id: fixture.isolated
  version: 1.0.0
entrypoint: isolated_plugin:run
consumes:
  - capability: source.snapshot.v1
    required: true
produces:
  - capability: data.isolated.v1
    artifactType: data.isolated
    schemaVersion: "1.0"
runtime:
  isolation: process
  timeoutSeconds: 10
""",
        encoding="utf-8",
    )
    plugin_source = """\
import os
from pathlib import Path
import socket
import subprocess
from argus.execution.contracts import RuntimeOutput

def run(context, _inputs):
    unrelated = os.path.join(
        os.environ["ARGUS_PLUGIN_RUNS_ROOT"],
        "_data", "artifacts", "sha256", "__HASH__"[:2], "__HASH__", "payload",
    )
    denied = {}
    for name, operation in {
        "network": lambda: socket.create_connection(("127.0.0.1", 9)),
        "subprocess": lambda: subprocess.run(["echo", "denied"]),
        "write": lambda: Path("/tmp/argus-plugin-escape").write_text("denied"),
        "artifact": lambda: Path(unrelated).read_bytes(),
        "snapshot_list": lambda: list(Path(context.snapshot.materialized_path).iterdir()),
    }.items():
        try:
            operation()
        except PermissionError:
            denied[name] = True
        else:
            denied[name] = False
    return [RuntimeOutput(
        capability="data.isolated.v1",
        artifact_type="data.isolated",
        schema_version="1.0",
        media_type="application/json",
        json_value={
            "pid": os.getpid(),
            "secret_present": "ARGUS_LLM_API_KEY" in os.environ,
            "denied": denied,
        },
    )]
"""
    (external / "isolated_plugin.py").write_text(
        plugin_source.replace("__HASH__", unrelated.content_hash),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "must-not-cross-boundary")
    registry = PluginRegistry.discover(
        builtin_root=tmp_path / "none",
        external_roots=[tmp_path / "external"],
        allow_external=True,
    )
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        ["fixture.isolated"],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)
        assert status.scan.status is ScanStatus.COMPLETED
        artifact = next(
            item for item in repositories.artifacts.list(scan_id=scan.id) if "data.isolated.v1" in item.capabilities
        )
        value = json.loads(
            ArtifactStore(tmp_path).read_bytes(
                artifact.content_hash,
                expected_size=artifact.size_bytes,
            )
        )
        assert value["pid"] != os.getpid()
        assert value["secret_present"] is False
        assert value["denied"] == {
            "artifact": True,
            "network": True,
            "snapshot_list": True,
            "subprocess": True,
            "write": True,
        }
        assert not Path("/tmp/argus-plugin-escape").exists()
    finally:
        database.close()


def test_process_plugin_cannot_return_injected_secret_in_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    plugin_root = tmp_path / "trusted-plugin"
    plugin_root.mkdir()
    (plugin_root / "secret_plugin.py").write_text(
        """\
import os
from argus.execution.contracts import RuntimeOutput

def run(_context, _inputs):
    return [RuntimeOutput(
        capability="data.secret.v1",
        artifact_type="data.secret",
        schema_version="1.0",
        media_type="application/json",
        json_value={"safe": True},
        metadata={"diagnostic": os.environ["ARGUS_LLM_API_KEY"]},
    )]
""",
        encoding="utf-8",
    )
    spec = PluginSpec(
        id="fixture.secret-output",
        version="1.0.0",
        kind=PluginKind.DETECTOR,
        entrypoint="secret_plugin:run",
        produces=[
            CapabilityDeclaration(
                capability="data.secret.v1",
                artifact_type="data.secret",
                schema_version="1.0",
            )
        ],
        permissions=PermissionSpec(
            network=NetworkPermission.LLM,
            secrets=SecretsPermission.LLM,
        ),
        runtime=RuntimeSpec(isolation=IsolationMode.PROCESS, timeout_seconds=10),
    )
    registry = PluginRegistry()
    registry.register(
        spec,
        origin=PluginOrigin.BUILTIN,
        manifest_path=str(plugin_root / "plugin.yaml"),
    )
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "protected-secret")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "fixture")
    database, repositories, scan = _prepared_scan(
        tmp_path,
        registry,
        [spec.id],
    )
    try:
        status = LocalPlanExecutor(
            repositories,
            runs_root=tmp_path,
            registry=registry,
        ).run_ready_tasks(scan.id)

        assert status.scan.status is ScanStatus.FAILED
        task = next(item for item in status.tasks if item.plugin_id == spec.id)
        assert task.error_message is not None
        assert "protected-secret" not in task.error_message
        assert all(
            "data.secret.v1" not in artifact.capabilities for artifact in repositories.artifacts.list(scan_id=scan.id)
        )
    finally:
        database.close()
