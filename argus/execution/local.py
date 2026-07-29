"""Serial DB-backed TaskPlan executor with crash recovery."""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import shutil
import threading
from uuid import UUID

from argus.artifacts.store import ArtifactStore
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import (
    AttemptStatus,
    ReviewStatus,
    ScanStatus,
    TaskStatus,
)
from argus.domain.errors import ConflictError, InvalidTransitionError
from argus.domain.models import Artifact, Scan, Task, TaskAttempt, TaskPlan, utc_now
from argus.execution.contracts import (
    ExecutionStatus,
    RuntimeContext,
    RuntimeInput,
    RuntimeOutput,
)
from argus.execution.review_gate import ensure_review, gate_enabled
from argus.execution.runner import (
    PluginRunner,
    project_workspace_views,
    publish_outputs,
)
from argus.execution.state_machine import (
    all_terminal,
    has_required_failure,
    plan_tasks,
    promote_ready_tasks,
)
from argus.plugins.legacy_adapter import register_legacy_plugins
from argus.plugins.registry import PluginRegistry
from argus.security.redaction import safe_error_summary
from argus.orchestration.registry import discover_analyzers


class ExecutionDeadlockError(RuntimeError):
    pass


class _AttemptHeartbeat:
    def __init__(
        self,
        repositories: Repositories,
        attempt_id: UUID,
        *,
        interval_seconds: float,
    ) -> None:
        self.repositories = repositories
        self.attempt_id = attempt_id
        self.interval_seconds = max(interval_seconds, 0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"argus-heartbeat-{attempt_id}",
            daemon=True,
        )

    def __enter__(self) -> _AttemptHeartbeat:
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            attempt = self.repositories.attempts.get(self.attempt_id)
            if attempt.status is not AttemptStatus.RUNNING:
                return
            try:
                self.repositories.attempts.update(attempt.model_copy(update={"heartbeat_at": utc_now()}))
            except ConflictError:
                return


def build_execution_registry() -> PluginRegistry:
    registry = PluginRegistry.discover()
    register_legacy_plugins(registry, discover_analyzers())
    return registry


class LocalPlanExecutor:
    def __init__(
        self,
        repositories: Repositories,
        *,
        runs_root: str | Path = "runs",
        registry: PluginRegistry | None = None,
        stale_after: timedelta = timedelta(minutes=5),
    ) -> None:
        self.repositories = repositories
        self.services = ControlServices(repositories)
        self.events = EventService(repositories.events)
        self.runs_root = Path(runs_root).resolve()
        self.store = ArtifactStore(self.runs_root)
        self.registry = registry
        self.runner = PluginRunner(registry) if registry is not None else None
        self.stale_after = stale_after

    def prepare(self, plan: TaskPlan) -> None:
        scan = self.repositories.scans.get(plan.scan_id)
        if scan.plan_id != plan.id:
            raise ValueError(f"scan {scan.id} is linked to {scan.plan_id}, not plan {plan.id}")
        persisted = self.repositories.plans.get(plan.id)
        if persisted.plan_hash != plan.plan_hash:
            raise ValueError(f"persisted plan hash differs for {plan.id}")
        if scan.status is ScanStatus.PLANNING:
            self.services.scans.transition(scan.id, ScanStatus.READY)
        elif scan.status is not ScanStatus.READY:
            raise InvalidTransitionError(f"scan {scan.id} cannot be prepared from {scan.status.value}")
        tasks = plan_tasks(self.repositories, scan.id, plan.id)
        promote_ready_tasks(self.repositories, tasks)
        self.events.append(
            "execution.prepared",
            project_id=scan.project_id,
            scan_id=scan.id,
            payload={"plan_id": str(plan.id), "task_count": len(tasks)},
        )

    def get_status(self, scan_id: UUID) -> ExecutionStatus:
        scan = self.repositories.scans.get(scan_id)
        tasks = plan_tasks(self.repositories, scan.id, scan.plan_id) if scan.plan_id is not None else []
        open_reviews = [
            item.id for item in self.repositories.reviews.list(scan_id=scan.id) if item.status is ReviewStatus.OPEN
        ]
        return ExecutionStatus(
            scan=scan,
            tasks=tasks,
            open_review_ids=open_reviews,
        )

    def run_ready_tasks(self, scan_id: UUID) -> ExecutionStatus:
        scan = self.repositories.scans.get(scan_id)
        if scan.plan_id is None:
            raise ValueError(f"scan {scan.id} has no TaskPlan")
        plan_id = scan.plan_id
        if scan.status is ScanStatus.READY:
            scan = self.services.scans.transition(scan.id, ScanStatus.RUNNING)
        elif scan.status is ScanStatus.WAITING_REVIEW:
            return self.resume(scan.id)
        elif scan.status is not ScanStatus.RUNNING:
            return self.get_status(scan.id)

        self.recover_stale(scan.id)
        self.recover_retryable(scan.id)
        while True:
            scan = self.repositories.scans.get(scan.id)
            if scan.status is not ScanStatus.RUNNING:
                return self.get_status(scan.id)
            tasks = plan_tasks(self.repositories, scan.id, plan_id)
            tasks = promote_ready_tasks(self.repositories, tasks)
            if has_required_failure(tasks):
                self.services.scans.transition(
                    scan.id,
                    ScanStatus.FAILED,
                    error_code="TASK_FAILED",
                    error_message="one or more required plan tasks failed",
                )
                return self.get_status(scan.id)
            ready = sorted(
                (task for task in tasks if task.status is TaskStatus.READY),
                key=lambda item: (item.created_at, item.plugin_id, str(item.id)),
            )
            if ready:
                paused = self._claim_and_execute(scan, ready[0])
                if paused:
                    return self.get_status(scan.id)
                continue
            if any(task.status is TaskStatus.WAITING_REVIEW for task in tasks):
                if scan.status is ScanStatus.RUNNING:
                    self.services.scans.transition(scan.id, ScanStatus.WAITING_REVIEW)
                return self.get_status(scan.id)
            if all_terminal(tasks):
                scan = self.services.scans.transition(
                    scan.id,
                    ScanStatus.STATIC_COMPLETED,
                )
                self.services.scans.transition(scan.id, ScanStatus.COMPLETED)
                return self.get_status(scan.id)
            active = [
                f"{task.plugin_id}:{task.status.value}"
                for task in tasks
                if task.status
                not in {
                    TaskStatus.SUCCEEDED,
                    TaskStatus.FAILED,
                    TaskStatus.SKIPPED,
                    TaskStatus.CANCELED,
                }
            ]
            raise ExecutionDeadlockError(f"no runnable task for scan {scan.id}: {active}")

    def resume(self, scan_id: UUID) -> ExecutionStatus:
        scan = self.repositories.scans.get(scan_id)
        if scan.status is not ScanStatus.WAITING_REVIEW:
            if scan.status in {ScanStatus.READY, ScanStatus.RUNNING}:
                return self.run_ready_tasks(scan.id)
            return self.get_status(scan.id)
        if scan.plan_id is None:
            raise ValueError(f"scan {scan.id} has no TaskPlan")
        waiting = [
            task
            for task in plan_tasks(self.repositories, scan.id, scan.plan_id)
            if task.status is TaskStatus.WAITING_REVIEW
        ]
        if not waiting:
            raise ExecutionDeadlockError(f"scan {scan.id} is waiting for review without a gate task")
        task = waiting[0]
        inputs = self._resolve_inputs(scan, task)
        review = ensure_review(
            self.repositories,
            scan=scan,
            task=task,
            inputs=inputs,
        )
        if review.status is ReviewStatus.OPEN:
            return self.get_status(scan.id)
        attempts = self.repositories.attempts.list(task_id=task.id)
        if not attempts:
            raise ExecutionDeadlockError(f"review task {task.id} has no TaskAttempt")
        attempt = attempts[-1]
        if review.status is ReviewStatus.REJECTED:
            self.repositories.attempts.update(
                attempt.model_copy(
                    update={
                        "status": AttemptStatus.FAILED,
                        "finished_at": utc_now(),
                        "error_code": "REVIEW_REJECTED",
                        "error_message": review.reason,
                    }
                )
            )
            self.services.tasks.transition(
                task.id,
                TaskStatus.FAILED,
                error_code="REVIEW_REJECTED",
                error_message=review.reason,
            )
            self.services.scans.transition(
                scan.id,
                ScanStatus.FAILED,
                error_code="REVIEW_REJECTED",
                error_message=review.reason,
            )
            return self.get_status(scan.id)
        if review.status is not ReviewStatus.APPROVED:
            return self.get_status(scan.id)

        scan = self.services.scans.transition(scan.id, ScanStatus.RUNNING)
        attempt = self.repositories.attempts.update(
            attempt.model_copy(
                update={
                    "status": AttemptStatus.RUNNING,
                    "heartbeat_at": utc_now(),
                }
            )
        )
        task = self.services.tasks.transition(task.id, TaskStatus.RUNNING)
        self._execute_claimed(scan, task, attempt, inputs)
        return self.run_ready_tasks(scan.id)

    def cancel(self, scan_id: UUID) -> ExecutionStatus:
        scan = self.repositories.scans.get(scan_id)
        if scan.status in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELED,
        }:
            return self.get_status(scan.id)
        if scan.plan_id is not None:
            for task in plan_tasks(self.repositories, scan.id, scan.plan_id):
                if task.status in {
                    TaskStatus.PENDING,
                    TaskStatus.READY,
                    TaskStatus.RUNNING,
                    TaskStatus.WAITING_REVIEW,
                    TaskStatus.INTERRUPTED,
                    TaskStatus.FAILED_RETRYABLE,
                }:
                    self.services.tasks.transition(task.id, TaskStatus.CANCELED)
            for attempt in self.repositories.attempts.list(scan_id=scan.id):
                if attempt.status in {
                    AttemptStatus.RUNNING,
                    AttemptStatus.WAITING_REVIEW,
                }:
                    self.repositories.attempts.update(
                        attempt.model_copy(
                            update={
                                "status": AttemptStatus.CANCELED,
                                "finished_at": utc_now(),
                            }
                        )
                    )
            self.repositories.reviews.supersede_open_for_scan(scan.id)
        self.services.scans.transition(scan.id, ScanStatus.CANCELED)
        return self.get_status(scan.id)

    def recover_stale(self, scan_id: UUID) -> None:
        cutoff = utc_now() - self.stale_after
        for attempt in self.repositories.attempts.list(scan_id=scan_id):
            if attempt.status is not AttemptStatus.RUNNING:
                continue
            if attempt.heartbeat_at >= cutoff and self._pid_alive(attempt.worker_pid):
                continue
            task = self.repositories.tasks.get(attempt.task_id)
            if task.status is not TaskStatus.RUNNING:
                continue
            committed = self._committed_outputs(task, attempt)
            if committed is not None:
                scan = self.repositories.scans.get(task.scan_id)
                project_workspace_views(
                    self._runtime_context(scan, task, attempt),
                    committed,
                )
                self.repositories.attempts.update(
                    attempt.model_copy(
                        update={
                            "status": AttemptStatus.SUCCEEDED,
                            "heartbeat_at": utc_now(),
                            "finished_at": utc_now(),
                        }
                    )
                )
                self.services.tasks.transition(task.id, TaskStatus.SUCCEEDED)
                continue
            self.repositories.attempts.update(
                attempt.model_copy(
                    update={
                        "status": AttemptStatus.INTERRUPTED,
                        "heartbeat_at": utc_now(),
                        "finished_at": utc_now(),
                        "error_code": "STALE_HEARTBEAT",
                        "error_message": "worker heartbeat expired",
                    }
                )
            )
            task = self.services.tasks.transition(
                task.id,
                TaskStatus.INTERRUPTED,
                error_code="STALE_HEARTBEAT",
                error_message="worker heartbeat expired",
            )
            target = TaskStatus.READY if attempt.attempt_number < task.max_attempts else TaskStatus.FAILED
            if target is TaskStatus.FAILED:
                self.services.tasks.transition(
                    task.id,
                    target,
                    error_code="MAX_ATTEMPTS",
                    error_message="retry budget exhausted after interruption",
                )
            else:
                self.services.tasks.transition(task.id, target)

    def recover_retryable(self, scan_id: UUID) -> None:
        scan = self.repositories.scans.get(scan_id)
        if scan.plan_id is None:
            return
        for task in plan_tasks(self.repositories, scan.id, scan.plan_id):
            if task.status not in {
                TaskStatus.INTERRUPTED,
                TaskStatus.FAILED_RETRYABLE,
            }:
                continue
            attempts = self.repositories.attempts.list(task_id=task.id)
            attempt_number = attempts[-1].attempt_number if attempts else 0
            if attempt_number < task.max_attempts:
                self.services.tasks.transition(task.id, TaskStatus.READY)
            else:
                self.services.tasks.transition(
                    task.id,
                    TaskStatus.FAILED,
                    error_code="MAX_ATTEMPTS",
                    error_message="retry budget exhausted during recovery",
                )

    def _claim_and_execute(self, scan: Scan, task: Task) -> bool:
        inputs = self._resolve_inputs(scan, task)
        pending_attempt = TaskAttempt(
            scan_id=scan.id,
            task_id=task.id,
            attempt_number=self.repositories.attempts.next_number(task.id),
            plugin_id=task.plugin_id,
            plugin_version=task.plugin_version,
            input_artifact_ids=[item.artifact.id for item in inputs.values()],
            input_hashes={capability: item.artifact.content_hash for capability, item in inputs.items()},
            config_hash=task.config_hash,
            worker_pid=os.getpid(),
        )
        try:
            claimed, attempt = self.repositories.tasks.claim_with_attempt(
                task.id,
                pending_attempt,
            )
        except (ConflictError, InvalidTransitionError):
            return False
        committed = self._committed_outputs(claimed, attempt)
        if committed is not None:
            project_workspace_views(
                self._runtime_context(scan, claimed, attempt),
                committed,
            )
            self.repositories.attempts.update(
                attempt.model_copy(
                    update={
                        "status": AttemptStatus.SUCCEEDED,
                        "heartbeat_at": utc_now(),
                        "finished_at": utc_now(),
                    }
                )
            )
            self.services.tasks.transition(
                claimed.id,
                TaskStatus.SUCCEEDED,
            )
            return False
        if claimed.kind != "review_gate" and self._restore_cached_outputs(
            scan,
            claimed,
            attempt,
        ):
            return False
        if claimed.kind == "review_gate" and gate_enabled(scan, claimed):
            review = ensure_review(
                self.repositories,
                scan=scan,
                task=claimed,
                inputs=inputs,
            )
            if review.status is ReviewStatus.OPEN:
                self.repositories.attempts.update(
                    attempt.model_copy(
                        update={
                            "status": AttemptStatus.WAITING_REVIEW,
                            "heartbeat_at": utc_now(),
                        }
                    )
                )
                self.services.tasks.transition(
                    claimed.id,
                    TaskStatus.WAITING_REVIEW,
                )
                self.services.scans.transition(
                    scan.id,
                    ScanStatus.WAITING_REVIEW,
                )
                self.events.append(
                    "review.opened",
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    task_id=claimed.id,
                    payload={
                        "review_id": str(review.id),
                        "subject_hash": review.subject_hash,
                    },
                )
                return True
        self._execute_claimed(scan, claimed, attempt, inputs)
        return False

    def _execute_claimed(
        self,
        scan: Scan,
        task: Task,
        attempt: TaskAttempt,
        inputs: dict[str, RuntimeInput],
    ) -> None:
        context = self._runtime_context(scan, task, attempt)
        attempt = self.repositories.attempts.update(attempt.model_copy(update={"heartbeat_at": utc_now()}))
        try:
            interval = min(
                max(self.stale_after.total_seconds() / 3, 0.1),
                30.0,
            )
            with _AttemptHeartbeat(
                self.repositories,
                attempt.id,
                interval_seconds=interval,
            ):
                outputs = self._plugin_runner().run(context, inputs)
                publish_outputs(context, outputs)
        except Exception as exc:
            self._record_failure(task, attempt, exc)
            return
        finally:
            shutil.rmtree(context.temp_dir, ignore_errors=True)
        self.repositories.attempts.update(
            attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "heartbeat_at": utc_now(),
                    "finished_at": utc_now(),
                }
            )
        )
        self.services.tasks.transition(task.id, TaskStatus.SUCCEEDED)
        self.events.append(
            "task.succeeded",
            project_id=scan.project_id,
            scan_id=scan.id,
            task_id=task.id,
            payload={
                "attempt_id": str(attempt.id),
                "plugin_id": task.plugin_id,
            },
        )

    def _record_failure(
        self,
        task: Task,
        attempt: TaskAttempt,
        exc: Exception,
    ) -> None:
        error_message = safe_error_summary(exc)
        retryable = attempt.attempt_number < task.max_attempts
        attempt_status = AttemptStatus.FAILED_RETRYABLE if retryable else AttemptStatus.FAILED
        self.repositories.attempts.update(
            attempt.model_copy(
                update={
                    "status": attempt_status,
                    "heartbeat_at": utc_now(),
                    "finished_at": utc_now(),
                    "error_code": type(exc).__name__,
                    "error_message": error_message,
                }
            )
        )
        task_status = TaskStatus.FAILED_RETRYABLE if retryable else TaskStatus.FAILED
        task = self.services.tasks.transition(
            task.id,
            task_status,
            error_code=type(exc).__name__,
            error_message=error_message,
        )
        scan = self.repositories.scans.get(task.scan_id)
        self.events.append(
            "task.failed_retryable" if retryable else "task.failed",
            project_id=scan.project_id,
            scan_id=scan.id,
            task_id=task.id,
            payload={
                "attempt_id": str(attempt.id),
                "error_code": type(exc).__name__,
                "error_message": error_message,
            },
        )
        if retryable:
            self.services.tasks.transition(task.id, TaskStatus.READY)

    def _resolve_inputs(
        self,
        scan: Scan,
        task: Task,
    ) -> dict[str, RuntimeInput]:
        artifacts = self.repositories.artifacts.list(scan_id=scan.id)
        dependency_ids = set(task.depends_on)
        inputs: dict[str, RuntimeInput] = {}
        for capability in [
            *task.required_capabilities,
            *task.optional_capabilities,
        ]:
            candidates = [
                artifact
                for artifact in artifacts
                if capability in artifact.capabilities
                and (artifact.task_id in dependency_ids or capability == "source.snapshot.v1")
            ]
            if not candidates:
                if capability in task.optional_capabilities:
                    continue
                raise ExecutionDeadlockError(f"task {task.plugin_id!r} has no Artifact for {capability!r}")
            artifact = candidates[-1]
            inputs[capability] = RuntimeInput(
                capability=capability,
                artifact=artifact,
                payload=self.store.read_bytes(
                    artifact.content_hash,
                    expected_size=artifact.size_bytes,
                ),
            )
        return inputs

    def _committed_outputs(
        self,
        task: Task,
        attempt: TaskAttempt,
    ) -> list[Artifact] | None:
        artifacts = [
            artifact
            for artifact in self.repositories.artifacts.list(scan_id=task.scan_id)
            if artifact.task_id == task.id
            and artifact.producer_plugin_version == task.plugin_version
            and artifact.metadata.get("config_hash") == task.config_hash
            and artifact.metadata.get("input_hashes") == attempt.input_hashes
        ]
        capabilities = {capability for artifact in artifacts for capability in artifact.capabilities}
        return artifacts if capabilities >= set(task.expected_capabilities) else None

    def _restore_cached_outputs(
        self,
        scan: Scan,
        task: Task,
        attempt: TaskAttempt,
    ) -> bool:
        candidates = [
            artifact
            for artifact in self.repositories.artifacts.find_cached_outputs(
                plugin_id=task.plugin_id,
                plugin_version=task.plugin_version,
                task_cache_key=task.cache_key,
            )
            if artifact.metadata.get("config_hash") == task.config_hash
            and artifact.metadata.get("input_hashes") == attempt.input_hashes
            and artifact.scan_id != scan.id
            and artifact.metadata.get("cache_scope") != "scan"
        ]
        selected: dict[str, Artifact] = {}
        for artifact in candidates:
            for capability in artifact.capabilities:
                if capability in task.expected_capabilities and capability not in selected:
                    selected[capability] = artifact
        if set(selected) != set(task.expected_capabilities):
            return False

        context = self._runtime_context(scan, task, attempt)
        outputs = [
            RuntimeOutput(
                capability=capability,
                artifact_type=selected[capability].artifact_type,
                schema_version=selected[capability].schema_version,
                media_type=selected[capability].media_type,
                payload=self.store.read_bytes(
                    selected[capability].content_hash,
                    expected_size=selected[capability].size_bytes,
                ),
                metadata={
                    "reused_artifact_id": str(selected[capability].id),
                    **(
                        {"workspace_view": selected[capability].metadata["workspace_view"]}
                        if "workspace_view" in selected[capability].metadata
                        else {}
                    ),
                },
            )
            for capability in task.expected_capabilities
        ]
        publish_outputs(context, outputs)
        self.repositories.attempts.update(
            attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "heartbeat_at": utc_now(),
                    "finished_at": utc_now(),
                }
            )
        )
        self.services.tasks.transition(task.id, TaskStatus.SUCCEEDED)
        self.events.append(
            "task.cache_reused",
            project_id=scan.project_id,
            scan_id=scan.id,
            task_id=task.id,
            payload={"attempt_id": str(attempt.id)},
        )
        return True

    def _runtime_context(
        self,
        scan: Scan,
        task: Task,
        attempt: TaskAttempt,
    ) -> RuntimeContext:
        temp_dir = self.runs_root / "_data" / "task-tmp" / str(attempt.id)
        temp_dir.mkdir(parents=True, exist_ok=True)
        return RuntimeContext(
            scan=scan,
            snapshot=self.repositories.snapshots.get(scan.snapshot_id),
            task=task,
            repositories=self.repositories,
            artifact_store=self.store,
            runs_root=self.runs_root,
            workspace=self._workspace(scan),
            attempt_id=attempt.id,
            input_hashes=attempt.input_hashes,
            temp_dir=temp_dir,
        )

    def _plugin_runner(self) -> PluginRunner:
        if self.runner is None:
            self.registry = build_execution_registry()
            self.runner = PluginRunner(self.registry)
        return self.runner

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @staticmethod
    def _workspace(scan: Scan) -> str:
        execution = scan.config.get("execution")
        if isinstance(execution, dict):
            workspace = execution.get("workspace")
            if isinstance(workspace, str) and workspace:
                return workspace
        return str(scan.id)
