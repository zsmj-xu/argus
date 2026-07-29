"""Operational performance baselines derived from persisted V2 records."""

from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories


class PerformanceBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: UUID
    snapshot_seconds: float | None
    graph_task_seconds: float
    candidate_count: int
    llm_call_count: int
    llm_total_tokens: int
    task_attempt_count: int
    task_resume_count: int
    control_query_ms: float
    web_graph_query_ms: float | None


def collect_performance_baseline(
    repositories: Repositories,
    scan_id: UUID,
    *,
    runs_root: str | Path = "runs",
) -> PerformanceBaseline:
    started = perf_counter()
    scan = repositories.scans.get(scan_id)
    tasks = repositories.tasks.list(scan_id=scan_id)
    attempts = repositories.attempts.list(scan_id=scan_id)
    artifacts = repositories.artifacts.list(scan_id=scan_id)
    control_query_ms = (perf_counter() - started) * 1000

    snapshot_durations = [
        max(0.0, (task.finished_at - task.started_at).total_seconds())
        for task in tasks
        if task.kind == "snapshot" and task.started_at is not None and task.finished_at is not None
    ]
    snapshot_seconds = sum(snapshot_durations) if snapshot_durations else None
    graph_task_seconds = sum(
        max(0.0, (task.finished_at - task.started_at).total_seconds())
        for task in tasks
        if task.started_at is not None
        and task.finished_at is not None
        and (
            "graph" in task.plugin_id
            or any(capability.startswith("graph.") for capability in task.expected_capabilities)
        )
    )
    store = ArtifactStore(runs_root)
    candidate_count = 0
    for artifact in artifacts:
        if artifact.artifact_type != "candidate.index.v1":
            continue
        value = store.read_json(
            artifact.content_hash,
            expected_size=artifact.size_bytes,
        )
        if isinstance(value, list):
            candidate_count += len(value)

    workspace = str(scan_id)
    execution = scan.config.get("execution")
    if isinstance(execution, dict):
        configured = execution.get("workspace")
        if isinstance(configured, str) and configured:
            workspace = configured
    audit_path = Path(runs_root) / workspace / "audit" / "llm.jsonl"
    llm_calls = 0
    llm_tokens = 0
    if audit_path.is_file():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            llm_calls += 1
            usage = record.get("usage")
            if isinstance(usage, dict):
                total = usage.get("total_tokens")
                if isinstance(total, int) and total >= 0:
                    llm_tokens += total

    graph_query_ms: float | None = None
    if any("security.graph.v1" in artifact.capabilities for artifact in artifacts):
        from argus.security_ir.service import SecurityGraphService

        graph_started = perf_counter()
        SecurityGraphService(repositories, store).find_nodes(
            scan_id,
            max_nodes=1,
        )
        graph_query_ms = round((perf_counter() - graph_started) * 1000, 3)

    return PerformanceBaseline(
        scan_id=scan_id,
        snapshot_seconds=snapshot_seconds,
        graph_task_seconds=graph_task_seconds,
        candidate_count=candidate_count,
        llm_call_count=llm_calls,
        llm_total_tokens=llm_tokens,
        task_attempt_count=len(attempts),
        task_resume_count=max(
            0,
            len(attempts) - len({attempt.task_id for attempt in attempts}),
        ),
        control_query_ms=round(control_query_ms, 3),
        web_graph_query_ms=graph_query_ms,
    )
