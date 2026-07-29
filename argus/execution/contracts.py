"""Execution backend and plugin runtime contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from uuid import UUID

from pydantic import JsonValue

from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories
from argus.domain.models import (
    Artifact,
    Scan,
    SourceSnapshot,
    StaticFindingV2,
    Task,
    TaskPlan,
)


@dataclass(frozen=True)
class RuntimeContext:
    scan: Scan
    snapshot: SourceSnapshot
    task: Task
    repositories: Repositories
    artifact_store: ArtifactStore
    runs_root: Path
    workspace: str
    attempt_id: UUID
    input_hashes: dict[str, str]
    temp_dir: Path


@dataclass(frozen=True)
class RuntimeInput:
    capability: str
    artifact: Artifact
    payload: bytes


@dataclass(frozen=True)
class RuntimeOutput:
    capability: str
    artifact_type: str
    schema_version: str
    media_type: str
    payload: bytes | None = None
    source_path: Path | None = None
    json_value: JsonValue | None = None
    metadata: dict[str, JsonValue] = field(default_factory=dict)
    cleanup_source: bool = False
    artifact_id: UUID | None = None
    static_findings: tuple[StaticFindingV2, ...] = ()


class PluginRuntime(Protocol):
    def __call__(
        self,
        context: RuntimeContext,
        inputs: dict[str, RuntimeInput],
    ) -> list[RuntimeOutput]: ...


@dataclass(frozen=True)
class ExecutionStatus:
    scan: Scan
    tasks: list[Task]
    open_review_ids: list[UUID]


class ExecutionBackend(Protocol):
    def prepare(self, plan: TaskPlan) -> None: ...

    def run_ready_tasks(self, scan_id: UUID) -> ExecutionStatus: ...

    def resume(self, scan_id: UUID) -> ExecutionStatus: ...

    def cancel(self, scan_id: UUID) -> ExecutionStatus: ...

    def get_status(self, scan_id: UUID) -> ExecutionStatus: ...
