"""Canonical TaskPlan serialization and hashing."""

from __future__ import annotations

from typing import Any

from argus.domain.hashing import sha256_digest
from argus.domain.models import PlannedTask, TaskPlan


def task_payload(task: PlannedTask) -> dict[str, Any]:
    return {
        "id": str(task.id),
        "plugin_id": task.plugin_id,
        "plugin_version": task.plugin_version,
        "kind": task.kind.value,
        "depends_on": [str(item) for item in task.depends_on],
        "required_capabilities": task.required_capabilities,
        "optional_capabilities": task.optional_capabilities,
        "expected_capabilities": task.expected_capabilities,
        "config_hash": task.config_hash,
        "cache_key": task.cache_key,
        "continue_on_failure": task.continue_on_failure,
        "max_attempts": task.max_attempts,
    }


def plan_hash_payload(scan_id: object, tasks: list[PlannedTask]) -> dict[str, Any]:
    return {"scan_id": str(scan_id), "tasks": [task_payload(task) for task in tasks]}


def calculate_plan_hash(scan_id: object, tasks: list[PlannedTask]) -> str:
    return sha256_digest(plan_hash_payload(scan_id, tasks))


def serialize_plan(plan: TaskPlan) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "id": str(plan.id),
        "scan_id": str(plan.scan_id),
        "plan_hash": plan.plan_hash,
        "created_at": plan.created_at.isoformat(),
        "tasks": [task_payload(task) for task in plan.tasks],
    }
