"""Deterministic task readiness and terminal-state rules."""

from __future__ import annotations

from uuid import UUID

from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.domain.enums import TaskStatus
from argus.domain.models import Task

_DEPENDENCY_TERMINAL = {
    TaskStatus.SUCCEEDED,
    TaskStatus.FAILED,
    TaskStatus.SKIPPED,
    TaskStatus.CANCELED,
}


def plan_tasks(
    repositories: Repositories,
    scan_id: UUID,
    plan_id: UUID,
) -> list[Task]:
    return [
        task
        for task in repositories.tasks.list(scan_id=scan_id)
        if task.plan_id == plan_id and task.plugin_id != "core.plan-compiler"
    ]


def promote_ready_tasks(
    repositories: Repositories,
    tasks: list[Task],
) -> list[Task]:
    services = ControlServices(repositories)
    by_id = {task.id: task for task in tasks}
    changed = False
    for task in tasks:
        if task.status is not TaskStatus.PENDING:
            continue
        dependencies = [by_id[item] for item in task.depends_on if item in by_id]
        if len(dependencies) != len(task.depends_on):
            continue
        if any(item.status not in _DEPENDENCY_TERMINAL for item in dependencies):
            continue
        required_blocked = any(
            item.status is not TaskStatus.SUCCEEDED
            and bool(set(item.expected_capabilities) & set(task.required_capabilities))
            for item in dependencies
        )
        target = TaskStatus.SKIPPED if required_blocked else TaskStatus.READY
        services.tasks.transition(task.id, target)
        changed = True
    if not changed:
        return tasks
    scan_id = tasks[0].scan_id if tasks else None
    if scan_id is None:
        return tasks
    plan_id = tasks[0].plan_id
    return [
        task
        for task in repositories.tasks.list(scan_id=scan_id)
        if task.plan_id == plan_id and task.plugin_id != "core.plan-compiler"
    ]


def has_required_failure(tasks: list[Task]) -> bool:
    return any(task.status is TaskStatus.FAILED and not task.continue_on_failure for task in tasks)


def all_terminal(tasks: list[Task]) -> bool:
    return all(task.status in _DEPENDENCY_TERMINAL for task in tasks)
