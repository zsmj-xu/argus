"""Compile selected plugins and capabilities into a deterministic DAG."""

from __future__ import annotations

from collections import defaultdict
from typing import cast
from uuid import UUID, uuid5

from packaging.version import Version
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from argus.domain.hashing import CanonicalValue, sha256_digest
from argus.domain.models import PlannedTask, TaskPlan
from argus.planning.capabilities import resolve_producer
from argus.planning.serialization import calculate_plan_hash
from argus.planning.validation import (
    CircularDependencyError,
    PlanningConfigError,
    UnknownPluginError,
)
from argus.plugins.registry import PluginRegistry, RegisteredPlugin


class PlanningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: UUID
    selected_plugin_ids: list[str]
    initial_capabilities: set[str] = Field(default_factory=set)
    provider_choices: dict[str, str] = Field(default_factory=dict)
    plugin_config: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    ordering_constraints: list[TaskOrdering] = Field(default_factory=list)


class TaskOrdering(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    before_plugin_id: str
    after_plugin_id: str


class TaskPlanner:
    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry

    def compile(self, request: PlanningRequest) -> TaskPlan:
        selected: dict[str, RegisteredPlugin] = {}
        for plugin_id in request.selected_plugin_ids:
            plugin = self.registry.get(plugin_id)
            if plugin is None:
                raise UnknownPluginError(f"unknown selected plugin: {plugin_id!r}")
            selected[plugin_id] = plugin

        dependencies: dict[str, set[str]] = defaultdict(set)
        resolving: list[str] = []

        def add_plugin(plugin: RegisteredPlugin) -> None:
            plugin_id = plugin.spec.id
            selected[plugin_id] = plugin
            if plugin_id in resolving:
                cycle_start = resolving.index(plugin_id)
                path = resolving[cycle_start:] + [plugin_id]
                raise CircularDependencyError(f"plugin dependency cycle: {' -> '.join(path)}")
            resolving.append(plugin_id)
            for requirement in plugin.spec.consumes:
                capability = requirement.capability
                if capability in request.initial_capabilities:
                    continue
                producer = resolve_producer(
                    capability,
                    registry=self.registry,
                    provider_choices=request.provider_choices,
                )
                dependencies[plugin_id].add(producer.spec.id)
                add_plugin(producer)
            resolving.pop()

        for plugin in list(selected.values()):
            add_plugin(plugin)

        for constraint in request.ordering_constraints:
            before = constraint.before_plugin_id
            after = constraint.after_plugin_id
            if before in selected and after in selected:
                dependencies[after].add(before)

        # Optional capabilities never pull a producer into the plan. If a selected
        # producer exists, however, preserve its data dependency.
        for plugin in selected.values():
            for requirement in plugin.spec.optional_consumes:
                producers = [
                    item for item in selected.values() if requirement.capability in item.spec.produced_capabilities
                ]
                configured = request.provider_choices.get(requirement.capability)
                if configured is not None:
                    producers = [item for item in producers if item.spec.id == configured]
                if len(producers) == 1:
                    dependencies[plugin.spec.id].add(producers[0].spec.id)

        ordered_ids = self._topological_order(selected, dependencies)
        task_ids: dict[str, UUID] = {}
        config_hashes: dict[str, str] = {}
        for plugin_id in ordered_ids:
            config = request.plugin_config.get(plugin_id, {})
            if not isinstance(config, dict):
                raise PlanningConfigError(f"configuration for plugin {plugin_id!r} must be an object")
            config_hashes[plugin_id] = sha256_digest(config)
            spec = selected[plugin_id].spec
            task_ids[plugin_id] = uuid5(
                request.scan_id,
                f"{spec.id}@{spec.version}:{config_hashes[plugin_id]}",
            )

        tasks: list[PlannedTask] = []
        for plugin_id in ordered_ids:
            spec = selected[plugin_id].spec
            dependency_ids = sorted(
                (task_ids[item] for item in dependencies[plugin_id]),
                key=str,
            )
            optional_inputs: set[str] = set()
            for optional in spec.optional_consumes:
                if any(
                    optional.capability in selected[dependency].spec.produced_capabilities
                    for dependency in dependencies[plugin_id]
                ):
                    optional_inputs.add(optional.capability)
            required = sorted(item.capability for item in spec.consumes)
            expected = sorted(item.capability for item in spec.produces if not item.supplemental)
            tasks.append(
                PlannedTask(
                    id=task_ids[plugin_id],
                    plugin_id=plugin_id,
                    plugin_version=spec.version,
                    kind=spec.kind,
                    depends_on=dependency_ids,
                    required_capabilities=required,
                    optional_capabilities=sorted(optional_inputs),
                    expected_capabilities=expected,
                    config_hash=config_hashes[plugin_id],
                    cache_key=sha256_digest(
                        cast(
                            CanonicalValue,
                            {
                                "plugin_id": plugin_id,
                                "plugin_version": spec.version,
                                "config_hash": config_hashes[plugin_id],
                                "dependencies": [
                                    {
                                        "plugin_id": dependency,
                                        "plugin_version": selected[dependency].spec.version,
                                        "config_hash": config_hashes[dependency],
                                    }
                                    for dependency in sorted(dependencies[plugin_id])
                                ],
                                "initial_capabilities": sorted(set(required) & request.initial_capabilities),
                            },
                        )
                    ),
                    continue_on_failure=spec.continue_on_failure,
                    max_attempts=spec.max_attempts,
                )
            )
        plan_hash = calculate_plan_hash(request.scan_id, tasks)
        return TaskPlan(
            id=uuid5(request.scan_id, plan_hash),
            scan_id=request.scan_id,
            tasks=tasks,
            plan_hash=plan_hash,
        )

    @staticmethod
    def _topological_order(
        selected: dict[str, RegisteredPlugin],
        dependencies: dict[str, set[str]],
    ) -> list[str]:
        dependants: dict[str, set[str]] = defaultdict(set)
        indegree = {plugin_id: len(dependencies[plugin_id]) for plugin_id in selected}
        for plugin_id, requirements in dependencies.items():
            for requirement in requirements:
                dependants[requirement].add(plugin_id)

        def key(item: str) -> tuple[str, Version]:
            return item, Version(selected[item].spec.version)

        ready = sorted(
            (plugin_id for plugin_id, degree in indegree.items() if degree == 0),
            key=key,
        )
        ordered: list[str] = []
        while ready:
            layer = ready
            ready = []
            for plugin_id in layer:
                ordered.append(plugin_id)
            for plugin_id in layer:
                for dependant in sorted(dependants[plugin_id], key=key):
                    indegree[dependant] -= 1
                    if indegree[dependant] == 0:
                        ready.append(dependant)
            ready.sort(key=key)
        if len(ordered) != len(selected):
            remaining = sorted(set(selected) - set(ordered))
            raise CircularDependencyError(f"plugin dependency cycle involves: {', '.join(remaining)}")
        return ordered
