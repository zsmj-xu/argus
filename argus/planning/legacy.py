"""Compile and persist a V2 plan alongside an unchanged V1 execution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import JsonValue, TypeAdapter

from argus.contracts import Analyzer
from argus.control.db import Database, control_db_path
from argus.control.repositories import Repositories
from argus.planning.persistence import TaskPlanPersistence
from argus.planning.planner import PlanningRequest, TaskOrdering, TaskPlanner
from argus.plugins.legacy_adapter import (
    SOURCE_CAPABILITY,
    legacy_analyzer_order,
    legacy_selected_plugin_ids,
    register_legacy_plugins,
)
from argus.plugins.registry import PluginRegistry
from argus.snapshots.compat import LegacyControlLink

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])


def compile_legacy_task_plan(
    *,
    link: LegacyControlLink,
    config: Mapping[str, Any],
    analyzers: Mapping[str, Analyzer],
    runs_root: str | Path = "runs",
) -> None:
    registry = PluginRegistry.discover()
    analyzer_ids = register_legacy_plugins(registry, analyzers)
    graph_config: dict[str, Any] = {}
    configured_graph = config.get("codegraph", {})
    if isinstance(configured_graph, dict):
        graph_config.update(configured_graph)
    if link.graph_provider_version is not None:
        graph_config["provider_binary_identity"] = link.graph_provider_version
    selected = legacy_selected_plugin_ids(config, analyzer_ids)
    normalized_config = _JSON_OBJECT.validate_python(dict(config))
    plugin_config = {plugin_id: normalized_config for plugin_id in selected}
    plugin_config["graph.codegraph"] = _JSON_OBJECT.validate_python(graph_config)
    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=link.scan_id,
            selected_plugin_ids=selected,
            initial_capabilities={SOURCE_CAPABILITY},
            plugin_config=plugin_config,
            ordering_constraints=[
                TaskOrdering(
                    before_plugin_id=before,
                    after_plugin_id=after,
                )
                for before, after in legacy_analyzer_order(config, analyzer_ids)
            ],
        )
    )
    database = Database(control_db_path(runs_root))
    try:
        TaskPlanPersistence(
            Repositories(database),
            runs_root=runs_root,
        ).persist(plan, snapshot_id=link.snapshot_id)
    finally:
        database.close()
