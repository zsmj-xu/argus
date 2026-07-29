from __future__ import annotations

from uuid import uuid4

from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.planning.planner import PlanningRequest, TaskPlanner
from argus.plugins.legacy_adapter import (
    BUSINESS_FLOW_SECURITY_IR_PLUGIN,
    SOURCE_CAPABILITY,
    legacy_selected_plugin_ids,
    register_legacy_plugins,
)
from argus.plugins.registry import PluginRegistry


class FakeBusinessFlowAnalyzer:
    name = "business-flow"
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    def run(self, _ctx: AnalysisContext) -> AnalyzerResult:
        return {
            "analyzer": self.name,
            "findings": [],
            "enrichment": {},
        }


def test_business_flow_security_ir_is_compiled_as_capability_dependencies() -> None:
    registry = PluginRegistry.discover()
    analyzer_ids = register_legacy_plugins(
        registry,
        {"business-flow": FakeBusinessFlowAnalyzer()},
    )
    selected = legacy_selected_plugin_ids(
        {
            "analyzers": {
                "enrichment": ["business-flow"],
                "vuln": [],
            }
        },
        analyzer_ids,
    )

    plan = TaskPlanner(registry).compile(
        PlanningRequest(
            scan_id=uuid4(),
            selected_plugin_ids=selected,
            initial_capabilities={SOURCE_CAPABILITY},
        )
    )

    by_plugin = {task.plugin_id: task for task in plan.tasks}
    adapter = by_plugin[BUSINESS_FLOW_SECURITY_IR_PLUGIN]
    dependencies = {task.plugin_id for task in plan.tasks if task.id in adapter.depends_on}
    assert dependencies == {
        "graph.codegraph",
        "legacy.analyzer.business-flow",
    }
    assert set(adapter.expected_capabilities) == {
        "security.routes.v1",
        "security.business-flow.v1",
        "security.authorization.v1",
        "security.resources.v1",
        "security.graph.v1",
    }
