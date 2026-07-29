from __future__ import annotations

import pytest

from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.plugins.legacy_adapter import (
    BUSINESS_FLOW_SECURITY_IR_PLUGIN,
    ENRICHMENT_REVIEWED,
    UnknownLegacyRequirementError,
    adapt_analyzer,
    legacy_selected_plugin_ids,
    register_legacy_plugins,
)
from argus.plugins.registry import PluginRegistry


class FakeAnalyzer:
    def __init__(self, name: str, phase: Phase, requires: list[str]) -> None:
        self.name = name
        self.phase = phase
        self.requires = requires

    def run(self, _ctx: AnalysisContext) -> AnalyzerResult:
        return {"analyzer": self.name, "findings": [], "enrichment": {}}


def test_legacy_requires_mapping_is_confined_to_adapter() -> None:
    analyzer = FakeAnalyzer(
        "business-logic",
        Phase.VULN_ANALYSIS,
        ["enriched-graph"],
    )

    spec = adapt_analyzer(analyzer)

    assert [item.capability for item in spec.consumes] == [
        "code.graph.codegraph.v1",
        ENRICHMENT_REVIEWED,
    ]
    assert spec.produces[0].capability == "legacy.findings.business-logic.v1"


def test_unknown_legacy_requirement_fails_closed() -> None:
    analyzer = FakeAnalyzer("future", Phase.VULN_ANALYSIS, ["unknown-legacy-key"])

    with pytest.raises(UnknownLegacyRequirementError, match="unknown-legacy-key"):
        adapt_analyzer(analyzer)


def test_adapter_builds_dynamic_aggregate_inputs() -> None:
    registry = PluginRegistry.discover()
    register_legacy_plugins(
        registry,
        {
            "flow": FakeAnalyzer("flow", Phase.ENRICHMENT, []),
            "idor": FakeAnalyzer("idor", Phase.VULN_ANALYSIS, []),
        },
    )

    enrichment = registry.require("legacy.enrichment.aggregate").spec
    findings = registry.require("legacy.findings.aggregate").spec
    assert [item.capability for item in enrichment.optional_consumes] == ["legacy.enrichment.flow.v1"]
    assert [item.capability for item in findings.optional_consumes] == [
        "legacy.findings.idor.v1",
        "finding.static.injection.v2",
        "finding.static.authorization.v2",
    ]


def test_business_flow_selection_adds_security_ir_adapter_without_planner_special_case() -> None:
    selected = legacy_selected_plugin_ids(
        {
            "analyzers": {
                "enrichment": ["business-flow"],
                "vuln": [],
            }
        },
        {"business-flow": "legacy.analyzer.business-flow"},
    )

    assert BUSINESS_FLOW_SECURITY_IR_PLUGIN in selected
    spec = PluginRegistry.discover().require(BUSINESS_FLOW_SECURITY_IR_PLUGIN).spec
    assert [item.capability for item in spec.consumes] == [
        "legacy.enrichment.business-flow.v1",
        "code.graph.codegraph.v1",
    ]
    assert "security.graph.v1" in spec.produced_capabilities
