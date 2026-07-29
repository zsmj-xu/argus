from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.detection.comparison import finding_comparison_runtime
from argus.domain.models import Artifact
from argus.execution.contracts import RuntimeInput
from argus.planning.planner import PlanningRequest, TaskPlanner
from argus.plugins.legacy_adapter import (
    SOURCE_CAPABILITY,
    legacy_selected_plugin_ids,
    register_legacy_plugins,
)
from argus.plugins.legacy_runtime import legacy_findings_aggregate_runtime
from argus.plugins.registry import PluginRegistry

SHA = "b" * 64


class FakeAnalyzer:
    def __init__(self, name: str, phase: Phase) -> None:
        self.name = name
        self.phase = phase
        self.requires = [] if phase is Phase.ENRICHMENT else ["enriched-graph"]

    def run(self, _context: AnalysisContext) -> AnalyzerResult:
        return {
            "analyzer": self.name,
            "findings": [],
            "enrichment": {},
        }


def _input(capability: str, records: list[dict[str, object]]) -> RuntimeInput:
    artifact = Artifact(
        scan_id=uuid4(),
        snapshot_id=uuid4(),
        task_id=uuid4(),
        artifact_type=capability,
        schema_version="1.0",
        capabilities=[capability],
        producer_plugin_id="fixture",
        producer_plugin_version="1.0.0",
        media_type="application/json",
        content_hash=SHA,
        size_bytes=2,
        storage_uri="/fixture",
    )
    return RuntimeInput(
        capability=capability,
        artifact=artifact,
        payload=json.dumps(records).encode(),
    )


def test_analysis_modes_select_legacy_v2_or_side_by_side_detectors() -> None:
    analyzer_ids = {
        "injection": "legacy.analyzer.injection",
        "authz": "legacy.analyzer.authz",
    }
    base = {"analyzers": {"enrichment": [], "vuln": ["injection", "authz"]}}

    legacy = legacy_selected_plugin_ids({**base, "analysisMode": "legacy"}, analyzer_ids)
    v2 = legacy_selected_plugin_ids({**base, "analysisMode": "v2"}, analyzer_ids)
    compare = legacy_selected_plugin_ids({**base, "analysisMode": "compare"}, analyzer_ids)

    assert "legacy.analyzer.injection" in legacy
    assert "detector.injection" not in legacy
    assert "detector.injection" in v2
    assert "legacy.analyzer.injection" not in v2
    assert {
        "legacy.analyzer.injection",
        "detector.injection",
        "comparison.injection",
        "legacy.analyzer.authz",
        "detector.authorization",
        "comparison.authorization",
    }.issubset(compare)


def test_compare_artifact_is_explicitly_side_channel() -> None:
    legacy_capability = "legacy.findings.injection.v1"
    v2_capability = "finding.static.injection.v2"
    location = {"file": "app.py", "line": 10, "node_id": "cg-handler"}
    inputs = {
        legacy_capability: _input(
            legacy_capability,
            [{"id": "legacy-1", "title": "Legacy title", "locations": [location]}],
        ),
        v2_capability: _input(
            v2_capability,
            [
                {
                    "id": "v2-1",
                    "title": "V2 title",
                    "fingerprint": SHA,
                    "locations": [location],
                },
                {
                    "id": "v2-2",
                    "title": "V2 only",
                    "fingerprint": "c" * 64,
                    "locations": [{"file": "other.py", "line": 2, "node_id": "cg-other"}],
                },
            ],
        ),
    }

    outputs = finding_comparison_runtime(
        SimpleNamespace(task=SimpleNamespace(plugin_id="comparison.injection")),  # type: ignore[arg-type]
        inputs,
    )
    payload = outputs[0].json_value

    assert isinstance(payload, dict)
    assert payload["affects_main_report"] is False
    assert payload["counts"] == {
        "legacy": 1,
        "v2": 2,
        "matched": 1,
        "legacy_only": 0,
        "v2_only": 1,
    }


def test_compare_mode_main_findings_projection_uses_v2_arm_only() -> None:
    legacy_capability = "legacy.findings.injection.v1"
    v2_capability = "finding.static.injection.v2"
    location = {"file": "app.py", "line": 10, "node_id": "cg-handler"}
    inputs = {
        legacy_capability: _input(
            legacy_capability,
            [{"id": "legacy-1", "title": "Legacy duplicate", "locations": [location]}],
        ),
        v2_capability: _input(
            v2_capability,
            [
                {
                    "id": "v2-1",
                    "rule_id": "injection.sink-reachability",
                    "vuln_class": "injection",
                    "title": "V2 result",
                    "severity": "high",
                    "static_confidence": "high",
                    "status": "unverified",
                    "locations": [location],
                    "source_node_ids": [],
                    "sink_node_ids": ["cg-handler"],
                    "evidence_artifact_ids": [],
                    "rationale": "bounded evidence",
                    "remediation": "parameterize",
                    "fingerprint": SHA,
                }
            ],
        ),
    }
    context = SimpleNamespace(
        scan=SimpleNamespace(id=uuid4(), config={"analysisMode": "compare"}),
        repositories=SimpleNamespace(
            tasks=SimpleNamespace(list=lambda **_: []),
        ),
    )

    output = legacy_findings_aggregate_runtime(  # type: ignore[arg-type]
        context,
        inputs,
    )[0]

    assert isinstance(output.json_value, list)
    assert [item["id"] for item in output.json_value] == ["v2-1"]
    assert output.json_value[0]["verification_status"] == "unverified"


def test_v2_authorization_plan_pulls_security_ir_by_capability() -> None:
    registry = PluginRegistry.discover()
    analyzer_ids = register_legacy_plugins(
        registry,
        {
            "authz": FakeAnalyzer("authz", Phase.VULN_ANALYSIS),
            "business-flow": FakeAnalyzer("business-flow", Phase.ENRICHMENT),
        },
    )
    selected = legacy_selected_plugin_ids(
        {
            "analysisMode": "v2",
            "analyzers": {"enrichment": [], "vuln": ["authz"]},
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
    detector = by_plugin["detector.authorization"]
    detector_dependencies = {task.plugin_id for task in plan.tasks if task.id in detector.depends_on}

    assert {
        "graph.codegraph",
        "semantic.business-flow-to-security-ir",
    } == detector_dependencies
    assert "legacy.analyzer.business-flow" in by_plugin
    assert "legacy.analyzer.authz" not in by_plugin


def test_compare_plan_dependencies_include_both_detection_arms() -> None:
    registry = PluginRegistry.discover()
    analyzer_ids = register_legacy_plugins(
        registry,
        {
            "injection": FakeAnalyzer("injection", Phase.VULN_ANALYSIS),
        },
    )
    selected = legacy_selected_plugin_ids(
        {
            "analysisMode": "compare",
            "analyzers": {"enrichment": [], "vuln": ["injection"]},
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
    comparison = by_plugin["comparison.injection"]
    dependencies = {task.plugin_id for task in plan.tasks if task.id in comparison.depends_on}

    assert dependencies == {
        "detector.injection",
        "legacy.analyzer.injection",
    }
