from __future__ import annotations

from argus.analyzers.injection.analyzer import ANALYZER
from argus.contracts import Confidence, Phase, Severity
from argus.orchestration.registry import discover_analyzers

from tests.analyzers.helpers import MockLLM, context_for, response_for


def test_injection_analyzer_contract_and_finding() -> None:
    llm = MockLLM(response_for("injection"))
    result = ANALYZER.run(context_for(llm))

    assert ANALYZER.name == "injection"
    assert ANALYZER.phase is Phase.VULN_ANALYSIS
    assert ANALYZER.requires == []
    finding = result["findings"][0]
    assert finding["vuln_class"] == "injection"
    assert finding["severity"] is Severity.HIGH
    assert finding["confidence"] is Confidence.MEDIUM
    assert finding["locations"][0]["node_id"] == "api/auth.py::authenticate"
    assert "api/auth.py::authenticate" in llm.prompt
    assert "POST /authenticate" in llm.prompt


def test_injection_bad_node_is_discarded() -> None:
    llm = MockLLM(response_for("injection").replace("api/auth.py::authenticate", "missing:node"))
    assert ANALYZER.run(context_for(llm))["findings"] == []


def test_registry_discovers_all_t08_analyzers() -> None:
    registry = discover_analyzers()
    assert {"injection", "xss", "auth", "ssrf"} <= registry.keys()
