from __future__ import annotations

from argus.analyzers.auth.analyzer import ANALYZER
from argus.contracts import Confidence, Phase, Severity

from tests.analyzers.helpers import MockLLM, context_for, response_for


def test_auth_analyzer_contract_and_finding() -> None:
    llm = MockLLM(response_for("auth"))
    result = ANALYZER.run(context_for(llm))

    assert ANALYZER.name == "auth"
    assert ANALYZER.phase is Phase.VULN_ANALYSIS
    assert ANALYZER.requires == []
    finding = result["findings"][0]
    assert finding["vuln_class"] == "auth"
    assert finding["severity"] is Severity.HIGH
    assert finding["confidence"] is Confidence.MEDIUM
    assert finding["locations"][0]["node_id"] == "api/auth.py::authenticate"


def test_auth_bad_node_is_discarded() -> None:
    llm = MockLLM(response_for("auth").replace("api/auth.py::authenticate", "missing:node"))
    assert ANALYZER.run(context_for(llm))["findings"] == []
