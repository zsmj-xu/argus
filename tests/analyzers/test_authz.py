"""Authorization analyzer tests."""

from __future__ import annotations

import json
import os

import pytest

from argus.analyzers.authz.analyzer import ANALYZER
from argus.contracts import AnalysisContext, Confidence, Phase, Severity, SourceMode
from argus.graph.codegraph import CodegraphHandle
from argus.orchestration.registry import discover_analyzers

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


class MockSource:
    mode = SourceMode.RAW

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        del path, start, end
        return ""


class MockLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.system = ""
        self.prompt = ""

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        del max_tokens
        self.system = system
        self.prompt = prompt
        return self.response


def _finding_payload(*, node_id: str = "api/auth.py::authenticate") -> dict[str, object]:
    return {
        "vuln_class": "authz",
        "title": "Resource lookup lacks an ownership check",
        "severity": "high",
        "confidence": "medium",
        "locations": [
            {
                "file": "api/auth.py",
                "line": 28,
                "node_id": node_id,
            }
        ],
        "data_flow": "request resource id -> authenticate -> sensitive resource",
        "rationale": "Authentication is present, but the resource is not bound to the current principal.",
        "evidence": "The handler reaches the resource operation without an ownership guard.",
        "remediation": "Scope the lookup to the current user or tenant before the side effect.",
    }


def _context(llm: MockLLM) -> AnalysisContext:
    return {
        "graph": CodegraphHandle(FIXTURE_DB),
        "enriched": {
            "endpoints": [
                {
                    "route": "POST /authenticate",
                    "handler_node_id": "api/auth.py::authenticate",
                    "trust_boundary": "resource id comes from the request",
                }
            ]
        },
        "source": MockSource(),
        "config": {"authz": {"max_candidates": 50}, "focus": "api/"},
        "llm": llm,
        "workspace": "test-authz",
    }


def test_authz_metadata_matches_analyzer_contract() -> None:
    assert ANALYZER.name == "authz"
    assert ANALYZER.phase is Phase.VULN_ANALYSIS
    assert ANALYZER.requires == []


def test_registry_discovers_module_level_authz_instance() -> None:
    assert discover_analyzers()["authz"] is ANALYZER


def test_authz_produces_valid_finding_anchored_to_graph() -> None:
    llm = MockLLM(json.dumps({"findings": [_finding_payload()]}))

    result = ANALYZER.run(_context(llm))

    assert result["analyzer"] == "authz"
    assert result["enrichment"] == {}
    finding = result["findings"][0]
    assert finding["vuln_class"] == "authz"
    assert finding["severity"] is Severity.HIGH
    assert finding["confidence"] is Confidence.MEDIUM
    assert finding["locations"][0]["node_id"] == "api/auth.py::authenticate"
    assert finding["id"].startswith("authz:authz:")


def test_authz_prompt_contains_codegraph_and_enriched_context() -> None:
    llm = MockLLM(json.dumps({"findings": []}))

    ANALYZER.run(_context(llm))

    assert "api/auth.py::authenticate" in llm.prompt
    assert "POST /authenticate" in llm.prompt
    assert "resource id comes from the request" in llm.prompt
    assert "focus" in llm.prompt
    assert "BOLA" in llm.system


def test_authz_discards_finding_with_unknown_node_id(caplog: pytest.LogCaptureFixture) -> None:
    llm = MockLLM(json.dumps({"findings": [_finding_payload(node_id="missing:node")]}))

    result = ANALYZER.run(_context(llm))

    assert result["findings"] == []
    assert "missing:node" in caplog.text


def test_authz_handles_malformed_llm_json(caplog: pytest.LogCaptureFixture) -> None:
    result = ANALYZER.run(_context(MockLLM("not-json")))

    assert result == {"analyzer": "authz", "findings": [], "enrichment": {}}
    assert "JSON" in caplog.text
