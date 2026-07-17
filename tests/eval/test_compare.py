"""T17: graph-vs-baseline comparison and strict baseline isolation."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from argus.analyzers.baseline.analyzer import BaselineAnalyzer, BaselineIsolationError, NoGraphHandle
from argus.config import DEFAULT_CONFIG
from argus.contracts import AnalysisContext, Confidence, Finding, GraphHandle, Severity, SourceMode
from argus.eval.compare import compare
from argus.orchestration.registry import discover_analyzers


class TrackingSource:
    def __init__(self, files: dict[str, str], mode: SourceMode = SourceMode.STRIPPED) -> None:
        self.files = files
        self.mode = mode
        self.calls: list[str] = []

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        del start, end
        self.calls.append(path)
        return self.files[path]


class TrackingLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls = 0
        self.system = ""
        self.prompt = ""

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        del max_tokens
        self.calls += 1
        self.system = system
        self.prompt = prompt
        return self.response


class OrdinaryGraph:
    def query(self, search: str) -> list[dict[str, Any]]:
        del search
        return []

    def node(self, node_id: str) -> dict[str, Any] | None:
        del node_id
        return None

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def explore(self, query: str) -> str:
        del query
        return ""


def _finding(finding_id: str, title: str, file: str, line: int) -> Finding:
    return {
        "id": finding_id,
        "analyzer": "test",
        "vuln_class": "business-logic",
        "title": title,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "locations": [{"file": file, "line": line, "node_id": f"file:{file}"}],
        "data_flow": title,
        "rationale": title,
        "evidence": title,
        "remediation": "Fix it",
    }


def _response() -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "title": "Replay due to missing idempotency guard",
                    "severity": "high",
                    "confidence": "medium",
                    "locations": [{"file": "api/orders.py", "line": 5, "node_id": "invented"}],
                    "data_flow": "duplicate request -> repeated credit",
                    "rationale": "The refund is replayable.",
                    "evidence": "No idempotency key is checked.",
                    "remediation": "Persist and reject duplicate operation keys.",
                }
            ]
        }
    )


def _context(
    source: TrackingSource,
    llm: TrackingLLM,
    *,
    graph: GraphHandle | None = None,
    enriched: dict[str, Any] | None = None,
) -> AnalysisContext:
    return {
        "graph": graph or NoGraphHandle(),
        "enriched": {} if enriched is None else enriched,
        "source": source,
        "config": {
            "baseline": {
                "files": ["api/orders.py"],
                "anchors": {
                    "api/orders.py": [
                        {
                            "node_id": "function:0123456789abcdef|refund",
                            "kind": "function",
                            "start_line": 2,
                            "end_line": 5,
                        }
                    ]
                },
            }
        },
        "llm": llm,
        "workspace": "eval-baseline",
    }


def test_compare_scores_graph_and_baseline_side_by_side_without_mutation() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "replay",
                "in_scope": True,
                "invariant_kind": "replay",
                "location": "api/orders.py:10",
            },
            {
                "id": "owner",
                "in_scope": True,
                "invariant_kind": "ownership",
                "location": "api/orders.py:30",
            },
        ]
    }
    graph_findings = [
        _finding("g1", "Replay idempotency flaw", "api/orders.py", 10),
        _finding("g2", "Ownership IDOR flaw", "api/orders.py", 30),
    ]
    baseline_findings = [
        _finding("b1", "Replay idempotency flaw", "api/orders.py", 10),
        _finding("b2", "Unrelated replay duplicate", "api/other.py", 1),
    ]
    originals = deepcopy((graph_findings, baseline_findings, ground_truth))

    result = compare(graph_findings, baseline_findings, ground_truth)

    assert result["graph"]["tp"] == 2
    assert result["graph"]["fp"] == 0
    assert result["graph"]["fn"] == 0
    assert result["baseline"]["tp"] == 1
    assert result["baseline"]["fp"] == 1
    assert result["baseline"]["fn"] == 1
    assert (graph_findings, baseline_findings, ground_truth) == originals


def test_baseline_uses_only_stripped_source_and_trusted_node_mapping() -> None:
    source = TrackingSource(
        {
            "api/orders.py": (
                '"""TEACHING_DOCSTRING_SECRET"""\n'
                "def refund(order):\n"
                "    marker = '# string content remains'\n"
                "    # TEACHING_COMMENT_SECRET\n"
                "    return credit(order)\n"
            )
        }
    )
    llm = TrackingLLM(_response())

    result = BaselineAnalyzer().run(_context(source, llm))

    assert source.calls == ["api/orders.py"]
    assert llm.calls == 1
    assert "TEACHING_DOCSTRING_SECRET" not in llm.prompt
    assert "TEACHING_COMMENT_SECRET" not in llm.prompt
    assert "# string content remains" in llm.prompt
    assert "function:0123456789abcdef|refund" not in llm.prompt
    assert "invented" not in llm.prompt
    assert result["findings"][0]["locations"] == [
        {"file": "api/orders.py", "line": 5, "node_id": "function:0123456789abcdef|refund"}
    ]
    assert result["findings"][0]["analyzer"] == "baseline"


def test_baseline_prompt_does_not_leak_comments_from_malformed_python() -> None:
    source = TrackingSource({"api/orders.py": "if True:\n  x = 1\n y = 2\n# TEACHING_SECRET\n"})
    llm = TrackingLLM(json.dumps({"findings": []}))

    BaselineAnalyzer().run(_context(source, llm))

    assert "TEACHING_SECRET" not in llm.prompt


@pytest.mark.parametrize(
    ("mode", "graph", "enriched"),
    [
        (SourceMode.RAW, NoGraphHandle(), {}),
        (SourceMode.STRIPPED, OrdinaryGraph(), {}),
        (SourceMode.STRIPPED, NoGraphHandle(), {"secret": "enrichment"}),
    ],
)
def test_baseline_rejects_isolation_violations_before_read_or_llm(
    mode: SourceMode,
    graph: GraphHandle,
    enriched: dict[str, Any],
) -> None:
    source = TrackingSource({"api/orders.py": "pass\n"}, mode=mode)
    llm = TrackingLLM(_response())

    with pytest.raises(BaselineIsolationError):
        BaselineAnalyzer().run(_context(source, llm, graph=graph, enriched=enriched))

    assert source.calls == []
    assert llm.calls == 0


def test_no_graph_handle_satisfies_protocol_and_never_silently_returns() -> None:
    graph = NoGraphHandle()
    assert isinstance(graph, GraphHandle)

    for call in (
        lambda: graph.query("x"),
        lambda: graph.node("x"),
        lambda: graph.callers("x"),
        lambda: graph.callees("x"),
        lambda: graph.explore("x"),
    ):
        with pytest.raises(BaselineIsolationError, match="graph access disabled"):
            call()


def test_registry_discovers_fail_closed_baseline_but_default_config_does_not_enable_it() -> None:
    assert "baseline" in discover_analyzers()
    assert "baseline" not in DEFAULT_CONFIG["analyzers"]["vuln"]
