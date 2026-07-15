"""Adversarial tests for the shared Shannon analyzer implementation."""

from __future__ import annotations

import json

from argus.analyzers.injection.analyzer import ANALYZER

from tests.analyzers.helpers import MockLLM, context_for, finding_payload, response_for


class FakeGraph:
    def __init__(self, nodes: list[dict[str, object]]) -> None:
        self.nodes = nodes

    def query(self, search: str) -> list[dict[str, object]]:
        assert search == ""
        return self.nodes

    def node(self, node_id: str) -> dict[str, object] | None:
        return next((node for node in self.nodes if node["id"] == node_id), None)

    def callers(self, symbol: str) -> list[dict[str, object]]:
        del symbol
        return []

    def callees(self, symbol: str) -> list[dict[str, object]]:
        del symbol
        return []

    def explore(self, query: str) -> str:
        return f"TRAIL source -> sanitizer -> sink for {query}"


def _node(node_id: str, file_path: str, start_line: int | None = 1) -> dict[str, object]:
    return {
        "id": node_id,
        "kind": "function",
        "name": node_id.rsplit("::", 1)[-1],
        "qualified_name": node_id.replace("::", "."),
        "file_path": file_path,
        "start_line": start_line,
        "end_line": start_line,
    }


def test_rejects_real_node_that_is_outside_focus_scope() -> None:
    graph = FakeGraph(
        [
            _node("api/safe.py::handler", "api/safe.py", 10),
            _node("admin/secret.py::delete_all", "admin/secret.py", 20),
        ]
    )
    payload = finding_payload("injection")
    payload["locations"] = [{"file": "admin/secret.py", "line": 20, "node_id": "admin/secret.py::delete_all"}]
    ctx = context_for(MockLLM(json.dumps({"findings": [payload]})))
    ctx["graph"] = graph
    ctx["config"] = {"focus": "api/safe.py"}

    assert ANALYZER.run(ctx)["findings"] == []


def test_rejects_location_when_graph_node_has_no_start_line() -> None:
    graph = FakeGraph([_node("api/routes.py::handler", "api/routes.py", None)])
    payload = finding_payload("injection")
    payload["locations"] = [{"file": "api/routes.py", "line": 999999, "node_id": "api/routes.py::handler"}]
    ctx = context_for(MockLLM(json.dumps({"findings": [payload]})))
    ctx["graph"] = graph
    ctx["config"] = {}

    assert ANALYZER.run(ctx)["findings"] == []


def test_each_batch_contains_graph_exploration_trail() -> None:
    graph = FakeGraph(
        [
            _node("api/routes.py::source", "api/routes.py", 1),
            _node("api/db.py::sink", "api/db.py", 2),
        ]
    )
    llm = MockLLM(json.dumps({"findings": []}))
    ctx = context_for(llm)
    ctx["graph"] = graph
    ctx["config"] = {"shannon": {"batch_size": 1}}

    ANALYZER.run(ctx)

    assert len(llm.prompts) == 2
    assert all("TRAIL source -> sanitizer -> sink" in prompt for prompt in llm.prompts)


def test_accepts_fenced_json_response() -> None:
    llm = MockLLM(f"```json\n{response_for('injection')}\n```")
    assert len(ANALYZER.run(context_for(llm))["findings"]) == 1
