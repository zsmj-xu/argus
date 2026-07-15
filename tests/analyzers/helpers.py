"""Shared fixtures for Shannon-derived analyzer tests."""

from __future__ import annotations

import json
import os
from typing import Any

from argus.contracts import AnalysisContext, SourceMode
from argus.graph.codegraph import CodegraphHandle

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


class MockSource:
    mode = SourceMode.RAW

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        del path, start, end
        return "def authenticate(request):\n    return request\n"


class MockLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.system = ""
        self.prompt = ""
        self.prompts: list[str] = []

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        del max_tokens
        self.system = system
        self.prompt = prompt
        self.prompts.append(prompt)
        return self.response


def finding_payload(vuln_class: str) -> dict[str, Any]:
    return {
        "vuln_class": vuln_class,
        "title": f"{vuln_class} flaw in authenticate",
        "severity": "high",
        "confidence": "medium",
        "locations": [{"file": "api/auth.py", "line": 28, "node_id": "api/auth.py::authenticate"}],
        "data_flow": "request -> authenticate -> sensitive operation",
        "rationale": "The graph path reaches a sensitive operation without a sufficient defense.",
        "evidence": "Graph and source evidence identify the unsafe path.",
        "remediation": "Apply the context-appropriate server-side defense before the sink.",
    }


def context_for(llm: MockLLM) -> AnalysisContext:
    return {
        "graph": CodegraphHandle(FIXTURE_DB),
        "enriched": {"endpoints": [{"route": "POST /authenticate", "handler_node_id": "api/auth.py::authenticate"}]},
        "source": MockSource(),
        "config": {"focus": "api/", "shannon": {"batch_size": 50}},
        "llm": llm,
        "workspace": "test-shannon",
    }


def response_for(vuln_class: str) -> str:
    return json.dumps({"findings": [finding_payload(vuln_class)]})
