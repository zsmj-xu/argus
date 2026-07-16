"""Tests for the experimental invariant enrichment analyzer."""

from __future__ import annotations

import json
from typing import Any

from argus.analyzers.invariant.analyzer import ANALYZER
from argus.config import DEFAULT_CONFIG
from argus.contracts import AnalysisContext, Analyzer, Phase, SourceMode


class _Graph:
    def __init__(self) -> None:
        self.nodes = [
            {
                "id": "api/orders.py::list_orders",
                "kind": "function",
                "name": "list_orders",
                "qualified_name": "api.orders.list_orders",
                "file_path": "api/orders.py",
                "start_line": 10,
                "end_line": 20,
                "signature": "def list_orders(order_id)",
            },
            {
                "id": "api/orders.py::redeem_coupon",
                "kind": "method",
                "name": "redeem_coupon",
                "qualified_name": "api.orders.OrderView.redeem_coupon",
                "file_path": "api/orders.py",
                "start_line": 22,
                "end_line": 35,
                "signature": "def redeem_coupon(self, code)",
            },
            {
                "id": "api/health.py::health",
                "kind": "function",
                "name": "health",
                "qualified_name": "api.health.health",
                "file_path": "api/health.py",
                "start_line": 1,
                "end_line": 3,
                "signature": "def health()",
            },
        ]

    def query(self, search: str) -> list[dict[str, Any]]:
        assert search == ""
        return list(self.nodes)

    def node(self, node_id: str) -> dict[str, Any] | None:
        return next((node for node in self.nodes if node["id"] == node_id), None)

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def explore(self, query: str) -> str:
        return query


class _Source:
    mode = SourceMode.RAW

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        del path, start, end
        return "def handler(request):\n    return request\n"


class _LLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.prompt = ""

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        del system, max_tokens
        self.prompt = prompt
        return self.response


def _ctx(response: str) -> tuple[AnalysisContext, _LLM]:
    llm = _LLM(response)
    ctx: AnalysisContext = {
        "graph": _Graph(),
        "enriched": {},
        "source": _Source(),
        "config": {},
        "llm": llm,
        "workspace": "invariant-test",
    }
    return ctx, llm


def test_analyzer_metadata_and_experimental_default() -> None:
    assert ANALYZER.name == "invariant"
    assert ANALYZER.phase == Phase.ENRICHMENT
    assert ANALYZER.requires == []
    assert isinstance(ANALYZER, Analyzer)
    assert "invariant" not in DEFAULT_CONFIG["analyzers"]["enrichment"]


def test_produces_five_kinds_with_handler_anchors_and_nullable_enforced_by() -> None:
    payload = {
        "invariants": [
            {
                "id": "inv-owner",
                "kind": "ownership",
                "statement": "只允许资源所有者读取订单",
                "handler": "list_orders",
                "handler_node_id": "hallucinated-node",
                "inferred_from": "api/orders.py:999",
                "confidence": "high",
                "enforced_by": "check_owner",
            },
            {
                "id": "inv-authn",
                "kind": "authentication",
                "statement": "敏感订单操作必须登录",
                "handler": "list_orders",
                "inferred_from": "api/orders.py:10",
                "confidence": "medium",
            },
            {
                "id": "inv-role",
                "kind": "role",
                "statement": "只有管理员能管理订单",
                "handler": "redeem_coupon",
                "inferred_from": "api/orders.py:22",
                "confidence": "medium",
                "enforced_by": None,
            },
            {
                "id": "inv-replay",
                "kind": "replay",
                "statement": "优惠券只能兑换一次",
                "handler": "redeem_coupon",
                "inferred_from": "api/orders.py:30",
                "confidence": "low",
                "enforced_by": "idempotency_key",
            },
            {
                "id": "inv-trust",
                "kind": "trust_boundary",
                "statement": "服务端不能采信请求体中的价格",
                "handler": "redeem_coupon",
                "inferred_from": "api/orders.py:25",
                "confidence": "high",
                "enforced_by": None,
            },
        ]
    }
    ctx, llm = _ctx(json.dumps(payload))

    result = ANALYZER.run(ctx)

    assert result["analyzer"] == "invariant"
    assert result["findings"] == []
    invariants = result["enrichment"]["invariants"]
    assert {item["kind"] for item in invariants} == {
        "ownership",
        "authentication",
        "role",
        "replay",
        "trust_boundary",
    }
    assert all(item["enforced_by"] is None or isinstance(item["enforced_by"], str) for item in invariants)
    assert {item["handler_node_id"] for item in invariants} <= {
        "api/orders.py::list_orders",
        "api/orders.py::redeem_coupon",
    }
    owner = next(item for item in invariants if item["id"] == "inv-owner")
    assert owner["handler_node_id"] == "api/orders.py::list_orders"
    assert owner["inferred_from"] == "api/orders.py:20"
    assert "ownership" in llm.prompt
    assert "authentication" in llm.prompt
    assert "role" in llm.prompt
    assert "replay" in llm.prompt
    assert "trust_boundary" in llm.prompt


def test_discards_unknown_handlers_and_invalid_kinds() -> None:
    payload = {
        "invariants": [
            {
                "id": "bad-kind",
                "kind": "state_machine",
                "statement": "not in scope",
                "handler": "list_orders",
            },
            {
                "id": "bad-handler",
                "kind": "ownership",
                "statement": "hallucinated handler",
                "handler": "not_in_graph",
            },
        ]
    }
    ctx, _ = _ctx(json.dumps(payload))
    assert ANALYZER.run(ctx)["enrichment"] == {"invariants": []}


def test_malformed_llm_output_degrades_to_empty_enrichment() -> None:
    ctx, _ = _ctx("not json")
    result = ANALYZER.run(ctx)
    assert result["enrichment"] == {"invariants": []}
    assert result["findings"] == []
