"""Business-logic analyzer tests focused on enriched-flow consumption."""

from __future__ import annotations

import json
from typing import Any

from argus.analyzers.business_logic.analyzer import ANALYZER
from argus.contracts import AnalysisContext, Analyzer, Confidence, Phase, Severity, SourceMode
from argus.orchestration.registry import discover_analyzers


class _Graph:
    def __init__(self, nodes: list[dict[str, Any]] | None = None) -> None:
        self.nodes = nodes or [
            _node("api/orders.py::checkout", "checkout", "api/orders.py", 10, 20),
            _node("api/orders.py::refund", "refund", "api/orders.py", 30, 45),
            _node("admin/ops.py::delete_all", "delete_all", "admin/ops.py", 5, 8),
        ]

    def query(self, search: str) -> list[dict[str, Any]]:
        assert search == ""
        return list(self.nodes)

    def node(self, node_id: str) -> dict[str, Any] | None:
        return next((node for node in self.nodes if node["id"] == node_id), None)

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        if symbol == "api/orders.py::refund":
            return [self.nodes[0]]
        return []

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        if symbol == "api/orders.py::checkout":
            return [self.nodes[1]]
        return []

    def explore(self, query: str) -> str:
        return f"verified call trail for {query}"


class _Source:
    mode = SourceMode.RAW

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        return f"# {path}:{start}-{end}\ndef handler(request):\n    return request.json\n"


class _LLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.prompts: list[str] = []
        self.system = ""

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        del max_tokens
        self.system = system
        self.prompts.append(prompt)
        return self.response


def _node(node_id: str, name: str, file_path: str, start: int, end: int | None) -> dict[str, Any]:
    return {
        "id": node_id,
        "kind": "function",
        "name": name,
        "qualified_name": node_id.replace("::", "."),
        "file_path": file_path,
        "start_line": start,
        "end_line": end,
        "signature": f"def {name}(request)",
    }


def _enriched(*, related: bool = True) -> dict[str, Any]:
    checkout_related = ["ep-refund"] if related else []
    refund_related = ["ep-checkout"] if related else []
    return {
        "endpoints": [
            {
                "id": "ep-checkout",
                "method": "POST",
                "path": "/checkout",
                "node_id": "api/orders.py::checkout",
            },
            {
                "id": "ep-refund",
                "method": "POST",
                "path": "/refund",
                "node_id": "api/orders.py::refund",
            },
        ],
        "handlers": [
            {"id": "h-checkout", "name": "checkout", "node_id": "api/orders.py::checkout"},
            {"id": "h-refund", "name": "refund", "node_id": "api/orders.py::refund"},
        ],
        "resources": [
            {"id": "r-order", "name": "Order", "owner_field": "user_id"},
        ],
        "operations": [
            {"id": "op-create", "verb": "create", "target_resource": "Order"},
            {"id": "op-refund", "verb": "update", "target_resource": "Order"},
        ],
        "edges": [
            {"from": "ep-checkout", "rel": "handled_by", "to": "h-checkout"},
            {"from": "h-checkout", "rel": "performs", "to": "op-create"},
            {"from": "op-create", "rel": "targets", "to": "r-order"},
            {"from": "ep-refund", "rel": "handled_by", "to": "h-refund"},
            {"from": "h-refund", "rel": "performs", "to": "op-refund"},
            {"from": "op-refund", "rel": "targets", "to": "r-order"},
        ],
        "business_flows": [
            {
                "endpoint_id": "ep-checkout",
                "intent": "用购物车内容创建订单",
                "preconditions": ["购物车属于当前用户"],
                "related_endpoint_ids": checkout_related,
                "actors": ["buyer"],
                "authorization_requirements": ["购物车属于当前用户"],
                "authorization_checks": [
                    {
                        "requirement": "购物车属于当前用户",
                        "enforced": False,
                        "enforced_by": None,
                        "note": "直接按 cart_id 查询",
                    }
                ],
                "trust_boundaries": [
                    {
                        "field": "amount",
                        "source": "request_body",
                        "validated": False,
                        "note": "服务端未按商品单价重新核价",
                    }
                ],
                "state_reads": ["cart.items"],
                "state_writes": ["order.status"],
                "state_transitions": [{"from": "cart", "to": "created", "note": "只能创建一次"}],
                "side_effects": ["扣减库存"],
                "replay_guards": [],
            },
            {
                "endpoint_id": "ep-refund",
                "intent": "对已支付订单执行退款",
                "preconditions": ["订单已支付", "当前用户有权退款"],
                "related_endpoint_ids": refund_related,
                "actors": ["buyer", "seller"],
                "authorization_requirements": ["退款发起者有权操作订单"],
                "authorization_checks": [],
                "trust_boundaries": [],
                "state_reads": ["order.status"],
                "state_writes": ["order.status", "wallet.balance"],
                "state_transitions": [{"from": "paid", "to": "refunded", "note": "只允许一次"}],
                "side_effects": ["退回资金"],
                "replay_guards": [],
            },
        ],
    }


def _finding(*, locations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "title": "Checkout trusts a client-controlled amount",
        "severity": "high",
        "confidence": "high",
        "locations": locations or [{"file": "wrong.py", "line": 999, "node_id": "api/orders.py::checkout"}],
        "data_flow": "request.amount -> checkout -> order total",
        "rationale": "The server creates the order without independently recomputing the amount.",
        "evidence": "The enriched trust boundary is unvalidated and the source confirms direct use.",
        "remediation": "Recompute totals from server-side product prices and quantities.",
    }


def _ctx(
    response: str,
    *,
    enriched: dict[str, Any] | None = None,
    graph: _Graph | None = None,
    config: dict[str, Any] | None = None,
) -> tuple[AnalysisContext, _LLM]:
    llm = _LLM(response)
    ctx: AnalysisContext = {
        "graph": graph or _Graph(),
        "enriched": _enriched() if enriched is None else enriched,
        "source": _Source(),
        "config": config or {},
        "llm": llm,
        "workspace": "business-logic-test",
    }
    return ctx, llm


def test_metadata_and_registry_contract() -> None:
    assert ANALYZER.name == "business-logic"
    assert ANALYZER.phase is Phase.VULN_ANALYSIS
    assert ANALYZER.requires == ["enriched-graph"]
    assert isinstance(ANALYZER, Analyzer)
    assert discover_analyzers()["business-logic"] is ANALYZER


def test_finds_price_tampering_with_enrichment_and_real_anchor() -> None:
    ctx, llm = _ctx(json.dumps({"findings": [_finding()]}))

    result = ANALYZER.run(ctx)

    assert result["analyzer"] == "business-logic"
    assert result["enrichment"] == {}
    finding = result["findings"][0]
    assert finding["vuln_class"] == "business-logic"
    assert finding["severity"] is Severity.HIGH
    assert finding["confidence"] is Confidence.HIGH
    assert finding["locations"] == [{"file": "api/orders.py", "line": 10, "node_id": "api/orders.py::checkout"}]
    assert '"field": "amount"' in llm.prompts[0]
    assert '"validated": false' in llm.prompts[0]
    assert "verified call trail" in llm.prompts[0]
    assert "server-side" in llm.system


def test_related_endpoints_stay_in_one_unit_and_allow_cross_handler_locations() -> None:
    cross_handler = _finding(
        locations=[
            {"file": "api/orders.py", "line": 15, "node_id": "api/orders.py::checkout"},
            {"file": "api/orders.py", "line": 35, "node_id": "api/orders.py::refund"},
        ]
    )
    ctx, llm = _ctx(
        json.dumps({"findings": [cross_handler]}),
        config={"business-logic": {"batch_size": 1}},
    )

    findings = ANALYZER.run(ctx)["findings"]

    assert len(llm.prompts) == 1
    assert len(findings) == 1
    assert {location["node_id"] for location in findings[0]["locations"]} == {
        "api/orders.py::checkout",
        "api/orders.py::refund",
    }


def test_rejects_real_node_outside_enriched_flow_scope() -> None:
    payload = _finding(locations=[{"file": "admin/ops.py", "line": 5, "node_id": "admin/ops.py::delete_all"}])
    ctx, _ = _ctx(json.dumps({"findings": [payload]}))
    assert ANALYZER.run(ctx)["findings"] == []


def test_unanchored_enriched_flows_are_skipped_without_calling_llm() -> None:
    enriched = _enriched()
    for endpoint in enriched["endpoints"]:
        endpoint["node_id"] = None
    for handler in enriched["handlers"]:
        handler["node_id"] = None
    ctx, llm = _ctx(json.dumps({"findings": [_finding()]}), enriched=enriched)

    result = ANALYZER.run(ctx)

    assert result == {"analyzer": "business-logic", "findings": [], "enrichment": {}}
    assert llm.prompts == []


def test_malformed_llm_json_degrades_to_empty_result() -> None:
    ctx, _ = _ctx("not json")
    assert ANALYZER.run(ctx) == {"analyzer": "business-logic", "findings": [], "enrichment": {}}


def test_disconnected_flows_are_batched_without_truncation() -> None:
    nodes = [
        _node(f"api/f{index}.py::handler_{index}", f"handler_{index}", f"api/f{index}.py", 1, 3) for index in range(3)
    ]
    graph = _Graph(nodes)
    enriched: dict[str, Any] = {
        "endpoints": [
            {"id": f"ep-{index}", "method": "POST", "path": f"/f{index}", "node_id": node["id"]}
            for index, node in enumerate(nodes)
        ],
        "handlers": [],
        "resources": [],
        "operations": [],
        "edges": [],
        "business_flows": [
            {
                "endpoint_id": f"ep-{index}",
                "intent": f"flow {index}",
                "related_endpoint_ids": [],
                "preconditions": [],
                "actors": [],
                "authorization_requirements": [],
                "authorization_checks": [],
                "trust_boundaries": [],
                "state_reads": [],
                "state_writes": [],
                "state_transitions": [],
                "side_effects": [],
                "replay_guards": [],
            }
            for index in range(3)
        ],
    }
    ctx, llm = _ctx(
        json.dumps({"findings": []}),
        graph=graph,
        enriched=enriched,
        # Even an unsafe caller override cannot merge unrelated workflows into one
        # prompt, because their allowed node ids must remain isolated.
        config={"business-logic": {"batch_size": 99}},
    )

    ANALYZER.run(ctx)

    assert len(llm.prompts) == 3
    assert all(f"handler_{index}" in prompt for index, prompt in enumerate(llm.prompts))
