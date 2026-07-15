"""business-flow 富化器测试。

不联网、不跑真 codegraph:
- graph:真实 CodegraphHandle 读 tests/fixtures/mini.db(含 function 节点 login / authenticate)。
- llm:返回预设 JSON 的 mock(带 markdown 代码围栏,测健壮解析)。
- source:最小 fake,mode + read。

核心断言:
- 富化器产路由骨架(endpoints 非空)且不产 finding(findings == [])。
- ANALYZER 元数据正确(name / phase / requires)。
- business_flows 存在且含 trust_boundaries 结构(T12 相对 logic-graph 的核心增值)。
- 带 markdown 围栏的 LLM 返回能被正确解析。
- handler.node_id 锚回 codegraph 真实节点(哪怕 LLM 未给 node_id,靠图按名解析)。
- LLM 返回不可解析时优雅降级:不崩、仍返回合法结构、findings 仍为 []。
"""

from __future__ import annotations

import json
import os
from typing import Any

from argus.analyzers.business_flow.analyzer import ANALYZER
from argus.contracts import AnalysisContext, Analyzer, Phase, SourceMode
from argus.graph.codegraph import CodegraphHandle

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")

# 预设的 LLM 语义重建结果:handler 故意不给 node_id,验证分析器靠图按名锚回。
_LLM_GRAPH: dict[str, Any] = {
    "endpoints": [
        {
            "id": "ep-login",
            "method": "POST",
            "path": "/api/login",
            "auth_required": False,
            "source_ref": "api/auth.py:10",
        }
    ],
    "handlers": [
        {"id": "h-login", "name": "login", "source_ref": "api/auth.py:10"},
    ],
    "resources": [
        {"id": "r-session", "name": "Session", "owner_field": "user_id", "source_ref": "api/auth.py:12"},
    ],
    "operations": [
        {"id": "op-create-session", "verb": "create", "target_resource": "Session", "source_ref": "api/auth.py:15"},
    ],
    "edges": [
        {"from": "ep-login", "rel": "handled_by", "to": "h-login"},
        {"from": "h-login", "rel": "performs", "to": "op-create-session"},
    ],
    "business_flows": [
        {
            "endpoint_id": "ep-login",
            "intent": "用户凭用户名口令登录并创建会话",
            "preconditions": ["用户已注册", "口令与存储哈希匹配"],
            "trust_boundaries": [
                {"field": "username", "source": "request_body", "validated": True, "note": "服务端按哈希校验"},
                {"field": "role", "source": "request_body", "validated": False, "note": "role 直接采信请求体、未复核"},
            ],
        }
    ],
}


class _FakeLLM:
    """返回预设文本的 mock LLM,实现 LLMClient 协议并记录调用。"""

    def __init__(self, text: str) -> None:
        self._text = text
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        self.calls.append({"system": system, "prompt": prompt, "max_tokens": max_tokens})
        return self._text


class _FakeSource:
    """最小 SourceAccess:mode + read。read 返回定长桩,不触碰磁盘。"""

    def __init__(self, mode: SourceMode = SourceMode.RAW) -> None:
        self.mode = mode

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        return f"# {path}\ndef handler():\n    ...\n"


def _fenced(payload: dict[str, Any]) -> str:
    """把 JSON 包进 ```json 围栏,并加些前后噪声,模拟真实 LLM 输出。"""
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return f"这是我重建的业务流:\n```json\n{body}\n```\n以上。"


def _ctx(llm_text: str) -> AnalysisContext:
    graph = CodegraphHandle(FIXTURE_DB)
    return {
        "graph": graph,
        "enriched": {},
        "source": _FakeSource(),
        "config": {},
        "llm": _FakeLLM(llm_text),
        "workspace": "bf-test",
    }


def _ctx_with_graph(graph: Any, llm_text: str) -> AnalysisContext:
    """像 _ctx,但注入一个自定义 GraphHandle(用于跨文件同名/调用边测试)。"""
    return {
        "graph": graph,
        "enriched": {},
        "source": _FakeSource(),
        "config": {},
        "llm": _FakeLLM(llm_text),
        "workspace": "bf-test",
    }


class _RecordingGraph:
    """记录 callers/callees 查询的最小 GraphHandle;list_orders 调用 get_order。"""

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = [
            {
                "id": "api/orders.py::list_orders",
                "kind": "function",
                "name": "list_orders",
                "qualified_name": "api.orders.list_orders",
                "file_path": "api/orders.py",
                "start_line": 10,
                "end_line": 20,
                "signature": "def list_orders()",
            },
            {
                "id": "api/orders.py::get_order",
                "kind": "function",
                "name": "get_order",
                "qualified_name": "api.orders.get_order",
                "file_path": "api/orders.py",
                "start_line": 22,
                "end_line": 30,
                "signature": "def get_order(order_id)",
            },
        ]
        self.callee_calls: list[str] = []
        self.caller_calls: list[str] = []

    def query(self, search: str) -> list[dict[str, Any]]:
        assert search == ""
        return list(self.nodes)

    def node(self, node_id: str) -> dict[str, Any] | None:
        return next((n for n in self.nodes if n["id"] == node_id), None)

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        self.callee_calls.append(symbol)
        if symbol == "api/orders.py::list_orders":
            return [self.nodes[1]]
        return []

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        self.caller_calls.append(symbol)
        if symbol == "api/orders.py::get_order":
            return [self.nodes[0]]
        return []

    def explore(self, query: str) -> str:
        return query


class _TwoHandlerGraph:
    """两个跨文件同名 `handler` 节点(a.py / b.py),用于 node_id 消歧测试。"""

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = [
            {
                "id": "a.py::handler",
                "kind": "function",
                "name": "handler",
                "qualified_name": "a.handler",
                "file_path": "a.py",
                "start_line": 5,
                "end_line": 15,
            },
            {
                "id": "b.py::handler",
                "kind": "function",
                "name": "handler",
                "qualified_name": "b.handler",
                "file_path": "b.py",
                "start_line": 5,
                "end_line": 15,
            },
        ]

    def query(self, search: str) -> list[dict[str, Any]]:
        assert search == ""
        return list(self.nodes)

    def node(self, node_id: str) -> dict[str, Any] | None:
        return next((n for n in self.nodes if n["id"] == node_id), None)

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        return []

    def explore(self, query: str) -> str:
        return query


def test_analyzer_metadata() -> None:
    assert ANALYZER.name == "business-flow"
    assert ANALYZER.phase == Phase.ENRICHMENT
    assert ANALYZER.requires == []
    assert isinstance(ANALYZER, Analyzer)


def test_business_flow_produces_enrichment() -> None:
    res = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))

    assert res["analyzer"] == "business-flow"
    assert res["enrichment"]["endpoints"]  # 有路由骨架
    assert res["findings"] == []  # 富化器不产 finding


def test_enrichment_has_all_sections() -> None:
    enrichment = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))["enrichment"]
    for section in ("endpoints", "handlers", "resources", "operations", "edges", "business_flows"):
        assert section in enrichment, f"缺少 enrichment 段:{section}"
    # 富化器不越界产 invariants(那是 T14 的职责)。
    assert "invariants" not in enrichment


def test_markdown_fence_is_stripped_and_parsed() -> None:
    """LLM 返回带 ```json 围栏 + 前后噪声,仍应被正确解析出结构化内容。"""
    enrichment = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))["enrichment"]
    ep = enrichment["endpoints"][0]
    assert ep["method"] == "POST"
    assert ep["path"] == "/api/login"
    assert ep["auth_required"] is False


def test_business_flows_carry_trust_boundaries() -> None:
    enrichment = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))["enrichment"]
    flows = enrichment["business_flows"]
    assert flows, "business_flows 不应为空"

    flow = flows[0]
    assert flow["endpoint_id"] == "ep-login"
    assert flow["intent"]
    assert isinstance(flow["preconditions"], list)

    boundaries = flow["trust_boundaries"]
    assert boundaries
    # 至少有一个未被服务端复核的信任边界(逻辑漏洞的信号)。
    unvalidated = [b for b in boundaries if b["validated"] is False]
    assert unvalidated
    for b in boundaries:
        assert "field" in b
        assert "source" in b
        assert "validated" in b


def test_handler_node_id_anchored_to_real_graph_node() -> None:
    """LLM 未给 node_id 时,分析器应按 handler 名从图中锚回真实节点 id。"""
    enrichment = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))["enrichment"]
    handler = enrichment["handlers"][0]
    assert handler["name"] == "login"
    # mini.db 中 login 的真实节点 id。
    assert handler["node_id"] == "api/auth.py::login"

    # endpoint 经 handled_by 边锚回同一真实节点。
    endpoint = enrichment["endpoints"][0]
    assert endpoint["node_id"] == "api/auth.py::login"


def test_unparseable_llm_output_degrades_gracefully() -> None:
    """LLM 返回垃圾时不崩:返回合法(可能为空)结构,findings 仍为 []。"""
    res = ANALYZER.run(_ctx("对不起我今天不想输出 JSON"))

    assert res["findings"] == []
    enrichment = res["enrichment"]
    # 各段仍存在且为 list(空列表也可),下游消费者不必做 None 判空。
    for section in ("endpoints", "handlers", "resources", "operations", "edges", "business_flows"):
        assert section in enrichment
        assert isinstance(enrichment[section], list)


def test_llm_actually_invoked_with_prompt() -> None:
    ctx = _ctx(_fenced(_LLM_GRAPH))
    ANALYZER.run(ctx)
    llm = ctx["llm"]
    assert isinstance(llm, _FakeLLM)
    assert len(llm.calls) == 1
    call = llm.calls[0]
    assert call["system"]
    assert call["prompt"]


# === 修复2:段内非法条目规整(逐条丢弃非 dict,业务流校验必需字段) ===


def test_illegal_entries_dropped_all_sections_stay_lists() -> None:
    """LLM 每段都混入非法条目;规整后非法条目被丢弃、合法条目保留、每段仍是 list。"""
    payload: dict[str, Any] = {
        "endpoints": ["not-an-object", {"id": "ep-x", "method": "GET", "path": "/x"}],
        "handlers": [42, {"id": "h-x", "name": "login"}],
        "resources": [None, {"id": "r-x", "name": "Order"}],
        "operations": ["bad", {"id": "op-x", "verb": "read", "target_resource": "Order"}],
        "edges": ["bad-edge", {"from": "ep-x", "rel": "handled_by", "to": "h-x"}],
        "business_flows": [
            "not-an-object",
            {"endpoint_id": "ep-x", "intent": "读取订单"},
        ],
    }
    enrichment = ANALYZER.run(_ctx(_fenced(payload)))["enrichment"]

    for section in ("endpoints", "handlers", "resources", "operations", "edges", "business_flows"):
        assert isinstance(enrichment[section], list)
        assert all(isinstance(item, dict) for item in enrichment[section]), f"{section} 残留非 dict"

    assert len(enrichment["endpoints"]) == 1
    assert len(enrichment["handlers"]) == 1
    assert len(enrichment["resources"]) == 1
    assert len(enrichment["operations"]) == 1
    assert len(enrichment["edges"]) == 1
    assert len(enrichment["business_flows"]) == 1
    assert enrichment["business_flows"][0]["endpoint_id"] == "ep-x"


def test_business_flow_missing_required_fields_dropped() -> None:
    """business_flows 缺 endpoint_id 或 intent 的条目被丢弃。"""
    payload: dict[str, Any] = {
        "business_flows": [
            {"intent": "缺 endpoint_id"},
            {"endpoint_id": "ep-y"},
            {"endpoint_id": "ep-ok", "intent": "两者都在"},
        ],
    }
    flows = ANALYZER.run(_ctx(_fenced(payload)))["enrichment"]["business_flows"]
    assert len(flows) == 1
    assert flows[0]["endpoint_id"] == "ep-ok"


def test_business_flow_trust_boundaries_non_dict_dropped() -> None:
    """trust_boundaries 非 list 时置空;list 内非 dict 条目被丢弃。"""
    payload: dict[str, Any] = {
        "business_flows": [
            {
                "endpoint_id": "ep-a",
                "intent": "a",
                "trust_boundaries": "not-a-list",
            },
            {
                "endpoint_id": "ep-b",
                "intent": "b",
                "trust_boundaries": ["bad", {"field": "amount", "source": "request_body", "validated": False}],
            },
        ],
    }
    flows = ANALYZER.run(_ctx(_fenced(payload)))["enrichment"]["business_flows"]
    by_id = {f["endpoint_id"]: f for f in flows}
    assert by_id["ep-a"]["trust_boundaries"] == []
    assert len(by_id["ep-b"]["trust_boundaries"]) == 1
    assert by_id["ep-b"]["trust_boundaries"][0]["field"] == "amount"


# === 修复3:node_id 消歧(跨文件同名) ===


def test_handler_disambiguated_by_source_ref() -> None:
    """两个跨文件同名 handler;LLM 未给 node_id 但给了 b.py 的 source_ref,应锚到 b.py。"""
    graph = _TwoHandlerGraph()
    payload: dict[str, Any] = {
        "handlers": [{"id": "h-1", "name": "handler", "source_ref": "b.py:10"}],
    }
    enrichment = ANALYZER.run(_ctx_with_graph(graph, _fenced(payload)))["enrichment"]
    assert enrichment["handlers"][0]["node_id"] == "b.py::handler"


def test_handler_ambiguous_name_yields_none_node_id() -> None:
    """同名跨文件且无任何消歧信息时,node_id 应为 None(不瞎猜取首个)。"""
    graph = _TwoHandlerGraph()
    payload: dict[str, Any] = {
        "handlers": [{"id": "h-1", "name": "handler"}],
    }
    enrichment = ANALYZER.run(_ctx_with_graph(graph, _fenced(payload)))["enrichment"]
    assert enrichment["handlers"][0]["node_id"] is None


def test_handler_provided_node_id_must_exist() -> None:
    """LLM 给的 node_id 不在图中时不采信,回落到消歧;无法消歧则 None。"""
    graph = _TwoHandlerGraph()
    payload: dict[str, Any] = {
        "handlers": [{"id": "h-1", "name": "handler", "node_id": "c.py::handler"}],
    }
    enrichment = ANALYZER.run(_ctx_with_graph(graph, _fenced(payload)))["enrichment"]
    assert enrichment["handlers"][0]["node_id"] is None


def test_endpoint_inherits_disambiguated_handler_node_id() -> None:
    """endpoint 经 handled_by 边继承已消歧的 handler node_id。"""
    graph = _TwoHandlerGraph()
    payload: dict[str, Any] = {
        "endpoints": [{"id": "ep-1", "method": "GET", "path": "/x"}],
        "handlers": [{"id": "h-1", "name": "handler", "source_ref": "b.py:10"}],
        "edges": [{"from": "ep-1", "rel": "handled_by", "to": "h-1"}],
    }
    enrichment = ANALYZER.run(_ctx_with_graph(graph, _fenced(payload)))["enrichment"]
    assert enrichment["endpoints"][0]["node_id"] == "b.py::handler"


# === 修复1:骨架发调用边 ===


def test_call_edges_queried_and_included_in_prompt() -> None:
    """骨架构建应查询 callers/callees,并把调用关系写进 prompt。"""
    graph = _RecordingGraph()
    ctx = _ctx_with_graph(graph, _fenced(_LLM_GRAPH))
    ANALYZER.run(ctx)

    # callees/callers 都被查询过。
    assert "api/orders.py::list_orders" in graph.callee_calls
    assert graph.caller_calls  # callers 也被查询

    llm = ctx["llm"]
    assert isinstance(llm, _FakeLLM)
    prompt = llm.calls[0]["prompt"]
    # prompt 里出现"谁调用谁"的信息:list_orders -> get_order。
    assert "list_orders" in prompt
    assert "get_order" in prompt
    # 调用关系以结构化形式进入 prompt(callees/calls 字样之一)。
    assert "callees" in prompt or "calls" in prompt


# === 修复4:business_flows 可选扩展字段 ===


def test_business_flow_new_fields_normalized() -> None:
    """LLM 产出新扩展字段时被正确规整进 business_flows。"""
    payload: dict[str, Any] = {
        "business_flows": [
            {
                "endpoint_id": "ep-refund",
                "intent": "退款",
                "related_endpoint_ids": ["ep-order", "ep-pay"],
                "actors": ["buyer"],
                "authorization_requirements": ["must own order"],
                "state_reads": ["order.status"],
                "state_writes": ["order.refunded"],
                "state_transitions": [{"from": "paid", "to": "refunded"}],
                "side_effects": ["refund money"],
                "replay_guards": ["idempotency_key"],
            }
        ],
    }
    flow = ANALYZER.run(_ctx(_fenced(payload)))["enrichment"]["business_flows"][0]
    assert flow["related_endpoint_ids"] == ["ep-order", "ep-pay"]
    assert flow["actors"] == ["buyer"]
    assert flow["authorization_requirements"] == ["must own order"]
    assert flow["state_reads"] == ["order.status"]
    assert flow["state_writes"] == ["order.refunded"]
    assert flow["state_transitions"] == [{"from": "paid", "to": "refunded"}]
    assert flow["side_effects"] == ["refund money"]
    assert flow["replay_guards"] == ["idempotency_key"]


def test_business_flow_new_fields_default_empty_when_absent() -> None:
    """LLM 不产新字段时,规整后缺省为空 list(向后兼容)。"""
    flow = ANALYZER.run(_ctx(_fenced(_LLM_GRAPH)))["enrichment"]["business_flows"][0]
    for field in (
        "related_endpoint_ids",
        "actors",
        "authorization_requirements",
        "state_reads",
        "state_writes",
        "state_transitions",
        "side_effects",
        "replay_guards",
    ):
        assert flow[field] == [], f"{field} 应缺省为空 list"


def test_business_flow_new_fields_wrong_type_defaults_empty() -> None:
    """新字段类型不对(非 list)时缺省为空 list,list 内非法项按需过滤。"""
    payload: dict[str, Any] = {
        "business_flows": [
            {
                "endpoint_id": "ep-z",
                "intent": "z",
                "related_endpoint_ids": "not-a-list",
                "actors": None,
                "side_effects": ["ok", 123],
            }
        ],
    }
    flow = ANALYZER.run(_ctx(_fenced(payload)))["enrichment"]["business_flows"][0]
    assert flow["related_endpoint_ids"] == []
    assert flow["actors"] == []
    # str list 段过滤掉非字符串项。
    assert flow["side_effects"] == ["ok"]
