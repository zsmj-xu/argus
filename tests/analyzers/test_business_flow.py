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
