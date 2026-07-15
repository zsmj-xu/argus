"""business-flow 富化器 —— 在 codegraph 骨架上重建业务流语义。

流程(见 run 内 1..6 步):
1. 从 codegraph 拉出函数/方法节点,组成静态调用图骨架。
2. 为骨架节点读取源码片段,拼出给 LLM 的上下文。
3. 组 prompt(骨架 + 上下文),调 LLM 单轮补全。
4. 健壮解析 LLM 返回的 JSON(剥离 markdown 围栏,失败则优雅降级)。
5. 规整成稳定的 enrichment 结构,并把 handler/endpoint 的 node_id 锚回 codegraph 真实节点。
6. 返回 AnalyzerResult:findings 恒为空(富化器不下漏洞结论),产物全在 enrichment。

产出结构的权威说明见同目录 SCHEMA.md —— 它是下游业务逻辑漏洞分析器的隐性契约。
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from argus.analyzers.base import AnalyzerBase
from argus.contracts import Phase

if TYPE_CHECKING:
    from argus.contracts import AnalysisContext, AnalyzerResult, GraphHandle, SourceAccess

# 被视作潜在 handler 的 codegraph 节点 kind。
_HANDLER_KINDS = frozenset({"function", "method"})

# 读取源码上下文的节点数上限,防止真实大仓把 prompt 撑爆。骨架列表本身不设上限。
_MAX_CONTEXT_NODES = 120

# enrichment 的稳定段;缺省全为空 list,保证下游消费者无需判空。
_ENRICHMENT_SECTIONS = ("endpoints", "handlers", "resources", "operations", "edges", "business_flows")

_SYSTEM = (
    "你是一名资深应用安全工程师,擅长把 Web/API 代码库抽象成业务流语义,"
    "用于自动化的业务逻辑漏洞检测。你的输出必须精确、可追溯到源码行号,且为严格的 JSON。"
)

# 从文本里抽取 ```json ... ``` / ``` ... ``` 代码围栏内容。
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


class BusinessFlowAnalyzer(AnalyzerBase):
    """在 codegraph 骨架上重建业务流的富化器。phase=ENRICHMENT,不产 findings。"""

    name = "business-flow"
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        graph = ctx["graph"]

        # 1. 拉骨架节点(函数/方法)。
        skeleton_nodes = _collect_skeleton_nodes(graph)

        # 2. 读源码片段拼上下文。
        context_text = _build_context(skeleton_nodes, ctx["source"])

        # 3. 组 prompt 调 LLM。
        prompt = self._load_prompt()
        prompt = prompt.replace("{{SKELETON}}", _skeleton_json(skeleton_nodes))
        prompt = prompt.replace("{{CONTEXT}}", context_text)
        raw = ctx["llm"].complete(system=_SYSTEM, prompt=prompt)

        # 4. 健壮解析(失败得到 None)。
        parsed = _parse_json_object(raw)

        # 5. 规整 + 锚回真实 node_id。
        enrichment = _assemble_enrichment(parsed, skeleton_nodes)

        # 6. 富化器不产 finding。
        return {"analyzer": self.name, "findings": [], "enrichment": enrichment}


# === 骨架抽取 ===


def _collect_skeleton_nodes(graph: GraphHandle) -> list[dict[str, Any]]:
    """从 codegraph 拉出函数/方法节点作为候选 handler 骨架。

    GraphHandle 协议没有"列出全部节点"的方法;空串 query 借 LIKE '%%' 命中所有节点,
    再按 kind 过滤到函数/方法。
    """
    all_nodes = graph.query("")
    return [node for node in all_nodes if str(node.get("kind", "")) in _HANDLER_KINDS]


def _skeleton_json(nodes: list[dict[str, Any]]) -> str:
    """把骨架节点压成紧凑 JSON 列表喂给 LLM,只保留定位与签名所需字段。"""
    compact = [
        {
            "id": node.get("id"),
            "name": node.get("name"),
            "kind": node.get("kind"),
            "file": node.get("file_path"),
            "start_line": node.get("start_line"),
            "end_line": node.get("end_line"),
            "signature": node.get("signature"),
        }
        for node in nodes
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


def _build_context(nodes: list[dict[str, Any]], source: SourceAccess) -> str:
    """为骨架节点读取源码片段,拼成 LLM 上下文。读失败的节点静默跳过。"""
    blocks: list[str] = []
    for node in nodes[:_MAX_CONTEXT_NODES]:
        file_path = node.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            continue

        start = node.get("start_line")
        end = node.get("end_line")
        start_line = start if isinstance(start, int) else None
        end_line = end if isinstance(end, int) else None

        try:
            snippet = source.read(file_path, start_line, end_line)
        except (OSError, ValueError):
            continue

        header = f"# {node.get('name')} [{node.get('kind')}] {node.get('id')} @ {file_path}:{start_line}"
        blocks.append(f"{header}\n{snippet}")

    if not blocks:
        return "(无可用源码上下文)"
    return "\n\n".join(blocks)


# === LLM 返回解析 ===


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """从 LLM 文本里健壮地解出一个 JSON 对象。

    依次尝试:剥离 markdown 代码围栏 → 截取首个 '{' 到末个 '}' → json.loads。
    任何失败或结果不是 dict 都返回 None,交由上层优雅降级。
    """
    if not text or not text.strip():
        return None

    candidates: list[str] = []

    fence_match = _FENCE_RE.search(text)
    if fence_match:
        candidates.append(fence_match.group(1))
    candidates.append(text)

    for candidate in candidates:
        sliced = _slice_object(candidate)
        if sliced is None:
            continue
        try:
            loaded = json.loads(sliced)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(loaded, dict):
            return loaded

    return None


def _slice_object(text: str) -> str | None:
    """截取 text 中首个 '{' 到最后一个 '}' 之间(含)的子串;找不到返回 None。"""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    return text[start : end + 1]


# === enrichment 规整与锚回 ===


def _assemble_enrichment(parsed: dict[str, Any] | None, skeleton_nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """把解析结果规整成稳定 enrichment 结构,并把 node_id 锚回真实节点。

    每个段缺省为空 list;解析失败(parsed=None)时全空,但结构完整。
    """
    enrichment: dict[str, Any] = {section: _as_list(parsed, section) for section in _ENRICHMENT_SECTIONS}

    valid_ids = {str(node.get("id")) for node in skeleton_nodes if node.get("id") is not None}
    name_to_id = _build_name_index(skeleton_nodes)

    enrichment["handlers"] = _anchor_handlers(enrichment["handlers"], valid_ids, name_to_id)
    handler_node_id = {str(h.get("id")): h.get("node_id") for h in enrichment["handlers"] if h.get("id") is not None}
    endpoint_to_handler = _handled_by_map(enrichment["edges"])
    enrichment["endpoints"] = _anchor_endpoints(
        enrichment["endpoints"], valid_ids, endpoint_to_handler, handler_node_id
    )

    return enrichment


def _as_list(parsed: dict[str, Any] | None, key: str) -> list[Any]:
    """从 parsed 里取 key;不是 list(含 None / parsed 本身为 None)时返回空 list。"""
    if parsed is None:
        return []
    value = parsed.get(key)
    if isinstance(value, list):
        return value
    return []


def _build_name_index(nodes: list[dict[str, Any]]) -> dict[str, str]:
    """建 name → node_id 映射(首个出现者胜),供按 handler 名兜底锚回。"""
    index: dict[str, str] = {}
    for node in nodes:
        name = node.get("name")
        node_id = node.get("id")
        if isinstance(name, str) and name and isinstance(node_id, str) and name not in index:
            index[name] = node_id
    return index


def _resolve_node_id(provided: Any, name: Any, valid_ids: set[str], name_to_id: dict[str, str]) -> str | None:
    """确定一个真实 node_id:优先采用 LLM 给的(须在图中真实存在),否则按 name 兜底解析。"""
    if isinstance(provided, str) and provided in valid_ids:
        return provided
    if isinstance(name, str):
        return name_to_id.get(name)
    return None


def _anchor_handlers(handlers: list[Any], valid_ids: set[str], name_to_id: dict[str, str]) -> list[dict[str, Any]]:
    """规整 handler 条目,补齐 node_id(锚回真实节点或 None)。"""
    anchored: list[dict[str, Any]] = []
    for handler in handlers:
        if not isinstance(handler, dict):
            continue
        node_id = _resolve_node_id(handler.get("node_id"), handler.get("name"), valid_ids, name_to_id)
        anchored.append(
            {
                "id": handler.get("id"),
                "name": handler.get("name"),
                "source_ref": handler.get("source_ref"),
                "node_id": node_id,
            }
        )
    return anchored


def _handled_by_map(edges: list[Any]) -> dict[str, str]:
    """从 edges 抽出 endpoint_id → handler_id(rel == 'handled_by')。"""
    mapping: dict[str, str] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if edge.get("rel") != "handled_by":
            continue
        src = edge.get("from")
        dst = edge.get("to")
        if isinstance(src, str) and isinstance(dst, str):
            mapping[src] = dst
    return mapping


def _anchor_endpoints(
    endpoints: list[Any],
    valid_ids: set[str],
    endpoint_to_handler: dict[str, str],
    handler_node_id: dict[str, Any],
) -> list[dict[str, Any]]:
    """规整 endpoint 条目;node_id 优先取 LLM 给的真实 id,否则经 handled_by 边取 handler 的 node_id。"""
    anchored: list[dict[str, Any]] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue

        node_id: str | None = None
        provided = endpoint.get("node_id")
        if isinstance(provided, str) and provided in valid_ids:
            node_id = provided
        else:
            endpoint_id = endpoint.get("id")
            if isinstance(endpoint_id, str):
                handler_id = endpoint_to_handler.get(endpoint_id)
                if handler_id is not None:
                    resolved = handler_node_id.get(handler_id)
                    node_id = resolved if isinstance(resolved, str) else None

        anchored.append(
            {
                "id": endpoint.get("id"),
                "method": endpoint.get("method"),
                "path": endpoint.get("path"),
                "auth_required": endpoint.get("auth_required"),
                "source_ref": endpoint.get("source_ref"),
                "node_id": node_id,
            }
        )
    return anchored


# 模块级实例 —— 注册表按约定发现。
ANALYZER = BusinessFlowAnalyzer()
