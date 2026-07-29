"""business-flow 富化器 —— 在 codegraph 骨架上重建业务流语义。

流程(见 run 内 1..6 步):
1. 从 codegraph 拉出函数/方法节点,组成静态调用图骨架,并沿 calls 边补出真实调用关系
   (仅保留两端都在骨架内的调用边,丢弃指向骨架外符号的悬空边)。
2. 为骨架节点读取源码片段,拼出给 LLM 的上下文。
3. 组 prompt(骨架 + 调用边 + 上下文),调 LLM 单轮补全。
4. 健壮解析 LLM 返回的 JSON(剥离 markdown 围栏,失败则优雅降级)。
5. 规整成稳定的 enrichment 结构:逐段丢弃非法条目、校验 business_flows 必需字段与
   引用完整性(endpoint_id/related_endpoint_ids 须指向真实 endpoint)、逐字段规整嵌套
   对象(trust_boundaries/state_transitions/authorization_checks),
   并把 handler/endpoint 的 node_id 消歧后锚回 codegraph 真实节点。
6. 返回 AnalyzerResult:findings 恒为空(富化器不下漏洞结论),产物全在 enrichment。

产出结构的权威说明见同目录 SCHEMA.md —— 它是下游业务逻辑漏洞分析器的隐性契约。
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from argus.analyzers.base import AnalyzerBase
from argus.contracts import Phase
from argus.llm.client import HEAVY_MAX_TOKENS
from argus.progress import emit_progress

if TYPE_CHECKING:
    from argus.contracts import AnalysisContext, AnalyzerResult, GraphHandle, SourceAccess

logger = logging.getLogger(__name__)

# 被视作潜在 handler 的 codegraph 节点 kind。
_HANDLER_KINDS = frozenset({"function", "method"})

# 读取源码上下文的节点数上限,防止真实大仓把 prompt 撑爆。骨架列表本身不设上限。
_MAX_CONTEXT_NODES = 120

# 探查调用边时最多探查多少个骨架节点(每节点 2 次图查询)。限制查询次数,防大仓拖慢。
_MAX_CALL_EDGE_PROBE_NODES = 300

# 喂给 LLM 的调用边总数上限,防止 prompt 因调用关系爆炸。达到即停止继续探查。
_MAX_CALL_EDGES = 500

# enrichment 的稳定段;缺省全为空 list,保证下游消费者无需判空。
_ENRICHMENT_SECTIONS = ("endpoints", "handlers", "resources", "operations", "edges", "business_flows")

# business_flows[] 中「值为字符串列表」的可选扩展字段;缺省/类型不符时规整为空 list。
_FLOW_STR_LIST_FIELDS = (
    "preconditions",
    "related_endpoint_ids",
    "actors",
    "authorization_requirements",
    "state_reads",
    "state_writes",
    "side_effects",
    "replay_guards",
)

# business_flows[] 中「值为对象列表」的可选字段。每个字段配一个逐字段规整器:
# 非 dict 条目丢弃,必需子字段缺失/非法的条目丢弃,其余子字段强制到稳定类型。
# 映射在 _NESTED_OBJECT_NORMALIZERS 里给出(定义在规整器之后)。
_FLOW_DICT_LIST_FIELDS = ("trust_boundaries", "state_transitions", "authorization_checks")

_SYSTEM = (
    "你是一名资深应用安全工程师,擅长把 Web/API 代码库抽象成业务流语义,"
    "用于自动化的业务逻辑漏洞检测。你的输出必须精确、可追溯到源码行号,且为严格的 JSON。"
)

# 从文本里抽取 ```json ... ``` / ``` ... ``` 代码围栏内容。
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


class BusinessFlowOutputError(RuntimeError):
    """Raised when a comparison run requires usable structured enrichment."""


class BusinessFlowAnalyzer(AnalyzerBase):
    """在 codegraph 骨架上重建业务流的富化器。phase=ENRICHMENT,不产 findings。"""

    name = "business-flow"
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    @staticmethod
    def _progress(ctx: AnalysisContext, *, event: str, message: str, **details: Any) -> None:
        runs_root = getattr(ctx["llm"], "runs_root", None)
        if not isinstance(runs_root, str):
            return
        emit_progress(
            ctx["workspace"],
            event=event,
            message=message,
            runs_root=runs_root,
            analyzer="business-flow",
            **details,
        )

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        graph = ctx["graph"]

        # 1. 拉骨架节点(函数/方法)并补出真实调用边。
        skeleton_nodes = _collect_skeleton_nodes(graph)
        call_edges = _collect_call_edges(graph, skeleton_nodes)
        settings = ctx["config"].get(self.name, {})
        max_tokens = settings.get("max_tokens", HEAVY_MAX_TOKENS) if isinstance(settings, dict) else HEAVY_MAX_TOKENS
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            max_tokens = HEAVY_MAX_TOKENS
        batch_size = settings.get("batch_size", 8) if isinstance(settings, dict) else 8
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            batch_size = 8
        strict_outputs = ctx["config"].get("strict_outputs") is True
        merged: dict[str, Any] = {section: [] for section in _ENRICHMENT_SECTIONS}

        # Split large repositories into bounded prompts. Each batch is normalized
        # independently, then merged so a single response cannot consume the whole
        # provider reasoning budget before producing structured JSON.
        batches = [skeleton_nodes[offset : offset + batch_size] for offset in range(0, len(skeleton_nodes), batch_size)]
        self._progress(
            ctx,
            event="analyzer_plan",
            message=f"业务流富化将分析 {len(skeleton_nodes)} 个函数/方法，共 {len(batches)} 个批次",
            node_count=len(skeleton_nodes),
            edge_count=len(call_edges),
            batch_size=batch_size,
            batch_count=len(batches),
        )
        for batch_index, batch_nodes in enumerate(batches, start=1):
            batch_started = time.monotonic()
            self._progress(
                ctx,
                event="batch_started",
                message=f"开始业务流批次 {batch_index}/{len(batches)}，包含 {len(batch_nodes)} 个节点",
                batch_index=batch_index,
                batch_count=len(batches),
                node_count=len(batch_nodes),
            )
            batch_ids = {str(node.get("id")) for node in batch_nodes if isinstance(node.get("id"), str)}
            batch_edges = [edge for edge in call_edges if edge.get("from") in batch_ids and edge.get("to") in batch_ids]
            context_text = _build_context(batch_nodes, ctx["source"])
            prompt = self._load_prompt()
            prompt = prompt.replace("{{SKELETON}}", _skeleton_json(batch_nodes, batch_edges))
            prompt = prompt.replace("{{CONTEXT}}", context_text)
            raw = ctx["llm"].complete(system=_SYSTEM, prompt=prompt, max_tokens=max_tokens)

            parsed = _parse_json_object(raw)
            if strict_outputs and parsed is None:
                self._progress(
                    ctx,
                    event="batch_failed",
                    message=f"业务流批次 {batch_index}/{len(batches)} 返回了无效 JSON",
                    level="error",
                    batch_index=batch_index,
                    batch_count=len(batches),
                    response_chars=len(raw),
                )
                raise BusinessFlowOutputError("business-flow analyzer returned invalid JSON")
            if parsed is not None and len(batches) > 1:
                _namespace_batch_ids(parsed, batch_index)
            _merge_enrichment(merged, _assemble_enrichment(parsed, batch_nodes))
            elapsed = round(time.monotonic() - batch_started, 1)
            self._progress(
                ctx,
                event="batch_completed",
                message=f"业务流批次 {batch_index}/{len(batches)} 完成，耗时 {elapsed:.1f} 秒",
                level="success" if parsed is not None else "warning",
                batch_index=batch_index,
                batch_count=len(batches),
                elapsed_seconds=elapsed,
                parsed=parsed is not None,
            )

        if strict_outputs and skeleton_nodes and not (merged["endpoints"] or merged["handlers"]):
            raise BusinessFlowOutputError("business-flow analyzer returned no usable endpoints or handlers")

        # 富化器不产 finding。
        return {"analyzer": self.name, "findings": [], "enrichment": merged}


# === 骨架抽取 ===


def _collect_skeleton_nodes(graph: GraphHandle) -> list[dict[str, Any]]:
    """从 codegraph 拉出函数/方法节点作为候选 handler 骨架。

    GraphHandle 协议没有"列出全部节点"的方法;空串 query 借 LIKE '%%' 命中所有节点,
    再按 kind 过滤到函数/方法。
    """
    all_nodes = graph.query("")
    return [node for node in all_nodes if str(node.get("kind", "")) in _HANDLER_KINDS]


def _collect_call_edges(graph: GraphHandle, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """沿 codegraph 的 calls 边为骨架节点补出真实调用关系(谁调用谁)。

    对每个骨架节点查询 callees(它调用了谁)与 callers(谁调用了它),合并去重成有向边。
    只保留 **两端都在骨架 node 集合内** 的边:callers/callees 可能返回骨架外的符号
    (如第三方库函数),这类悬空边对下游业务流分析无意义,直接丢弃。
    为防大仓 prompt 爆炸与查询过多:最多探查 `_MAX_CALL_EDGE_PROBE_NODES` 个节点,
    且总边数达到 `_MAX_CALL_EDGES` 即停止。
    """
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    skeleton_ids = {str(node.get("id")) for node in nodes if isinstance(node.get("id"), str) and node.get("id")}

    for node in nodes[:_MAX_CALL_EDGE_PROBE_NODES]:
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id:
            continue
        node_name = node.get("name")

        # node_id 调用了谁:node_id -> callee
        for callee in graph.callees(node_id):
            if _append_call_edge(edges, seen, skeleton_ids, node_id, node_name, callee.get("id"), callee.get("name")):
                if len(edges) >= _MAX_CALL_EDGES:
                    return edges

        # 谁调用了 node_id:caller -> node_id
        for caller in graph.callers(node_id):
            if _append_call_edge(edges, seen, skeleton_ids, caller.get("id"), caller.get("name"), node_id, node_name):
                if len(edges) >= _MAX_CALL_EDGES:
                    return edges

    return edges


def _append_call_edge(
    edges: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    skeleton_ids: set[str],
    from_id: Any,
    from_name: Any,
    to_id: Any,
    to_name: Any,
) -> bool:
    """把一条 (from_id -> to_id) 调用边去重后追加。追加成功返回 True。

    两端都须是骨架内的合法 node id;任一端悬空(不在 `skeleton_ids`)则丢弃。
    """
    if not isinstance(from_id, str) or not from_id or not isinstance(to_id, str) or not to_id:
        return False
    if from_id not in skeleton_ids or to_id not in skeleton_ids:
        return False
    key = (from_id, to_id)
    if key in seen:
        return False
    seen.add(key)
    edges.append(
        {
            "from": from_id,
            "from_name": from_name,
            "rel": "calls",
            "to": to_id,
            "to_name": to_name,
        }
    )
    return True


def _skeleton_json(nodes: list[dict[str, Any]], call_edges: list[dict[str, Any]]) -> str:
    """把骨架节点 + 调用边压成紧凑 JSON 喂给 LLM,只保留定位、签名与调用关系。"""
    compact_nodes = [
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
    skeleton = {"nodes": compact_nodes, "call_edges": call_edges}
    return json.dumps(skeleton, ensure_ascii=False, indent=2)


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


def _merge_enrichment(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Merge normalized batch sections while preserving stable first-seen order."""
    for section in _ENRICHMENT_SECTIONS:
        existing = target[section]
        seen = {
            item.get("id") if isinstance(item, dict) and item.get("id") else json.dumps(item, sort_keys=True)
            for item in existing
        }
        for item in source[section]:
            key = item.get("id") if isinstance(item, dict) and item.get("id") else json.dumps(item, sort_keys=True)
            if key not in seen:
                existing.append(item)
                seen.add(key)


def _namespace_batch_ids(parsed: dict[str, Any], batch_index: int) -> None:
    """Make LLM-local entity IDs unique and keep their internal references intact."""
    mapping: dict[str, str] = {}
    for section in ("endpoints", "handlers", "resources", "operations"):
        items = parsed.get(section)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                continue
            original = item["id"]
            namespaced = f"batch-{batch_index}:{original}"
            mapping[original] = namespaced
            item["id"] = namespaced

    edges = parsed.get("edges")
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            for field in ("from", "to"):
                value = edge.get(field)
                if isinstance(value, str) and value in mapping:
                    edge[field] = mapping[value]

    flows = parsed.get("business_flows")
    if isinstance(flows, list):
        for flow in flows:
            if not isinstance(flow, dict):
                continue
            endpoint_id = flow.get("endpoint_id")
            if isinstance(endpoint_id, str) and endpoint_id in mapping:
                flow["endpoint_id"] = mapping[endpoint_id]
            related = flow.get("related_endpoint_ids")
            if isinstance(related, list):
                flow["related_endpoint_ids"] = [mapping.get(item, item) for item in related]


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

    每个段缺省为空 list,且逐条只保留合法对象(非 dict 条目丢弃并记 warning);
    解析失败(parsed=None)时全空,但结构完整。下游无需任何防御性判空/判型。
    """
    # 各段先取原始 list(非 list 或缺失得到空 list)。
    raw_sections = {section: _as_list(parsed, section) for section in _ENRICHMENT_SECTIONS}

    valid_ids = {str(node.get("id")) for node in skeleton_nodes if node.get("id") is not None}
    name_index = _build_name_index(skeleton_nodes)

    enrichment: dict[str, Any] = {}
    # 保留原样(仅丢弃非 dict)的段。
    enrichment["resources"] = _coerce_dict_entries(raw_sections["resources"], "resources")
    enrichment["operations"] = _coerce_dict_entries(raw_sections["operations"], "operations")
    enrichment["edges"] = _coerce_dict_entries(raw_sections["edges"], "edges")
    # 需要锚回真实 node_id 的段。
    enrichment["handlers"] = _anchor_handlers(raw_sections["handlers"], valid_ids, name_index)
    handler_node_id = {str(h.get("id")): h.get("node_id") for h in enrichment["handlers"] if h.get("id") is not None}
    endpoint_to_handler = _handled_by_map(enrichment["edges"])
    enrichment["endpoints"] = _anchor_endpoints(
        raw_sections["endpoints"], valid_ids, endpoint_to_handler, handler_node_id
    )
    # 合法 endpoint id 集合:business_flows 的 endpoint_id/related_endpoint_ids 引用完整性校验用。
    valid_endpoint_ids = {
        str(ep.get("id")) for ep in enrichment["endpoints"] if isinstance(ep.get("id"), str) and ep.get("id")
    }
    # 业务流:丢非法条目 + 校验必需字段与引用完整性 + 规整可选扩展字段与嵌套对象。
    enrichment["business_flows"] = _normalize_business_flows(raw_sections["business_flows"], valid_endpoint_ids)

    return enrichment


def _as_list(parsed: dict[str, Any] | None, key: str) -> list[Any]:
    """从 parsed 里取 key;不是 list(含 None / parsed 本身为 None)时返回空 list。"""
    if parsed is None:
        return []
    value = parsed.get(key)
    if isinstance(value, list):
        return value
    return []


def _coerce_dict_entries(items: list[Any], section: str) -> list[dict[str, Any]]:
    """只保留 items 中的 dict 条目(原样);非 dict 条目丢弃并记 warning。"""
    kept: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if isinstance(item, dict):
            kept.append(item)
        else:
            logger.warning("Discarding %s entry %d: expected object, got %s", section, index, type(item).__name__)
    return kept


def _str_list(value: Any) -> list[str]:
    """把 value 规整成字符串列表:非 list 返回 [];list 内非字符串项丢弃。"""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _coerce_bool(value: Any) -> bool:
    """把 value 强制成 bool:仅真正的 bool 透传,其它一律 False(缺省/类型不符时的安全默认)。"""
    return value if isinstance(value, bool) else False


def _optional_string(value: Any) -> str | None:
    """string 透传,其它(含 None / 非 string)一律 None。"""
    return value if isinstance(value, str) else None


def _string_or_empty(value: Any) -> str:
    """string 透传,其它一律空串。"""
    return value if isinstance(value, str) else ""


def _normalize_trust_boundary(item: dict[str, Any]) -> dict[str, Any] | None:
    """逐字段规整 trust_boundary:field/source 须非空 string(否则丢);validated 强制 bool;note 缺省空串。"""
    field = _required_string(item.get("field"))
    source = _required_string(item.get("source"))
    if field is None or source is None:
        return None
    return {
        "field": field,
        "source": source,
        "validated": _coerce_bool(item.get("validated")),
        "note": _string_or_empty(item.get("note")),
    }


def _normalize_state_transition(item: dict[str, Any]) -> dict[str, Any] | None:
    """逐字段规整 state_transition:from/to 须非空 string(否则丢);note 缺省空串。"""
    from_state = _required_string(item.get("from"))
    to_state = _required_string(item.get("to"))
    if from_state is None or to_state is None:
        return None
    return {
        "from": from_state,
        "to": to_state,
        "note": _string_or_empty(item.get("note")),
    }


def _normalize_authorization_check(item: dict[str, Any]) -> dict[str, Any] | None:
    """逐字段规整 authorization_check:requirement 须非空 string(否则丢);enforced 强制 bool;
    enforced_by 为 string 或 None;note 缺省空串。区分「授权要求」与「是否真执行了校验」。
    """
    requirement = _required_string(item.get("requirement"))
    if requirement is None:
        return None
    return {
        "requirement": requirement,
        "enforced": _coerce_bool(item.get("enforced")),
        "enforced_by": _optional_string(item.get("enforced_by")),
        "note": _string_or_empty(item.get("note")),
    }


# 逐字段规整器签名:输入一个 dict 条目,返回规整后的 dict,或判非法时返回 None(丢弃)。
_NestedNormalizer = Callable[[dict[str, Any]], dict[str, Any] | None]

# business_flows[] 对象列表字段 → 逐字段规整器。非 dict 条目与规整器判非法(返回 None)的条目均丢弃。
_NESTED_OBJECT_NORMALIZERS: dict[str, _NestedNormalizer] = {
    "trust_boundaries": _normalize_trust_boundary,
    "state_transitions": _normalize_state_transition,
    "authorization_checks": _normalize_authorization_check,
}


def _normalize_dict_list(value: Any, normalizer: _NestedNormalizer) -> list[dict[str, Any]]:
    """把 value 规整成对象列表:非 list 返回 [];非 dict 项丢弃;逐字段规整器返回 None 的项丢弃。"""
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        result = normalizer(item)
        if result is not None:
            normalized.append(result)
    return normalized


def _build_name_index(nodes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """建 name → 该名下所有骨架节点 的映射,供 handler 按名消歧锚回(不丢弃同名节点)。"""
    index: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        name = node.get("name")
        node_id = node.get("id")
        if isinstance(name, str) and name and isinstance(node_id, str) and node_id:
            index.setdefault(name, []).append(node)
    return index


def _required_string(value: Any) -> str | None:
    """非空字符串(strip 后非空)返回其本身,否则 None。"""
    return value if isinstance(value, str) and value.strip() else None


def _resolve_handler_node_id(
    handler: dict[str, Any],
    valid_ids: set[str],
    name_index: dict[str, list[dict[str, Any]]],
) -> str | None:
    """确定 handler 的真实 node_id,同名跨文件时消歧;无法唯一确定时返回 None(不瞎猜)。

    1. LLM 给的 node_id 若在图中真实存在,直接采用。
    2. 否则按 name 取候选;唯一则用之。
    3. 多个同名候选时,用 source_ref/file_path/qualified_name 缩小到唯一匹配;仍不唯一则 None。
    """
    provided = handler.get("node_id")
    if isinstance(provided, str) and provided in valid_ids:
        return provided

    name = handler.get("name")
    if not isinstance(name, str):
        return None

    candidates = name_index.get(name, [])
    if not candidates:
        return None
    if len(candidates) == 1:
        node_id = candidates[0].get("id")
        return node_id if isinstance(node_id, str) else None

    return _disambiguate_by_location(candidates, handler)


def _disambiguate_by_location(candidates: list[dict[str, Any]], handler: dict[str, Any]) -> str | None:
    """在同名候选中用 handler 的 source_ref/file_path/qualified_name 精确定位到唯一节点。"""
    hint_files = _location_hint_files(handler)
    hint_qualified = handler.get("qualified_name")

    matched: list[dict[str, Any]] = []
    for node in candidates:
        node_file = node.get("file_path")
        node_qualified = node.get("qualified_name")
        file_hit = isinstance(node_file, str) and node_file in hint_files
        qualified_hit = isinstance(hint_qualified, str) and bool(hint_qualified) and node_qualified == hint_qualified
        if file_hit or qualified_hit:
            matched.append(node)

    if len(matched) == 1:
        node_id = matched[0].get("id")
        return node_id if isinstance(node_id, str) else None
    return None


def _location_hint_files(handler: dict[str, Any]) -> set[str]:
    """从 handler 的 source_ref('路径:行号')与 file_path 抽出用于消歧的文件路径集合。"""
    files: set[str] = set()
    source_ref = handler.get("source_ref")
    if isinstance(source_ref, str) and source_ref:
        # source_ref 形如 "相对路径:行号";剥掉尾部行号得到文件路径。
        files.add(source_ref.rsplit(":", 1)[0])
    file_path = handler.get("file_path")
    if isinstance(file_path, str) and file_path:
        files.add(file_path)
    return files


def _anchor_handlers(
    handlers: list[Any],
    valid_ids: set[str],
    name_index: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """规整 handler 条目(丢弃非 dict),补齐 node_id(消歧后锚回真实节点或 None)。"""
    anchored: list[dict[str, Any]] = []
    for index, handler in enumerate(handlers):
        if not isinstance(handler, dict):
            logger.warning("Discarding handlers entry %d: expected object, got %s", index, type(handler).__name__)
            continue
        node_id = _resolve_handler_node_id(handler, valid_ids, name_index)
        anchored.append(
            {
                "id": handler.get("id"),
                "name": handler.get("name"),
                "source_ref": handler.get("source_ref"),
                "node_id": node_id,
            }
        )
    return anchored


def _handled_by_map(edges: list[dict[str, Any]]) -> dict[str, str]:
    """从 edges 抽出 endpoint_id → handler_id(rel == 'handled_by')。"""
    mapping: dict[str, str] = {}
    for edge in edges:
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
    """规整 endpoint 条目(丢弃非 dict);node_id 优先取 LLM 给的真实 id,否则经 handled_by 边取 handler 的 node_id。"""
    anchored: list[dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            logger.warning("Discarding endpoints entry %d: expected object, got %s", index, type(endpoint).__name__)
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


def _normalize_business_flows(flows: list[Any], valid_endpoint_ids: set[str]) -> list[dict[str, Any]]:
    """规整 business_flows:丢非法/缺必需字段/悬空引用的条目,把可选扩展字段规整为稳定类型。

    - 非 dict 条目丢弃。
    - 缺 endpoint_id 或 intent(须为非空字符串)的条目丢弃。
    - **引用完整性**:endpoint_id 不在 `valid_endpoint_ids`(不指向真实 endpoint)的整条 flow 丢弃;
      related_endpoint_ids 只保留存在于 `valid_endpoint_ids` 的 id(悬空 id 过滤掉)。
    - 字符串列表字段(preconditions 等)缺省/类型不符 → 空 list,list 内非字符串项丢弃。
    - 对象列表字段(trust_boundaries / state_transitions / authorization_checks)缺省/类型不符 → 空 list;
      非 dict 项丢弃;逐字段规整(必需子字段缺失的条目丢弃,其余子字段强制到稳定类型)。
    """
    normalized: list[dict[str, Any]] = []
    for index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            logger.warning("Discarding business_flows entry %d: expected object, got %s", index, type(flow).__name__)
            continue

        endpoint_id = _required_string(flow.get("endpoint_id"))
        intent = _required_string(flow.get("intent"))
        if endpoint_id is None or intent is None:
            logger.warning("Discarding business_flows entry %d: missing required endpoint_id/intent", index)
            continue

        if endpoint_id not in valid_endpoint_ids:
            logger.warning(
                "Discarding business_flows entry %d: endpoint_id %r does not reference any endpoint",
                index,
                endpoint_id,
            )
            continue

        entry: dict[str, Any] = {"endpoint_id": endpoint_id, "intent": intent}
        for field in _FLOW_STR_LIST_FIELDS:
            entry[field] = _str_list(flow.get(field))
        # related_endpoint_ids 引用完整性:只保留指向真实 endpoint 的 id。
        entry["related_endpoint_ids"] = [
            ep_id for ep_id in entry["related_endpoint_ids"] if ep_id in valid_endpoint_ids
        ]
        for field in _FLOW_DICT_LIST_FIELDS:
            entry[field] = _normalize_dict_list(flow.get(field), _NESTED_OBJECT_NORMALIZERS[field])
        normalized.append(entry)

    return normalized


# 模块级实例 —— 注册表按约定发现。
ANALYZER = BusinessFlowAnalyzer()
