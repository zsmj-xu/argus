"""LangGraph 管道装配 —— 节点顺序、分析器执行、checkpoint 编译。

节点顺序:
    build_graph → enrichment → review-enrichment → vuln → review-findings → report

- build_graph:图 db 已存在则跳过建图(测试可注入 fixture db),否则调 build_graph()。
- enrichment / vuln:跑注册表里对应 phase 的分析器(M1 可能为空)。
- review-*:interrupt 检查点(见 checkpoints.py),按 config 决定是否停顿。
- report:M1 先写占位 markdown 到 runs/<ws>/report.md。

每个节点执行完把节点名 append 到 state.completed_nodes。节点串行执行,故直接返回
"旧值 + 追加" 的完整新列表即可,无需为 ArgusState 加 reducer 注解。
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from langgraph.graph import END, START, StateGraph

from argus.contracts import (
    AnalysisContext,
    Analyzer,
    ArgusState,
    Finding,
    GraphHandle,
    LLMClient,
    Phase,
    SourceAccess,
    SourceMode,
)
from argus.graph.build import build_graph
from argus.graph.codegraph import CodegraphHandle
from argus.llm.client import AuditedLLM
from argus.orchestration.checkpoints import (
    REVIEW_ENRICHMENT,
    REVIEW_FINDINGS,
    review_enrichment,
    review_findings,
)
from argus.reporting.report import render_report

# 节点名常量(与 completed_nodes 里记录的名字一致)。
NODE_BUILD_GRAPH = "build_graph"
NODE_ENRICHMENT = "enrichment"
NODE_VULN = "vuln"
NODE_REPORT = "report"


class _FileSourceAccess:
    """最小 SourceAccess 实现:按 repo_path 读文件(可选行范围)。

    M1 只做原样读取;stripped 模式的注释/docstring 剥离留待后续任务。
    """

    def __init__(self, repo_path: str, mode: SourceMode) -> None:
        self.repo_path = repo_path
        self.mode = mode

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        abs_path = path if os.path.isabs(path) else os.path.join(self.repo_path, path)
        with open(abs_path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()

        if start is None and end is None:
            return "".join(lines)

        lo = (start - 1) if start else 0
        hi = end if end else len(lines)
        return "".join(lines[lo:hi])


def _json_default(value: object) -> Any:
    """json.dump 的兜底序列化器。

    Severity/Confidence 是 (str, Enum);取 `.value` 落成纯字符串,反序列化回来即干净的
    str,不会残留枚举对象。其余不可序列化对象退化成 str,保证 json.dump 永不因未知类型崩。
    """
    if hasattr(value, "value"):
        return value.value
    return str(value)


def _atomic_write_json(path: str, obj: Any) -> None:
    """把 obj 以 JSON 原子写到 path:临时文件 + os.replace。

    - 先 makedirs 确保父目录存在。
    - 写到同目录下的临时文件再 os.replace,避免 interrupt 时暴露半写文件。
    - 用 _json_default 序列化枚举(Severity/Confidence)等非原生类型。
    """
    dirname = os.path.dirname(path) or "."
    os.makedirs(dirname, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dirname, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, default=_json_default, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _runs_root_from_state(state: ArgusState) -> str:
    """从 report_path(<runs_root>/<ws>/report.md)反推 runs_root。"""
    return os.path.dirname(os.path.dirname(state["report_path"]))


def _build_context(state: ArgusState, graph: GraphHandle) -> AnalysisContext:
    """为分析器组装只读 AnalysisContext。

    LLM 用环境变量里的 api_key 现建;M1 分析器不实际调 LLM,故无 key 也能构造
    (仅在真正 complete() 时才需要网络)。
    """
    runs_root = _runs_root_from_state(state)
    llm: LLMClient = AuditedLLM(
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        workspace=state["workspace"],
        runs_root=runs_root,
    )
    source: SourceAccess = _FileSourceAccess(state["repo_path"], state["source_mode"])

    return {
        "graph": graph,
        "enriched": state["enriched"],
        "source": source,
        "config": state["config"],
        "llm": llm,
        "workspace": state["workspace"],
    }


def _selected_names(state: ArgusState, phase: Phase) -> list[str]:
    """从 config.analyzers.<phase> 读取本阶段应跑的分析器 name 列表。"""
    analyzers_cfg = state["config"].get("analyzers", {})
    if phase is Phase.ENRICHMENT:
        return list(analyzers_cfg.get("enrichment", []))
    return list(analyzers_cfg.get("vuln", []))


def _persist_phase_artifact(
    state: ArgusState,
    phase: Phase,
    enriched: dict[str, Any],
    findings: list[Finding],
) -> None:
    """把本阶段产物确定性落盘到 ArgusState 里约定的路径。

    - enrichment → enriched_graph_path 写富化 dict(空阶段即 {})。
    - vuln → findings_path 写 findings 列表(空阶段即 [];枚举经 _json_default 转字符串)。
    interrupt 检查点在本节点之后才停顿,故此处落盘保证:停在检查点时对应文件已存在,
    内容即 checkpoint state 里的值。
    """
    if phase is Phase.ENRICHMENT:
        _atomic_write_json(state["enriched_graph_path"], enriched)
    else:
        _atomic_write_json(state["findings_path"], findings)


def _run_phase(
    state: ArgusState,
    analyzers: dict[str, Analyzer],
    phase: Phase,
    node_name: str,
) -> dict[str, Any]:
    """跑某一阶段:按 config 选中且已注册的分析器,合并其产物。

    - enrichment 产物合并进 state.enriched(供下游漏洞分析器读)。
    - findings 累加进 state.findings。
    未在注册表里的名字静默跳过(M1 注册表可能为空)。
    无论是否有分析器运行,本阶段产物都会落盘(空阶段写合法空 {} / [])。
    """
    selected = _selected_names(state, phase)
    to_run = [analyzers[name] for name in selected if name in analyzers and analyzers[name].phase is phase]

    if not to_run:
        # 无分析器:产物保持 state 现值(enrichment 通常 {},vuln 通常 []),仍确定性落盘。
        _persist_phase_artifact(state, phase, dict(state["enriched"]), list(state["findings"]))
        return {"completed_nodes": [*state["completed_nodes"], node_name]}

    graph: GraphHandle = CodegraphHandle(state["graph_db_path"])
    ctx = _build_context(state, graph)

    merged_enriched: dict[str, Any] = dict(state["enriched"])
    new_findings: list[Finding] = list(state["findings"])

    for analyzer in to_run:
        result = analyzer.run(ctx)
        merged_enriched.update(result.get("enrichment", {}))
        new_findings.extend(result.get("findings", []))

    _persist_phase_artifact(state, phase, merged_enriched, new_findings)

    return {
        "enriched": merged_enriched,
        "findings": new_findings,
        "completed_nodes": [*state["completed_nodes"], node_name],
    }


def build_graph_node(state: ArgusState) -> dict[str, Any]:
    """建图节点:db 已存在则跳过(接受注入的 fixture db),否则调 codegraph build_graph。"""
    db_path = state["graph_db_path"]
    if db_path and os.path.exists(db_path):
        resolved = db_path
    else:
        resolved = build_graph(state["repo_path"])

    return {
        "graph_db_path": resolved,
        "completed_nodes": [*state["completed_nodes"], NODE_BUILD_GRAPH],
    }


def report_node(state: ArgusState) -> dict[str, Any]:
    """报告节点:把 findings 确定性渲染为 markdown 并写到 runs/<ws>/report.md。"""
    report_path = state["report_path"]
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    markdown = render_report(state["findings"], state)
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(markdown)

    return {"completed_nodes": [*state["completed_nodes"], NODE_REPORT]}


def build_pipeline(analyzers: dict[str, Analyzer], checkpointer: Any) -> Any:
    """装配并编译 LangGraph 管道。

    analyzers:注册表(或测试注入的)分析器字典。checkpointer:SqliteSaver。
    返回编译后的图(CompiledStateGraph),用 checkpointer 持久化状态。
    """

    def enrichment_node(state: ArgusState) -> dict[str, Any]:
        return _run_phase(state, analyzers, Phase.ENRICHMENT, NODE_ENRICHMENT)

    def vuln_node(state: ArgusState) -> dict[str, Any]:
        return _run_phase(state, analyzers, Phase.VULN_ANALYSIS, NODE_VULN)

    graph = StateGraph(ArgusState)
    graph.add_node(NODE_BUILD_GRAPH, build_graph_node)
    graph.add_node(NODE_ENRICHMENT, enrichment_node)
    graph.add_node(REVIEW_ENRICHMENT, review_enrichment)
    graph.add_node(NODE_VULN, vuln_node)
    graph.add_node(REVIEW_FINDINGS, review_findings)
    graph.add_node(NODE_REPORT, report_node)

    graph.add_edge(START, NODE_BUILD_GRAPH)
    graph.add_edge(NODE_BUILD_GRAPH, NODE_ENRICHMENT)
    graph.add_edge(NODE_ENRICHMENT, REVIEW_ENRICHMENT)
    graph.add_edge(REVIEW_ENRICHMENT, NODE_VULN)
    graph.add_edge(NODE_VULN, REVIEW_FINDINGS)
    graph.add_edge(REVIEW_FINDINGS, NODE_REPORT)
    graph.add_edge(NODE_REPORT, END)

    return graph.compile(checkpointer=checkpointer)
