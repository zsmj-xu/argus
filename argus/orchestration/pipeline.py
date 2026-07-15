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

import os
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
    """
    selected = _selected_names(state, phase)
    to_run = [analyzers[name] for name in selected if name in analyzers and analyzers[name].phase is phase]

    if not to_run:
        return {"completed_nodes": [*state["completed_nodes"], node_name]}

    graph: GraphHandle = CodegraphHandle(state["graph_db_path"])
    ctx = _build_context(state, graph)

    merged_enriched: dict[str, Any] = dict(state["enriched"])
    new_findings: list[Finding] = list(state["findings"])

    for analyzer in to_run:
        result = analyzer.run(ctx)
        merged_enriched.update(result.get("enrichment", {}))
        new_findings.extend(result.get("findings", []))

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
