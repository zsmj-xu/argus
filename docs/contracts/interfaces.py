"""Argus 核心接口契约 —— 权威定义(冻结)。

这是编排层与分析器之间唯一的耦合点。任何人写实现前不得私自修改;
改动须走 docs/COLLABORATION.md 的契约变更流程。

M1 会把本文件落成可导入的 argus/contracts.py 并加契约一致性测试;
两者必须逐字一致。
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, TypedDict, runtime_checkable


# ============================================================
# 枚举
# ============================================================


class Phase(str, Enum):
    """分析器所属阶段。富化器产语义,漏洞分析器产 Finding。"""

    ENRICHMENT = "enrichment"
    VULN_ANALYSIS = "vuln_analysis"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceMode(str, Enum):
    """喂给 LLM 的源码模式。stripped 去注释/docstring,防靶场教学注释泄露答案。"""

    RAW = "raw"
    STRIPPED = "stripped"


# ============================================================
# Finding —— 统一输出契约
# ============================================================


class CodeLocation(TypedDict):
    """一条 Finding 锚回代码的位置。node_id 必须是 codegraph 中真实存在的节点 id。"""

    file: str
    line: int
    node_id: str  # 强制锚回 codegraph 节点(如 "file:api/coupons.py" 或函数/方法节点 id)


class Finding(TypedDict):
    """所有分析器(含实验性的 invariant)统一的产出。报告与对照评测都依赖此结构。"""

    id: str  # 稳定唯一 id,建议 f"{analyzer}:{vuln_class}:{短哈希}"
    analyzer: str  # 产出该 finding 的分析器 name
    vuln_class: str  # "injection" / "authz" / "business-logic" / ...
    title: str
    severity: Severity
    confidence: Confidence
    locations: list[CodeLocation]  # 至少一条;每条锚回真实 node_id
    data_flow: str  # 从入口到危险点的数据/控制流描述(可为空串)
    rationale: str  # 为什么这是漏洞
    evidence: str  # 支撑证据(代码片段引用、图查询结果等)
    remediation: str  # 修复建议


# ============================================================
# AnalysisContext —— 统一输入契约(只读)
# ============================================================


@runtime_checkable
class GraphHandle(Protocol):
    """codegraph 的只读句柄。封装对 codegraph CLI/DB 的访问,分析器不直接碰 SQLite。

    M1 提供最小实现;方法签名冻结,内部实现可演进。
    """

    def query(self, search: str) -> list[dict[str, Any]]:
        """按符号名/关键词搜索节点。对应 codegraph query。"""
        ...

    def node(self, node_id: str) -> dict[str, Any] | None:
        """取单个节点的详情(源码 + caller/callee trail)。对应 codegraph node。"""
        ...

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        """谁调用了该符号。对应 codegraph callers。"""
        ...

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        """该符号调用了谁。对应 codegraph callees。"""
        ...

    def explore(self, query: str) -> str:
        """探索一个区域:相关符号源码 + 调用路径,一次返回。对应 codegraph explore。"""
        ...


@runtime_checkable
class SourceAccess(Protocol):
    """目标仓库源码的只读访问。按 source_mode 决定是否 strip 注释/docstring。"""

    mode: SourceMode

    def read(self, path: str, start: int | None = None, end: int | None = None) -> str:
        """读文件(可选行范围)。mode=stripped 时返回去注释/docstring 后的内容,保留行号。"""
        ...


@runtime_checkable
class LLMClient(Protocol):
    """LLM 客户端(带审计包装)。分析器通过它调模型,调用会被审计记录。"""

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        """单轮补全,返回文本。"""
        ...


class AnalysisContext(TypedDict):
    """所有分析器拿到的同一份只读输入。这是"共享事实层"的落地。"""

    graph: GraphHandle
    enriched: dict[str, Any]  # 上游富化产物(enriched-graph);ENRICHMENT 阶段可能为空 {}
    source: SourceAccess
    config: dict[str, Any]  # 人注入的领域知识:角色映射、身份认证上下文、focus/avoid 规则
    llm: LLMClient
    workspace: str  # 当前 workspace 名,分析器可据此定位 runs/<ws>/ 下的产物


# ============================================================
# AnalyzerResult —— 分析器返回
# ============================================================


class AnalyzerResult(TypedDict):
    """分析器 run() 的返回。

    findings:漏洞分析器产出(富化器通常为空 [])。
    enrichment:富化器产出,会被合并进 enriched-graph 供下游读(漏洞分析器通常为 {})。
    """

    analyzer: str
    findings: list[Finding]
    enrichment: dict[str, Any]


# ============================================================
# Analyzer —— 分析器协议
# ============================================================


@runtime_checkable
class Analyzer(Protocol):
    """可插拔分析器。放在 argus/analyzers/<name>/,由注册表自动发现。

    编排层只认这个协议,不认识任何具体分析器。加分析器 = 加目录 + 注册,不碰编排。
    """

    name: str  # 唯一标识,如 "injection" / "business-flow" / "invariant"
    phase: Phase  # 所属阶段
    requires: list[str]  # 依赖的产物 key(如 ["enriched-graph"]);编排据此拓扑排序

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        ...


# ============================================================
# ArgusState —— LangGraph 共享状态
# ============================================================


class ArgusState(TypedDict):
    """LangGraph StateGraph 的共享状态,由 SqliteSaver 持久化到 runs/<ws>/state.db。"""

    repo_path: str  # 目标仓库绝对路径
    workspace: str
    config: dict[str, Any]  # 合并后的配置(YAML + 命令行 --set 注入)
    source_mode: SourceMode

    # 各阶段产物路径(落盘 JSON/MD,人可直接编辑后 continue)
    graph_db_path: str  # .codegraph/codegraph.db
    enriched_graph_path: str  # runs/<ws>/enriched-graph.json
    findings_path: str  # runs/<ws>/findings.json
    report_path: str  # runs/<ws>/report.md

    # 累积产出
    enriched: dict[str, Any]
    findings: list[Finding]

    # 编排游标
    completed_nodes: list[str]  # 已完成的节点名,resume 时跳过
