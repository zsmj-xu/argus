"""编排 checkpoint/resume 测试。

关键断言:resume 后已完成节点不重跑。用 SqliteSaver(tmp_path 下的 db)+ 一个
注入的 MockVuln 分析器,不依赖真 LLM / 真 codegraph(用 fixture mini.db 绕过建图)。

流程:build_graph(skip,db 已存在)→ enrichment(空)→ review-enrichment(跳过)
→ vuln(跑 MockVuln)→ review-findings(interrupt 停下)→ report。
第一次 invoke 在 review-findings 停下时 MockVuln 已跑一次;resume 直接跑 report,
MockVuln 不应再被调用。
"""

from __future__ import annotations

import os
from typing import Any

from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.orchestration.checkpoints import make_checkpointer
from argus.orchestration.pipeline import build_pipeline
from argus.orchestration.state import make_initial_state

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


class MockVuln:
    """注入用的假漏洞分析器,记录 run() 被调用的次数。"""

    name = "mock"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self) -> None:
        self.calls = 0

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        self.calls += 1
        return {"analyzer": self.name, "findings": [], "enrichment": {}}


def _thread_config(workspace: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": workspace}}


def test_completed_node_not_rerun_on_resume(tmp_path: Any) -> None:
    workspace = "pipe-test"
    runs_root = str(tmp_path / "runs")

    # 只在 review-findings 处 interrupt,让 vuln 先跑完再停下。
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["mock"]},
        "checkpoints": ["review-findings"],
        "source_mode": "raw",
    }
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    # 用 fixture db 绕过真实建图:build_graph 节点见到已存在的 db 即跳过。
    state["graph_db_path"] = FIXTURE_DB

    mock = MockVuln()
    analyzers: dict[str, Any] = {"mock": mock}

    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline(analyzers, checkpointer)
    cfg = _thread_config(workspace)

    # 第一次:跑到 review-findings 停下,MockVuln 已跑一次。
    result = app.invoke(state, cfg)
    assert "__interrupt__" in result
    assert mock.calls == 1
    assert "vuln" in result["completed_nodes"]
    assert "report" not in result["completed_nodes"]

    # resume:直接跑 report,已完成的 vuln 不重跑。
    from langgraph.types import Command

    final = app.invoke(Command(resume="approved"), cfg)
    assert mock.calls == 1  # 关键:vuln 未因 resume 再次执行
    assert "report" in final["completed_nodes"]


def test_yolo_skips_all_interrupts(tmp_path: Any) -> None:
    workspace = "yolo-test"
    runs_root = str(tmp_path / "runs")

    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["mock"]},
        "checkpoints": False,  # --yolo 等价:全关
        "source_mode": "raw",
    }
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    state["graph_db_path"] = FIXTURE_DB

    mock = MockVuln()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"mock": mock}, checkpointer)

    # checkpoints=False:一次 invoke 直接跑到 report,不停顿。
    final = app.invoke(state, _thread_config(workspace))
    assert "__interrupt__" not in final
    assert mock.calls == 1
    for node in ("build_graph", "enrichment", "review-enrichment", "vuln", "review-findings", "report"):
        assert node in final["completed_nodes"]
    assert os.path.exists(final["report_path"])
