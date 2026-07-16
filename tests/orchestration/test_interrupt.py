"""interrupt 检查点 + continue 放行测试。

关键断言:检查点真正暂停图执行(interrupt),且暂停时下游节点尚未运行。用注入的
计数分析器(MockVuln.calls)证明"停在 interrupt 时 vuln 未执行 / continue 后才执行",
而非恒真断言。SqliteSaver 落在 tmp_path,用 fixture mini.db 绕过真实建图,不联网。

覆盖:
- 默认 config(checkpoints=True):停在 review-enrichment,vuln 未跑,payload 有用。
- continue:从 interrupt 放行后 vuln 执行、图推进到 report。
- checkpoints=False(--yolo 等价):一路跑完,无 interrupt。
- checkpoints=["review-enrichment"]:只停 enrichment,不停 findings。
"""

from __future__ import annotations

import os
from typing import Any

from langgraph.types import Command

from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.orchestration.checkpoints import REVIEW_ENRICHMENT, REVIEW_FINDINGS, make_checkpointer
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


def _make_app(
    tmp_path: Any,
    workspace: str,
    checkpoints: Any,
) -> tuple[Any, dict[str, Any], MockVuln, dict[str, Any]]:
    """组装编译好的 pipeline + 初始 state + mock 分析器 + thread config。"""
    runs_root = str(tmp_path / "runs")
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["mock"]},
        "checkpoints": checkpoints,
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
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"mock": mock}, checkpointer)
    return app, state, mock, _thread_config(workspace)


def test_pipeline_pauses_at_review_enrichment(tmp_path: Any) -> None:
    """默认 checkpoints=True:富化后停在 review-enrichment,vuln 尚未执行。"""
    app, state, mock, cfg = _make_app(tmp_path, "pause-test", checkpoints=True)

    result = app.invoke(state, cfg)

    # 停在 interrupt。
    assert "__interrupt__" in result
    interrupts = result["__interrupt__"]
    assert interrupts, "expected a non-empty __interrupt__ list"
    payload = interrupts[0].value
    assert payload["stage"] == REVIEW_ENRICHMENT
    # payload 指向富化产物路径,供人查看。
    assert payload["artifact_path"] == state["enriched_graph_path"]
    assert "message" in payload

    # 关键:停在 review-enrichment 时,下游 vuln 尚未执行。
    assert mock.calls == 0
    assert REVIEW_ENRICHMENT not in result["completed_nodes"]
    assert "vuln" not in result["completed_nodes"]

    # 图停在 review-enrichment 节点(下一步就是它)。
    snapshot = app.get_state(cfg)
    assert snapshot.next == (REVIEW_ENRICHMENT,)


def test_continue_resumes_past_interrupt(tmp_path: Any) -> None:
    """continue(Command(resume=...))放行后 vuln 执行,图推进到 report。"""
    app, state, mock, cfg = _make_app(tmp_path, "continue-test", checkpoints=True)

    first = app.invoke(state, cfg)
    assert "__interrupt__" in first
    assert mock.calls == 0  # 停在 review-enrichment,vuln 还没跑

    # 放行 review-enrichment。停在 review-findings(第二个检查点默认也开)。
    second = app.invoke(Command(resume="approved"), cfg)
    assert "__interrupt__" in second
    assert mock.calls == 1  # vuln 在放行后执行了一次
    assert REVIEW_ENRICHMENT in second["completed_nodes"]
    assert "vuln" in second["completed_nodes"]
    assert "report" not in second["completed_nodes"]

    # 再放行 review-findings,跑到 report。
    final = app.invoke(Command(resume="approved"), cfg)
    assert "__interrupt__" not in final
    assert mock.calls == 1  # 已完成的 vuln 不因 continue 重跑
    assert REVIEW_FINDINGS in final["completed_nodes"]
    assert "report" in final["completed_nodes"]
    assert os.path.exists(final["report_path"])


def test_yolo_skips_all_interrupts(tmp_path: Any) -> None:
    """checkpoints=False(--yolo 等价):一次 invoke 跑到底,无 interrupt。"""
    app, state, mock, cfg = _make_app(tmp_path, "yolo-interrupt-test", checkpoints=False)

    final = app.invoke(state, cfg)

    assert "__interrupt__" not in final
    assert mock.calls == 1
    for node in ("build_graph", "enrichment", REVIEW_ENRICHMENT, "vuln", REVIEW_FINDINGS, "report"):
        assert node in final["completed_nodes"]
    assert os.path.exists(final["report_path"])


def test_only_selected_checkpoint_enabled(tmp_path: Any) -> None:
    """checkpoints=["review-enrichment"]:只停 enrichment,放行后不停 findings。"""
    app, state, mock, cfg = _make_app(
        tmp_path,
        "selected-test",
        checkpoints=[REVIEW_ENRICHMENT],
    )

    first = app.invoke(state, cfg)
    # 只在 review-enrichment 停下。
    assert "__interrupt__" in first
    assert first["__interrupt__"][0].value["stage"] == REVIEW_ENRICHMENT
    assert mock.calls == 0

    # 放行后:vuln 跑,review-findings 未启用 → 不再 interrupt,直达 report。
    final = app.invoke(Command(resume="approved"), cfg)
    assert "__interrupt__" not in final
    assert mock.calls == 1
    assert REVIEW_FINDINGS in final["completed_nodes"]
    assert "report" in final["completed_nodes"]
    assert os.path.exists(final["report_path"])
