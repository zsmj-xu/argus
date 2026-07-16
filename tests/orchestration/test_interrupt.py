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

import json
import os
from typing import Any

from langgraph.types import Command

from argus.contracts import AnalysisContext, AnalyzerResult, Confidence, Finding, Phase, Severity
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


def _finding_with_enums() -> Finding:
    """构造一条 severity/confidence 为枚举的 finding,验证落盘时枚举被序列化成字符串。"""
    return {
        "id": "mock:injection:deadbeef",
        "analyzer": "mock-finding",
        "vuln_class": "injection",
        "title": "SQL injection in login",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "locations": [{"file": "api/login.py", "line": 42, "node_id": "file:api/login.py"}],
        "data_flow": "request.form -> query",
        "rationale": "unsanitized input reaches SQL",
        "evidence": "cursor.execute(f'... {user}')",
        "remediation": "use parameterized queries",
    }


class MockVulnWithFinding:
    """产出一条带枚举 severity/confidence 的 finding 的假漏洞分析器。"""

    name = "mock-finding"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self) -> None:
        self.calls = 0

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        self.calls += 1
        return {"analyzer": self.name, "findings": [_finding_with_enums()], "enrichment": {}}


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

    # 停在检查点时富化产物已落盘,内容 == checkpoint state 里的 enriched。
    enriched_path = state["enriched_graph_path"]
    assert os.path.exists(enriched_path)
    snapshot = app.get_state(cfg)
    with open(enriched_path, encoding="utf-8") as handle:
        assert json.load(handle) == snapshot.values["enriched"]

    # 图停在 review-enrichment 节点(下一步就是它)。
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

    # 停在 review-findings 时 findings 产物已落盘,内容 == checkpoint state 里的 findings。
    findings_path = state["findings_path"]
    assert os.path.exists(findings_path)
    snapshot = app.get_state(cfg)
    with open(findings_path, encoding="utf-8") as handle:
        assert json.load(handle) == snapshot.values["findings"]

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


def test_findings_artifact_serializes_enums_as_strings(tmp_path: Any) -> None:
    """findings 落盘时 Severity/Confidence 枚举被转成纯字符串("high" 等)。"""
    runs_root = str(tmp_path / "runs")
    workspace = "enum-serialize-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["mock-finding"]},
        "checkpoints": True,
        "source_mode": "raw",
    }
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    state["graph_db_path"] = FIXTURE_DB

    mock = MockVulnWithFinding()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"mock-finding": mock}, checkpointer)
    cfg = _thread_config(workspace)

    # 放行 review-enrichment,停在 review-findings。
    app.invoke(state, cfg)
    app.invoke(Command(resume="approved"), cfg)

    findings_path = state["findings_path"]
    assert os.path.exists(findings_path)
    with open(findings_path, encoding="utf-8") as handle:
        written = json.load(handle)

    # 枚举被序列化成字符串,而非枚举对象/其它形式。
    assert written[0]["severity"] == "high"
    assert written[0]["confidence"] == "high"
    assert isinstance(written[0]["severity"], str)
    # 落盘内容与 checkpoint state 里的 findings 一致(枚举 == 字符串,因 (str, Enum))。
    snapshot = app.get_state(cfg)
    assert written == snapshot.values["findings"]


def test_empty_analyzers_still_persist_valid_empty_artifacts(tmp_path: Any) -> None:
    """两阶段均无分析器时,仍落盘合法空产物:enriched → {},findings → []。"""
    runs_root = str(tmp_path / "runs")
    workspace = "empty-artifacts-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": []},
        "checkpoints": True,
        "source_mode": "raw",
    }
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    state["graph_db_path"] = FIXTURE_DB

    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({}, checkpointer)
    cfg = _thread_config(workspace)

    # 停在 review-enrichment:enriched 产物已落盘为合法空 {}。
    app.invoke(state, cfg)
    enriched_path = state["enriched_graph_path"]
    assert os.path.exists(enriched_path)
    with open(enriched_path, encoding="utf-8") as handle:
        assert json.load(handle) == {}

    # 放行到 review-findings:findings 产物已落盘为合法空 []。
    app.invoke(Command(resume="approved"), cfg)
    findings_path = state["findings_path"]
    assert os.path.exists(findings_path)
    with open(findings_path, encoding="utf-8") as handle:
        assert json.load(handle) == []
