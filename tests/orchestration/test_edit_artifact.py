"""T11:检查点放行后从磁盘重载产物 —— 人工编辑生效测试。

关键断言:人停在检查点时手改磁盘上的产物文件(enriched-graph.json / findings.json),
continue 放行后,下游节点读到的是**编辑后**的版本而非内存旧值。用记录 run() 时
ctx["enriched"] 快照的 mock 分析器证明"编辑真的生效",而非恒真断言。

覆盖:
- 停在 review-enrichment → 手改 enriched-graph.json → continue → vuln 的 ctx["enriched"] 含手改内容。
- 停在 review-findings → 手改 findings.json → continue → 最终 state.findings / report 用手改后的。
- checkpoints=False(--yolo):不 interrupt、不重载(通过 spy 断言重载 0 次)。
- 磁盘 JSON 写坏时不崩,保留内存 state 并记 warning。

SqliteSaver 落在 tmp_path,用 fixture mini.db 绕过真实建图,不联网。
"""

from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any

from langgraph.types import Command

from argus.contracts import (
    AnalysisContext,
    AnalyzerResult,
    Confidence,
    Finding,
    Phase,
    Severity,
)
from argus.orchestration.checkpoints import (
    REVIEW_ENRICHMENT,
    REVIEW_FINDINGS,
    make_checkpointer,
)
from argus.orchestration.pipeline import build_pipeline
from argus.orchestration.state import make_initial_state

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


class MockEnricher:
    """富化 mock:产出固定富化内容,供下游读 / 落盘 / 被人编辑。"""

    name = "enricher"
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    def __init__(self, enrichment: dict[str, Any]) -> None:
        self.enrichment = enrichment

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        return {"analyzer": self.name, "findings": [], "enrichment": copy.deepcopy(self.enrichment)}


class EnrichedCapturingVuln:
    """漏洞 mock:run() 时深拷贝记录它在 ctx 里看到的 enriched。

    深拷贝是必须的 —— ctx["enriched"] 是 state.enriched 的引用,不拷会记录到后续被改动的同一对象。
    """

    name = "capture"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self) -> None:
        self.calls = 0
        self.seen_enriched: dict[str, Any] | None = None

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        self.calls += 1
        self.seen_enriched = copy.deepcopy(ctx["enriched"])
        return {"analyzer": self.name, "findings": [], "enrichment": {}}


def _finding(title: str) -> Finding:
    """构造一条带枚举 severity/confidence 的 finding。"""
    return {
        "id": "mock:injection:deadbeef",
        "analyzer": "mock-finding",
        "vuln_class": "injection",
        "title": title,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "locations": [{"file": "api/login.py", "line": 42, "node_id": "file:api/login.py"}],
        "data_flow": "request.form -> query",
        "rationale": "unsanitized input reaches SQL",
        "evidence": "cursor.execute(f'... {user}')",
        "remediation": "use parameterized queries",
    }


class MockVulnWithFinding:
    """漏洞 mock:产出一条 finding(标题可定制),用于验证 findings 重载。"""

    name = "mock-finding"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self, title: str) -> None:
        self.calls = 0
        self.title = title

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        self.calls += 1
        return {"analyzer": self.name, "findings": [_finding(self.title)], "enrichment": {}}


def _thread_config(workspace: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": workspace}}


def _make_state(tmp_path: Any, workspace: str, config: dict[str, Any], runs_root: str) -> dict[str, Any]:
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    # 用 fixture db 绕过真实建图:build_graph 节点见到已存在的 db 即跳过。
    state["graph_db_path"] = FIXTURE_DB
    return state


def test_edited_enriched_graph_is_reloaded(tmp_path: Any) -> None:
    """停在 review-enrichment → 手改 enriched-graph.json → continue → vuln 看到手改内容。"""
    runs_root = str(tmp_path / "runs")
    workspace = "edit-enriched-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": ["enricher"], "vuln": ["capture"]},
        # 只开 review-enrichment:放行一次即跑到 vuln 并直达 report。
        "checkpoints": [REVIEW_ENRICHMENT],
        "source_mode": "raw",
    }
    state = _make_state(tmp_path, workspace, config, runs_root)

    enricher = MockEnricher({"endpoints": {"orig": True}})
    capture = EnrichedCapturingVuln()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"enricher": enricher, "capture": capture}, checkpointer)
    cfg = _thread_config(workspace)

    first = app.invoke(state, cfg)
    assert "__interrupt__" in first
    assert capture.calls == 0  # 停在 review-enrichment,vuln 还没跑

    # 人手改磁盘上的 enriched-graph.json:新增一个 endpoint。
    enriched_path = state["enriched_graph_path"]
    with open(enriched_path, encoding="utf-8") as handle:
        on_disk = json.load(handle)
    assert on_disk == {"endpoints": {"orig": True}}
    on_disk["endpoints"]["added_by_human"] = {"path": "/admin"}
    with open(enriched_path, "w", encoding="utf-8") as handle:
        json.dump(on_disk, handle)

    final = app.invoke(Command(resume="approved"), cfg)
    assert "__interrupt__" not in final

    # 关键:放行后 vuln 拿到的 enriched 是手改后的版本,含 added_by_human。
    assert capture.calls == 1
    assert capture.seen_enriched is not None
    assert capture.seen_enriched == {"endpoints": {"orig": True, "added_by_human": {"path": "/admin"}}}

    # 手改版本也持久化进了 state.enriched。
    assert app.get_state(cfg).values["enriched"]["endpoints"]["added_by_human"] == {"path": "/admin"}


def test_edited_findings_is_reloaded(tmp_path: Any) -> None:
    """停在 review-findings → 手改 findings.json 标题 → continue → 最终 state / report 用手改后的。"""
    runs_root = str(tmp_path / "runs")
    workspace = "edit-findings-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["mock-finding"]},
        # 只开 review-findings:review-enrichment pass-through,放行一次即跑到 report。
        "checkpoints": [REVIEW_FINDINGS],
        "source_mode": "raw",
    }
    state = _make_state(tmp_path, workspace, config, runs_root)

    mock = MockVulnWithFinding("SQL injection in login")
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"mock-finding": mock}, checkpointer)
    cfg = _thread_config(workspace)

    first = app.invoke(state, cfg)
    assert "__interrupt__" in first
    assert first["__interrupt__"][0].value["stage"] == REVIEW_FINDINGS

    # 人手改磁盘上的 findings.json:改标题(severity/confidence 保持 T09 落盘的字符串)。
    findings_path = state["findings_path"]
    with open(findings_path, encoding="utf-8") as handle:
        on_disk = json.load(handle)
    assert on_disk[0]["title"] == "SQL injection in login"
    assert on_disk[0]["severity"] == "high"  # 磁盘上是字符串
    on_disk[0]["title"] = "EDITED BY HUMAN: command injection"
    with open(findings_path, "w", encoding="utf-8") as handle:
        json.dump(on_disk, handle)

    final = app.invoke(Command(resume="approved"), cfg)
    assert "__interrupt__" not in final

    # 关键:最终 state.findings 是手改后的标题。
    findings = app.get_state(cfg).values["findings"]
    assert findings[0]["title"] == "EDITED BY HUMAN: command injection"
    # severity 仍是字符串,report 用 _as_str 兼容,渲染不崩。
    assert findings[0]["severity"] == "high"

    # report.md 用了手改后的标题。
    report_path = state["report_path"]
    assert os.path.exists(report_path)
    with open(report_path, encoding="utf-8") as handle:
        report = handle.read()
    assert "EDITED BY HUMAN: command injection" in report
    assert "SQL injection in login" not in report


def test_yolo_does_not_reload_artifacts(tmp_path: Any, monkeypatch: Any) -> None:
    """checkpoints=False(--yolo):不 interrupt,也不从磁盘重载产物(spy 断言 0 次重载)。"""
    import argus.orchestration.checkpoints as checkpoints_mod

    reload_calls = 0
    original = checkpoints_mod._reload_artifact

    def counting_reload(*args: Any, **kwargs: Any) -> Any:
        nonlocal reload_calls
        reload_calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(checkpoints_mod, "_reload_artifact", counting_reload)

    runs_root = str(tmp_path / "runs")
    workspace = "yolo-no-reload-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": ["enricher"], "vuln": ["capture"]},
        "checkpoints": False,
        "source_mode": "raw",
    }
    state = _make_state(tmp_path, workspace, config, runs_root)

    enricher = MockEnricher({"endpoints": {"orig": True}})
    capture = EnrichedCapturingVuln()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"enricher": enricher, "capture": capture}, checkpointer)
    cfg = _thread_config(workspace)

    final = app.invoke(state, cfg)

    # 一路跑到底,无 interrupt。
    assert "__interrupt__" not in final
    assert capture.calls == 1
    assert "report" in final["completed_nodes"]
    # 关键:yolo 下两个检查点都 pass-through,从未从磁盘重载(避免多余磁盘读)。
    assert reload_calls == 0


def test_corrupt_artifact_json_keeps_in_memory_state(tmp_path: Any, caplog: Any) -> None:
    """磁盘 JSON 写坏时不崩:保留内存 state,并记 warning。"""
    runs_root = str(tmp_path / "runs")
    workspace = "corrupt-json-test"
    config: dict[str, Any] = {
        "analyzers": {"enrichment": ["enricher"], "vuln": ["capture"]},
        "checkpoints": [REVIEW_ENRICHMENT],
        "source_mode": "raw",
    }
    state = _make_state(tmp_path, workspace, config, runs_root)

    enricher = MockEnricher({"endpoints": {"orig": True}})
    capture = EnrichedCapturingVuln()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"enricher": enricher, "capture": capture}, checkpointer)
    cfg = _thread_config(workspace)

    first = app.invoke(state, cfg)
    assert "__interrupt__" in first

    # 人手抖把 enriched-graph.json 写成非法 JSON。
    enriched_path = state["enriched_graph_path"]
    with open(enriched_path, "w", encoding="utf-8") as handle:
        handle.write("{ this is not valid json ]]")

    with caplog.at_level(logging.WARNING):
        final = app.invoke(Command(resume="approved"), cfg)

    # 不崩:图跑到底。
    assert "__interrupt__" not in final
    assert capture.calls == 1
    # 关键:重载失败时保留内存里的 enriched(富化器产出的原值),而非把坏 JSON 塞进去。
    assert capture.seen_enriched == {"endpoints": {"orig": True}}
    # 记了 warning。
    assert any(record.levelno == logging.WARNING for record in caplog.records)
