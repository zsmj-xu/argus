"""T10:continue 命令 --set / --focus 参数注入到 state.config 测试。

关键断言:注入的 --set / --focus 真的合并进了 checkpoint 持久化的 state.config,
且**放行后执行的下游节点**(vuln)在 ctx["config"] 里读得到注入值 —— 不是只改了本地变量。
用一个记录 ctx["config"] 快照的 mock 分析器证明这一点。

直接测底层 `_advance`(带注入参数)对 state.config 的效果:_advance 是 resume/continue
共用的推进逻辑,continue 传注入、resume 不传。SqliteSaver 落在 tmp_path,fixture mini.db
绕过真实建图,不联网。
"""

from __future__ import annotations

import copy
import os
from typing import Any

from argus.cli import _advance
from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.orchestration.checkpoints import REVIEW_ENRICHMENT, make_checkpointer
from argus.orchestration.pipeline import build_pipeline
from argus.orchestration.state import make_initial_state

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


class ConfigCapturingVuln:
    """假漏洞分析器:run() 时深拷贝并记录它在 ctx 里看到的 config。

    深拷贝是必须的 —— ctx["config"] 是 state.config 的引用,不拷会记录到后续被改动的同一对象。
    """

    name = "capture"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self) -> None:
        self.calls = 0
        self.seen_config: dict[str, Any] | None = None

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        self.calls += 1
        self.seen_config = copy.deepcopy(ctx["config"])
        return {"analyzer": self.name, "findings": [], "enrichment": {}}


def _thread_config(workspace: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": workspace}}


def _make_app(tmp_path: Any, workspace: str) -> tuple[Any, dict[str, Any], ConfigCapturingVuln, dict[str, Any], str]:
    """组装编译好的 pipeline + 初始 state + capture 分析器 + thread config + runs_root。

    只开 review-enrichment 检查点(第一个),这样放行一次就能跑到 vuln 并直达 report,
    不必再处理 review-findings。
    """
    runs_root = str(tmp_path / "runs")
    config: dict[str, Any] = {
        "analyzers": {"enrichment": [], "vuln": ["capture"]},
        "checkpoints": [REVIEW_ENRICHMENT],
        "source_mode": "raw",
    }
    state = make_initial_state(
        repo_path=str(tmp_path / "repo"),
        workspace=workspace,
        config=config,
        runs_root=runs_root,
    )
    state["graph_db_path"] = FIXTURE_DB

    mock = ConfigCapturingVuln()
    checkpointer = make_checkpointer(workspace, runs_root=runs_root)
    app = build_pipeline({"capture": mock}, checkpointer)
    return app, state, mock, _thread_config(workspace), runs_root


def _pause_at_enrichment(
    app: Any, state: dict[str, Any], cfg: dict[str, Any], monkeypatch: Any, runs_root: str
) -> None:
    """把图跑到 review-enrichment 停下,并把 cli 模块的 RUNS_ROOT 指向 tmp_path。

    _advance 用模块级 RUNS_ROOT 定位 workspace db,故测试期间打补丁指向 tmp runs。
    """
    monkeypatch.setattr("argus.cli.RUNS_ROOT", runs_root)
    monkeypatch.setattr("argus.cli.discover_analyzers", lambda: {"capture": _CaptureFromClosure.instance})
    first = app.invoke(state, cfg)
    assert "__interrupt__" in first


class _CaptureFromClosure:
    """_advance 内部会自己 discover_analyzers()+build_pipeline;为了让它用同一个 capture
    实例(以便断言 seen_config),把实例挂在这里供 monkeypatch 的 discover_analyzers 返回。"""

    instance: ConfigCapturingVuln


def test_continue_set_injects_into_downstream_config(tmp_path: Any, monkeypatch: Any) -> None:
    """continue --set auth.roles=x:放行后 vuln 节点在 ctx["config"] 里读到 auth.roles == x。"""
    app, state, mock, cfg, runs_root = _make_app(tmp_path, "inject-set-test")
    _CaptureFromClosure.instance = mock
    _pause_at_enrichment(app, state, cfg, monkeypatch, runs_root)
    assert mock.calls == 0  # 停在 review-enrichment,vuln 还没跑

    rc = _advance("inject-set-test", "approved", "continue", overrides=["auth.roles=x"], focus=None)
    assert rc == 0

    # 关键:注入真的到了放行后执行的 vuln 节点。
    assert mock.calls == 1
    assert mock.seen_config is not None
    assert mock.seen_config["auth"]["roles"] == "x"

    # 且持久化进了 state.config,后续 resume 也看得到。
    assert app.get_state(cfg).values["config"]["auth"]["roles"] == "x"


def test_continue_focus_injects_into_downstream_config(tmp_path: Any, monkeypatch: Any) -> None:
    """continue --focus src/orders/:等价于 --set focus=src/orders/,vuln 读到 config["focus"]。"""
    app, state, mock, cfg, runs_root = _make_app(tmp_path, "inject-focus-test")
    _CaptureFromClosure.instance = mock
    _pause_at_enrichment(app, state, cfg, monkeypatch, runs_root)

    rc = _advance("inject-focus-test", "approved", "continue", overrides=[], focus="src/orders/")
    assert rc == 0

    assert mock.calls == 1
    assert mock.seen_config is not None
    assert mock.seen_config["focus"] == "src/orders/"
    assert app.get_state(cfg).values["config"]["focus"] == "src/orders/"


def test_continue_set_and_focus_together(tmp_path: Any, monkeypatch: Any) -> None:
    """--set 和 --focus 同时注入,两者都合并进下游 config。"""
    app, state, mock, cfg, runs_root = _make_app(tmp_path, "inject-both-test")
    _CaptureFromClosure.instance = mock
    _pause_at_enrichment(app, state, cfg, monkeypatch, runs_root)

    rc = _advance(
        "inject-both-test",
        "approved",
        "continue",
        overrides=["auth.roles=./roles.yaml"],
        focus="src/orders/",
    )
    assert rc == 0

    assert mock.seen_config is not None
    assert mock.seen_config["auth"]["roles"] == "./roles.yaml"
    assert mock.seen_config["focus"] == "src/orders/"


def test_continue_without_injection_leaves_config_unchanged(tmp_path: Any, monkeypatch: Any) -> None:
    """不传注入时 continue 行为不变:送 "approved" 放行,config 不被意外改动。"""
    app, state, mock, cfg, runs_root = _make_app(tmp_path, "inject-none-test")
    _CaptureFromClosure.instance = mock
    _pause_at_enrichment(app, state, cfg, monkeypatch, runs_root)

    config_before = copy.deepcopy(app.get_state(cfg).values["config"])

    rc = _advance("inject-none-test", "approved", "continue", overrides=[], focus=None)
    assert rc == 0

    assert mock.calls == 1
    # config 未被注入逻辑意外改动。
    assert app.get_state(cfg).values["config"] == config_before
    assert mock.seen_config == config_before
