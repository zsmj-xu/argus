"""Argus CLI —— argparse 分发 start / resume / continue / stop / workspaces。

- start:建 workspace 目录 → build_graph → load_config → make_initial_state → 编译并 invoke 图。
- resume:用同 workspace 的 checkpointer 续跑;已完成节点(completed_nodes)不重跑。
- continue:M1 骨架(后续任务完善 --set / --focus 注入)。
- stop:M1 骨架。
- workspaces:列出 runs/ 下的 workspace。

pyproject entry point:argus.cli:main。
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from langgraph.types import Command

from argus.orchestration.checkpoints import make_checkpointer
from argus.orchestration.pipeline import build_pipeline
from argus.orchestration.registry import discover_analyzers
from argus.orchestration.state import make_initial_state, workspace_dir

RUNS_ROOT = "runs"


def _thread_config(workspace: str) -> dict[str, Any]:
    """LangGraph 用 workspace 名作为 thread_id,使 checkpoint 按 workspace 隔离。"""
    return {"configurable": {"thread_id": workspace}}


def _report_result(result: dict[str, Any], workspace: str) -> None:
    """把一次 invoke/resume 的结果打印给用户。"""
    completed = result.get("completed_nodes", [])
    print(f"[argus] workspace={workspace} completed_nodes={completed}")

    if "__interrupt__" in result:
        interrupts = result["__interrupt__"]
        detail = interrupts[0].value if interrupts else {}
        print(f"[argus] paused at checkpoint: {detail}")
        print(f"[argus] run `argus resume -w {workspace}` after review")
        return

    report_path = result.get("report_path")
    if report_path and os.path.exists(report_path):
        print(f"[argus] report written: {report_path}")
    print("[argus] pipeline complete")


def cmd_start(args: argparse.Namespace) -> int:
    """start:新建/覆盖一次运行。建目录 → 载配置 → 初始状态 → 编译 invoke。"""
    from argus.config import load_config

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"[argus] repo not found: {repo_path}", file=sys.stderr)
        return 1

    workspace = args.workspace
    ws_dir = workspace_dir(workspace, RUNS_ROOT)
    os.makedirs(ws_dir, exist_ok=True)

    overrides: list[str] = list(args.set or [])
    if args.yolo:
        # --yolo 等价于关闭所有 checkpoint。
        overrides.append("checkpoints=false")

    config = load_config(args.config, overrides)

    state = make_initial_state(
        repo_path=repo_path,
        workspace=workspace,
        config=config,
        runs_root=RUNS_ROOT,
    )

    analyzers = discover_analyzers()
    print(f"[argus] discovered {len(analyzers)} analyzer(s): {sorted(analyzers)}")

    checkpointer = make_checkpointer(workspace, runs_root=RUNS_ROOT)
    app = build_pipeline(analyzers, checkpointer)

    result = app.invoke(state, _thread_config(workspace))
    _report_result(result, workspace)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """resume:用同 workspace 的 checkpointer 续跑。已完成节点不重跑。"""
    workspace = args.workspace
    db_path = os.path.join(workspace_dir(workspace, RUNS_ROOT), "state.db")
    if not os.path.exists(db_path):
        print(f"[argus] no checkpoint for workspace {workspace!r} at {db_path}", file=sys.stderr)
        return 1

    analyzers = discover_analyzers()
    checkpointer = make_checkpointer(workspace, runs_root=RUNS_ROOT)
    app = build_pipeline(analyzers, checkpointer)
    cfg = _thread_config(workspace)

    snapshot = app.get_state(cfg)
    if not snapshot.next:
        print(f"[argus] workspace {workspace!r} already complete; nothing to resume")
        _report_result(dict(snapshot.values), workspace)
        return 0

    # 从上次 interrupt 处继续:Command(resume=...) 提供审阅结论,已完成节点不重跑。
    result = app.invoke(Command(resume="approved"), cfg)
    _report_result(result, workspace)
    return 0


def cmd_continue(args: argparse.Namespace) -> int:
    """continue:M1 骨架。后续任务实现 --set / --focus 注入后再续跑。"""
    print(f"[argus] `continue` is a stub in M1 (workspace={args.workspace}); use `resume` for now")
    return 0


def cmd_stop(_args: argparse.Namespace) -> int:
    """stop:M1 骨架。LangGraph 无常驻进程,invoke 结束即停止。"""
    print("[argus] `stop` is a stub in M1 (runs are synchronous; nothing to stop)")
    return 0


def cmd_workspaces(_args: argparse.Namespace) -> int:
    """workspaces:列出 runs/ 下的 workspace 目录。"""
    if not os.path.isdir(RUNS_ROOT):
        print("[argus] no workspaces yet")
        return 0

    names = sorted(entry for entry in os.listdir(RUNS_ROOT) if os.path.isdir(os.path.join(RUNS_ROOT, entry)))
    if not names:
        print("[argus] no workspaces yet")
        return 0

    for name in names:
        has_state = os.path.exists(os.path.join(RUNS_ROOT, name, "state.db"))
        marker = "checkpoint" if has_state else "no-checkpoint"
        print(f"{name}\t[{marker}]")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """装配 argparse 子命令解析器。"""
    parser = argparse.ArgumentParser(prog="argus", description="AI 白盒代码扫描编排器")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="新建一次扫描运行")
    start.add_argument("-r", "--repo", required=True, help="目标仓库路径")
    start.add_argument("-w", "--workspace", required=True, help="workspace 名")
    start.add_argument("-c", "--config", default=None, help="YAML 配置路径")
    start.add_argument("--set", action="append", default=[], help="点路径覆盖,如 a.b=c(可多次)")
    start.add_argument("--yolo", action="store_true", help="跳过所有 checkpoint,一次跑到底")
    start.set_defaults(func=cmd_start)

    resume = subparsers.add_parser("resume", help="从上次 checkpoint 续跑")
    resume.add_argument("-w", "--workspace", required=True, help="workspace 名")
    resume.set_defaults(func=cmd_resume)

    cont = subparsers.add_parser("continue", help="(M1 骨架)带注入的续跑")
    cont.add_argument("-w", "--workspace", required=True, help="workspace 名")
    cont.add_argument("--set", action="append", default=[], help="点路径覆盖")
    cont.add_argument("--focus", default=None, help="聚焦路径")
    cont.set_defaults(func=cmd_continue)

    stop = subparsers.add_parser("stop", help="(M1 骨架)停止运行")
    stop.set_defaults(func=cmd_stop)

    workspaces = subparsers.add_parser("workspaces", help="列出所有 workspace")
    workspaces.set_defaults(func=cmd_workspaces)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 入口。返回进程退出码。"""
    parser = _build_parser()
    args = parser.parse_args(argv)
    func: Any = args.func
    result: int = func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
