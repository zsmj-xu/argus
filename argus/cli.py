"""Argus CLI —— argparse 分发 start / resume / continue / stop / workspaces。

- start:建 workspace 目录 → build_graph → load_config → make_initial_state → 编译并 invoke 图。
- resume:崩溃后用同 workspace 的 checkpointer 续跑;可在重试前注入配置。
- continue:人看完检查点后主动放行 interrupt,推进图继续跑,并把 --set / --focus 注入进 state.config。
- stop:M1 骨架。
- workspaces:列出 runs/ 下的 workspace。

pyproject entry point:argus.cli:main。
"""

from __future__ import annotations

import argparse
import copy
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
        print(f"[argus] run `argus continue -w {workspace}` after review")
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


def _inject_into_state(
    app: Any,
    cfg: dict[str, Any],
    overrides: list[str],
    focus: str | None,
) -> None:
    """把 continue 的 --set / --focus 合并进 checkpoint 持久化的 state.config。

    读当前 state.config 深拷贝 → 用 apply_overrides 打 --set 点路径 → --focus 映射成
    config["focus"] 键(分析器读 config.get("focus") 做 scope)→ update_state 写回 state。
    写回后进入 checkpoint,故放行后执行的下游节点及后续 resume 都能读到合并后的 config。
    无注入(空 overrides 且无 focus)时直接返回,不触碰 state。
    """
    from argus.config import apply_overrides

    if not overrides and focus is None:
        return

    snapshot = app.get_state(cfg)
    merged_config: dict[str, Any] = copy.deepcopy(snapshot.values["config"])

    apply_overrides(merged_config, overrides)
    if focus is not None:
        # --focus <path> 等价于 --set focus=<path>:focus 是 config 的一个 scope 键。
        merged_config["focus"] = focus

    app.update_state(cfg, {"config": merged_config})


def _advance(
    workspace: str,
    resume_value: Any,
    action: str,
    overrides: list[str] | None = None,
    focus: str | None = None,
) -> int:
    """resume / continue 共用的推进逻辑:把停下的图向前推。

    - 校验 checkpoint db 存在。
    - 图已完成(无 next)时报告即返回,不重跑。
    - 有注入(--set / --focus)时,放行前先把注入合并进 state.config(见 _inject_into_state)。
    - 停在 interrupt 时:用 Command(resume=resume_value) 放行(本节点不重跑)。
    - 有待跑节点但不在 interrupt(如崩溃在节点中途)时:用 None 平推续跑。
    action 仅用于日志,区分是 resume 还是 continue 触发;两者都可在推进前注入调整。
    """
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
        print(f"[argus] workspace {workspace!r} already complete; nothing to {action}")
        _report_result(dict(snapshot.values), workspace)
        return 0

    # 放行前把 --set / --focus 注入合并进 state.config,让下游节点从 state 读到新值。
    _inject_into_state(app, cfg, overrides or [], focus)

    # 停在 interrupt(检查点)时,Command(resume=...) 提供审阅结论并从检查点之后继续;
    # 否则(崩溃在节点中途)用 None 平推,让 LangGraph 从断点续跑。
    paused_at_checkpoint = bool(snapshot.interrupts)
    graph_input: Any = Command(resume=resume_value) if paused_at_checkpoint else None
    if paused_at_checkpoint:
        stage = snapshot.interrupts[0].value.get("stage", "?")
        print(f"[argus] {action}: releasing checkpoint {stage!r} for workspace {workspace!r}")
    else:
        print(f"[argus] {action}: continuing workspace {workspace!r} from last checkpoint")

    result = app.invoke(graph_input, cfg)
    _report_result(result, workspace)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """resume:崩溃后调整配置并续跑。可能停在 interrupt,也可能停在节点中途。"""
    return _advance(
        args.workspace,
        "approved",
        "resume",
        overrides=list(args.set or []),
        focus=args.focus,
    )


def cmd_continue(args: argparse.Namespace) -> int:
    """continue:人看完检查点后主动放行 interrupt,推进图继续跑。

    放行同时把 --set(点路径覆盖,可多次)/ --focus(聚焦路径)注入进 state.config,
    让放行后执行的下游节点(vuln 等)及后续 resume 都读得到。
    """
    return _advance(
        args.workspace,
        "approved",
        "continue",
        overrides=list(args.set or []),
        focus=args.focus,
    )


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


def cmd_web(args: argparse.Namespace) -> int:
    """启动仅监听本机的 Argus Web Console。"""
    from argus.web import serve

    return serve(args)


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

    resume = subparsers.add_parser("resume", help="从上次 checkpoint 调整配置并续跑")
    resume.add_argument("-w", "--workspace", required=True, help="workspace 名")
    resume.add_argument("--set", action="append", default=[], help="重试前注入点路径覆盖(可多次)")
    resume.add_argument("--focus", default=None, help="重试前调整聚焦路径")
    resume.set_defaults(func=cmd_resume)

    cont = subparsers.add_parser("continue", help="人审阅后放行 interrupt 检查点,推进图继续跑")
    cont.add_argument("-w", "--workspace", required=True, help="workspace 名")
    cont.add_argument("--set", action="append", default=[], help="点路径覆盖(T10 注入)")
    cont.add_argument("--focus", default=None, help="聚焦路径(T10 注入)")
    cont.set_defaults(func=cmd_continue)

    stop = subparsers.add_parser("stop", help="(M1 骨架)停止运行")
    stop.set_defaults(func=cmd_stop)

    workspaces = subparsers.add_parser("workspaces", help="列出所有 workspace")
    workspaces.set_defaults(func=cmd_workspaces)

    web = subparsers.add_parser("web", help="启动本地 Web Console")
    web.add_argument("--host", default="127.0.0.1", help="监听地址（仅允许 loopback）")
    web.add_argument("--port", type=int, default=8765, help="监听端口")
    web.add_argument("--runs-root", default=RUNS_ROOT, help="工作区根目录")
    web.set_defaults(func=cmd_web)

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
