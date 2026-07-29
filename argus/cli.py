"""Argus CLI —— argparse 分发 start / resume / continue / stop / workspaces。

- start:加载配置 → 创建 SourceSnapshot/Control 记录 → 在快照上编译并 invoke 旧图。
- resume:崩溃后用同 workspace 的 checkpointer 续跑;可在重试前注入配置。
- continue:人看完检查点后主动放行 interrupt,推进图继续跑,并把 --set / --focus 注入进 state.config。
- stop:M1 骨架。
- workspaces:列出 runs/ 下的 workspace。

pyproject entry point:argus.cli:main。
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from typing import Any
from uuid import UUID

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
    """start:创建隔离源码快照和 V2 记录，再运行兼容 Pipeline。"""
    from argus.config import load_config
    from argus.snapshots.compat import (
        finish_legacy_scan_record,
        prepare_legacy_scan,
        record_legacy_interruption,
        sync_legacy_artifacts,
    )

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"[argus] repo not found: {repo_path}", file=sys.stderr)
        return 1

    workspace = args.workspace

    overrides: list[str] = list(args.set or [])
    if args.yolo:
        # --yolo 等价于关闭所有 checkpoint。
        overrides.append("checkpoints=false")

    config = load_config(args.config, overrides)
    control_link = prepare_legacy_scan(
        repository_path=repo_path,
        workspace=workspace,
        config=config,
        runs_root=RUNS_ROOT,
    )
    if control_link.materialized_path is None:
        raise RuntimeError("source snapshot was not materialized")

    state = make_initial_state(
        repo_path=control_link.materialized_path,
        workspace=workspace,
        config=config,
        runs_root=RUNS_ROOT,
    )

    analyzers = discover_analyzers()
    print(f"[argus] discovered {len(analyzers)} analyzer(s): {sorted(analyzers)}")
    from argus.planning.legacy import compile_legacy_task_plan

    compile_legacy_task_plan(
        link=control_link,
        config=config,
        analyzers=analyzers,
        runs_root=RUNS_ROOT,
    )

    checkpointer = make_checkpointer(workspace, runs_root=RUNS_ROOT)
    app = build_pipeline(analyzers, checkpointer)

    try:
        result = app.invoke(state, _thread_config(workspace))
    except Exception as exc:
        try:
            sync_legacy_artifacts(workspace=workspace, runs_root=RUNS_ROOT)
            record_legacy_interruption(workspace, type(exc).__name__, RUNS_ROOT)
        except Exception as control_exc:
            raise ExceptionGroup(
                "legacy scan and Control Store synchronization both failed",
                [exc, control_exc],
            ) from exc
        raise
    sync_legacy_artifacts(workspace=workspace, runs_root=RUNS_ROOT)
    finish_legacy_scan_record(
        workspace=workspace,
        paused="__interrupt__" in result,
        runs_root=RUNS_ROOT,
    )
    _report_result(result, workspace)
    return 0


def _merged_state_config(
    app: Any,
    cfg: dict[str, Any],
    overrides: list[str],
    focus: str | None,
) -> dict[str, Any] | None:
    """Build a review-time config update without mutating the checkpoint."""
    from argus.config import apply_overrides, validate_config

    if not overrides and focus is None:
        return None

    snapshot = app.get_state(cfg)
    merged_config: dict[str, Any] = copy.deepcopy(snapshot.values["config"])
    apply_overrides(merged_config, overrides)
    if focus is not None:
        merged_config["focus"] = focus
    return validate_config(merged_config)


def _inject_into_state(
    app: Any,
    cfg: dict[str, Any],
    overrides: list[str],
    focus: str | None,
) -> None:
    """把 continue 的 --set / --focus 合并进 checkpoint 持久化的 state.config。"""
    merged_config = _merged_state_config(app, cfg, overrides, focus)
    if merged_config is None:
        return

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

    from argus.snapshots.compat import (
        finish_legacy_scan_record,
        record_legacy_interruption,
        resume_legacy_scan_record,
        sync_legacy_artifacts,
        update_legacy_scan_config,
    )

    analyzers = discover_analyzers()
    checkpointer = make_checkpointer(workspace, runs_root=RUNS_ROOT)
    app = build_pipeline(analyzers, checkpointer)
    cfg = _thread_config(workspace)

    snapshot = app.get_state(cfg)
    if not snapshot.next:
        sync_legacy_artifacts(workspace=workspace, runs_root=RUNS_ROOT)
        finish_legacy_scan_record(workspace=workspace, paused=False, runs_root=RUNS_ROOT)
        print(f"[argus] workspace {workspace!r} already complete; nothing to {action}")
        _report_result(dict(snapshot.values), workspace)
        return 0

    # 放行前把 --set / --focus 注入合并进 state.config,让下游节点从 state 读到新值。
    merged_config = _merged_state_config(app, cfg, overrides or [], focus)
    if merged_config is not None:
        update_legacy_scan_config(workspace, merged_config, RUNS_ROOT)
        app.update_state(cfg, {"config": merged_config})
    resume_legacy_scan_record(workspace, RUNS_ROOT)

    # 停在 interrupt(检查点)时,Command(resume=...) 提供审阅结论并从检查点之后继续;
    # 否则(崩溃在节点中途)用 None 平推,让 LangGraph 从断点续跑。
    paused_at_checkpoint = bool(snapshot.interrupts)
    graph_input: Any = Command(resume=resume_value) if paused_at_checkpoint else None
    if paused_at_checkpoint:
        stage = snapshot.interrupts[0].value.get("stage", "?")
        print(f"[argus] {action}: releasing checkpoint {stage!r} for workspace {workspace!r}")
    else:
        print(f"[argus] {action}: continuing workspace {workspace!r} from last checkpoint")

    try:
        result = app.invoke(graph_input, cfg)
    except Exception as exc:
        try:
            sync_legacy_artifacts(workspace=workspace, runs_root=RUNS_ROOT)
            record_legacy_interruption(workspace, type(exc).__name__, RUNS_ROOT)
        except Exception as control_exc:
            raise ExceptionGroup(
                "legacy resume and Control Store synchronization both failed",
                [exc, control_exc],
            ) from exc
        raise
    sync_legacy_artifacts(workspace=workspace, runs_root=RUNS_ROOT)
    finish_legacy_scan_record(
        workspace=workspace,
        paused="__interrupt__" in result,
        runs_root=RUNS_ROOT,
    )
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


def _print_v2_status(status: Any) -> None:
    print(f"[argus] scan_id={status.scan.id} engine={status.scan.engine.value} status={status.scan.status.value}")
    for task in status.tasks:
        print(f"[argus] task={task.plugin_id} status={task.status.value}")
    for review_id in status.open_review_ids:
        print(f"[argus] review_open={review_id}")


def _v2_executor() -> tuple[Any, Any]:
    from argus.control.db import Database, control_db_path, upgrade_database
    from argus.control.repositories import Repositories
    from argus.execution.local import LocalPlanExecutor

    path = control_db_path(RUNS_ROOT)
    upgrade_database(path)
    database = Database(path)
    return database, LocalPlanExecutor(
        Repositories(database),
        runs_root=RUNS_ROOT,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    """Create a scan; M4 defaults to the V2 LocalPlanExecutor."""
    if args.engine == "legacy":
        print(
            "[argus] warning: the legacy engine is deprecated; migrate to `argus scan` V2",
            file=sys.stderr,
        )
        return cmd_start(args)

    from argus.config import load_config
    from argus.execution.scan import create_v2_scan

    overrides = list(args.set or [])
    if args.yolo:
        overrides.append("checkpoints=false")
    config = load_config(args.config, overrides)
    scan = create_v2_scan(
        repository_path=os.path.abspath(args.repo),
        workspace=args.workspace,
        config=config,
        runs_root=RUNS_ROOT,
    )
    database, executor = _v2_executor()
    try:
        status = executor.run_ready_tasks(scan.id)
        _print_v2_status(status)
        return 0 if status.scan.status.value != "failed" else 1
    finally:
        database.close()


def cmd_scan_status(args: argparse.Namespace) -> int:
    database, executor = _v2_executor()
    try:
        _print_v2_status(executor.get_status(UUID(args.scan_id)))
        return 0
    finally:
        database.close()


def cmd_scan_resume(args: argparse.Namespace) -> int:
    database, executor = _v2_executor()
    try:
        status = executor.resume(UUID(args.scan_id))
        _print_v2_status(status)
        return 0 if status.scan.status.value != "failed" else 1
    finally:
        database.close()


def cmd_scan_cancel(args: argparse.Namespace) -> int:
    database, executor = _v2_executor()
    try:
        _print_v2_status(executor.cancel(UUID(args.scan_id)))
        return 0
    finally:
        database.close()


def cmd_review_decide(args: argparse.Namespace) -> int:
    from argus.control.services import ControlServices
    from argus.domain.enums import ReviewStatus

    database, executor = _v2_executor()
    try:
        target = ReviewStatus.APPROVED if args.review_action == "approve" else ReviewStatus.REJECTED
        review = ControlServices(executor.repositories).reviews.decide(
            UUID(args.review_id),
            target,
            reviewer=args.reviewer,
            reason=args.reason,
        )
        print(f"[argus] review_id={review.id} status={review.status.value} scan_id={review.scan_id}")
        return 0
    finally:
        database.close()


def cmd_verification_status(args: argparse.Namespace) -> int:
    from argus.control_plane.service import ControlPlaneService

    summary = ControlPlaneService(RUNS_ROOT).verification_summary(UUID(args.finding_id))
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_verification_approval(args: argparse.Namespace) -> int:
    from argus.control_plane.service import ControlPlaneService
    from argus.verification.models import ApprovalDecision

    service = ControlPlaneService(RUNS_ROOT)
    if args.verification_approval_action == "request":
        approval = service.request_verification_approval(UUID(args.plan_id))
    else:
        target = (
            ApprovalDecision.APPROVED if args.verification_approval_action == "approve" else ApprovalDecision.REJECTED
        )
        approval = service.decide_verification_approval(
            UUID(args.approval_id),
            target,
            {
                "reviewer": args.reviewer,
                "reason": args.reason,
            },
        )
    print(
        f"[argus] verification_approval_id={approval['id']} "
        f"decision={approval['decision']} plan_hash={approval['plan_hash']}"
    )
    return 0


def cmd_verification_execute(args: argparse.Namespace) -> int:
    from argus.control_plane.service import ControlPlaneService

    test_data: dict[str, str] = {}
    for item in args.test_data:
        key, separator, value = item.partition("=")
        if separator != "=" or not key or not value:
            raise ValueError("--test-data entries must use non-empty NAME=VALUE syntax")
        test_data[key] = value
    result = ControlPlaneService(RUNS_ROOT).execute_verification(
        UUID(args.plan_id),
        {"test_data": test_data},
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_control_backup(args: argparse.Namespace) -> int:
    from argus.control.db import control_db_path
    from argus.control.maintenance import backup_database

    result = backup_database(control_db_path(RUNS_ROOT), args.output)
    print(
        json.dumps(
            {
                "path": str(result.path),
                "sha256": result.sha256,
                "size_bytes": result.size_bytes,
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_artifact_gc(args: argparse.Namespace) -> int:
    from datetime import timedelta

    from argus.control.db import Database, control_db_path
    from argus.control.maintenance import collect_artifact_garbage

    database = Database(control_db_path(RUNS_ROOT))
    try:
        result = collect_artifact_garbage(
            database,
            runs_root=RUNS_ROOT,
            apply=args.apply,
            minimum_age=timedelta(hours=args.minimum_age_hours),
        )
    finally:
        database.close()
    print(
        json.dumps(
            {
                "mode": "quarantine" if args.apply else "dry-run",
                "referenced": result.referenced,
                "candidates": list(result.candidates),
                "quarantined": list(result.quarantined),
                "quarantine_root": (str(result.quarantine_root) if result.quarantine_root is not None else None),
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_findings_export(args: argparse.Namespace) -> int:
    from pathlib import Path

    from argus.reporting.exports import findings_json, findings_sarif

    database, executor = _v2_executor()
    try:
        findings = executor.repositories.findings.list(scan_id=UUID(args.scan_id))
    finally:
        database.close()
    rendered = findings_sarif(findings) if args.format == "sarif" else findings_json(findings)
    if args.output == "-":
        print(rendered, end="")
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"[argus] findings exported: {output.resolve()}")
    return 0


def cmd_performance_baseline(args: argparse.Namespace) -> int:
    from argus.performance import collect_performance_baseline

    database, executor = _v2_executor()
    try:
        baseline = collect_performance_baseline(
            executor.repositories,
            UUID(args.scan_id),
            runs_root=RUNS_ROOT,
        )
    finally:
        database.close()
    print(baseline.model_dump_json(indent=2))
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

    scan = subparsers.add_parser(
        "scan",
        help="新建扫描（默认使用 V2 本地执行器）",
    )
    scan.add_argument("-r", "--repo", required=True, help="目标仓库路径")
    scan.add_argument("-w", "--workspace", required=True, help="workspace 名")
    scan.add_argument("-c", "--config", default=None, help="YAML 配置路径")
    scan.add_argument(
        "--engine",
        choices=["legacy", "v2"],
        default="v2",
        help="执行引擎（默认 v2）",
    )
    scan.add_argument("--set", action="append", default=[], help="点路径配置覆盖")
    scan.add_argument("--yolo", action="store_true", help="跳过静态 Review Gate")
    scan.set_defaults(func=cmd_scan)

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

    scan_status = subparsers.add_parser("scan-status", help="查询 V2 Scan 状态")
    scan_status.add_argument("--scan-id", required=True)
    scan_status.set_defaults(func=cmd_scan_status)

    scan_resume = subparsers.add_parser("scan-resume", help="恢复 V2 Scan")
    scan_resume.add_argument("--scan-id", required=True)
    scan_resume.set_defaults(func=cmd_scan_resume)

    scan_cancel = subparsers.add_parser("scan-cancel", help="取消 V2 Scan")
    scan_cancel.add_argument("--scan-id", required=True)
    scan_cancel.set_defaults(func=cmd_scan_cancel)

    review = subparsers.add_parser("review", help="处理 V2 静态审核")
    review_actions = review.add_subparsers(dest="review_action", required=True)
    for action in ("approve", "reject"):
        decision = review_actions.add_parser(action)
        decision.add_argument("--review-id", required=True)
        decision.add_argument("--reviewer", required=True)
        decision.add_argument("--reason", required=True)
        decision.set_defaults(func=cmd_review_decide)

    verification_status = subparsers.add_parser(
        "verification-status",
        help="查询 M8 验证需求、计划和审批状态（不执行网络请求）",
    )
    verification_status.add_argument("--finding-id", required=True)
    verification_status.set_defaults(func=cmd_verification_status)

    verification_approval = subparsers.add_parser(
        "verification-approval",
        help="处理 hash 绑定的 M8 验证计划审批",
    )
    verification_approval_actions = verification_approval.add_subparsers(
        dest="verification_approval_action",
        required=True,
    )
    request = verification_approval_actions.add_parser("request")
    request.add_argument("--plan-id", required=True)
    request.set_defaults(func=cmd_verification_approval)
    for action in ("approve", "reject"):
        decision = verification_approval_actions.add_parser(action)
        decision.add_argument("--approval-id", required=True)
        decision.add_argument("--reviewer", required=True)
        decision.add_argument("--reason", required=True)
        decision.set_defaults(func=cmd_verification_approval)

    verification_execute = subparsers.add_parser(
        "verification-execute",
        help="执行已人工审批的 M9 只读 HTTP 验证计划",
    )
    verification_execute.add_argument("--plan-id", required=True)
    verification_execute.add_argument(
        "--test-data",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="显式测试数据；不会自动枚举资源 ID",
    )
    verification_execute.set_defaults(func=cmd_verification_execute)

    control_backup = subparsers.add_parser(
        "control-backup",
        help="创建不覆盖已有目标的 Control Store 一致性备份",
    )
    control_backup.add_argument("--output", required=True)
    control_backup.set_defaults(func=cmd_control_backup)

    artifact_gc = subparsers.add_parser(
        "artifact-gc",
        help="列出未引用 Artifact；--apply 时移入可恢复隔离区",
    )
    artifact_gc.add_argument("--apply", action="store_true")
    artifact_gc.add_argument("--minimum-age-hours", type=float, default=24.0)
    artifact_gc.set_defaults(func=cmd_artifact_gc)

    findings_export = subparsers.add_parser(
        "findings-export",
        help="从 Canonical Finding 导出 JSON 或 SARIF",
    )
    findings_export.add_argument("--scan-id", required=True)
    findings_export.add_argument("--format", choices=["json", "sarif"], required=True)
    findings_export.add_argument("--output", default="-")
    findings_export.set_defaults(func=cmd_findings_export)

    performance = subparsers.add_parser(
        "performance-baseline",
        help="汇总 V2 Scan 的持久化性能基线",
    )
    performance.add_argument("--scan-id", required=True)
    performance.set_defaults(func=cmd_performance_baseline)

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
