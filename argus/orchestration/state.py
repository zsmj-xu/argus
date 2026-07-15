"""初始状态构造与产物路径约定。

make_initial_state() 依据 repo/workspace/config 组装一份 ArgusState,并把各阶段
产物路径固定到 runs/<workspace>/ 下。source_mode 从 config 读取(默认 raw)。
"""

from __future__ import annotations

import os
from typing import Any

from argus.contracts import ArgusState, SourceMode


def workspace_dir(workspace: str, runs_root: str = "runs") -> str:
    """返回 runs/<workspace>/ 目录路径(不负责创建)。"""
    return os.path.join(runs_root, workspace)


def _resolve_source_mode(config: dict[str, Any]) -> SourceMode:
    """从 config 读取 source_mode,非法值回退到 RAW。"""
    raw = config.get("source_mode", SourceMode.RAW.value)
    try:
        return SourceMode(raw)
    except ValueError:
        return SourceMode.RAW


def make_initial_state(
    *,
    repo_path: str,
    workspace: str,
    config: dict[str, Any],
    runs_root: str = "runs",
) -> ArgusState:
    """构造初始 ArgusState。

    产物路径固定到 runs/<workspace>/ 下;graph_db_path 先置为默认的
    <repo>/.codegraph/codegraph.db,build_graph 节点会据实覆盖。
    """
    ws_dir = workspace_dir(workspace, runs_root)
    default_db = os.path.join(repo_path, ".codegraph", "codegraph.db")

    return {
        "repo_path": repo_path,
        "workspace": workspace,
        "config": config,
        "source_mode": _resolve_source_mode(config),
        "graph_db_path": default_db,
        "enriched_graph_path": os.path.join(ws_dir, "enriched-graph.json"),
        "findings_path": os.path.join(ws_dir, "findings.json"),
        "report_path": os.path.join(ws_dir, "report.md"),
        "enriched": {},
        "findings": [],
        "completed_nodes": [],
    }
