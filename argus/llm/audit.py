"""审计落盘 —— 把每次 LLM 调用追加写到 runs/<workspace>/audit/llm.jsonl。

崩溃安全的思路:append-only JSON Lines,每行一条完整记录。目录不存在时自动创建。
"""

from __future__ import annotations

import json
import os
from typing import Any


def audit_path(workspace: str, runs_root: str = "runs") -> str:
    """返回某 workspace 的审计文件路径 `runs_root/<workspace>/audit/llm.jsonl`。"""
    return os.path.join(runs_root, workspace, "audit", "llm.jsonl")


def append_audit(workspace: str, record: dict[str, Any], runs_root: str = "runs") -> None:
    """把一条记录以 JSON Lines 格式追加写到审计文件。

    审计目录不存在时自动创建。record 原样序列化为一行 JSON(不排序、保留 UTF-8)。
    """
    path = audit_path(workspace, runs_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    line = json.dumps(record, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
