"""审计落盘 —— 把每次 LLM 调用追加写到 runs/<workspace>/audit/llm.jsonl。

崩溃安全的思路:append-only JSON Lines,每行一条完整记录。目录不存在时自动创建。
"""

from __future__ import annotations

import json
import os
from enum import Enum
import hashlib
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class AuditLevel(str, Enum):
    METADATA = "metadata"
    REDACTED = "redacted"
    FULL = "full"


def audit_path(workspace: str, runs_root: str = "runs") -> str:
    """返回某 workspace 的审计文件路径 `runs_root/<workspace>/audit/llm.jsonl`。"""
    return os.path.join(runs_root, workspace, "audit", "llm.jsonl")


def _safe_url(value: object) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return "[redacted]"
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, "", "", ""))


def _content_metadata(value: object, *, include_hash: bool) -> dict[str, Any]:
    text = value if isinstance(value, str) else ""
    metadata: dict[str, Any] = {"chars": len(text)}
    if include_hash:
        metadata["sha256"] = hashlib.sha256(text.encode()).hexdigest()
    return metadata


def sanitize_audit_record(
    record: dict[str, Any],
    *,
    level: AuditLevel,
) -> dict[str, Any]:
    base = {
        key: record.get(key)
        for key in (
            "timestamp",
            "model",
            "finish_reason",
            "usage",
            "attempt",
            "max_tokens",
        )
    }
    base["base_url"] = _safe_url(record.get("base_url"))
    if level is AuditLevel.FULL:
        base.update(
            {
                "system": record.get("system", ""),
                "prompt": record.get("prompt", ""),
                "response": record.get("response", ""),
            }
        )
    else:
        include_hash = level is AuditLevel.REDACTED
        base["content"] = {
            field: _content_metadata(record.get(field), include_hash=include_hash)
            for field in ("system", "prompt", "response")
        }
    base["audit_level"] = level.value
    return base


def append_audit(
    workspace: str,
    record: dict[str, Any],
    runs_root: str = "runs",
    *,
    level: AuditLevel = AuditLevel.REDACTED,
) -> None:
    """把一条记录以 JSON Lines 格式追加写到审计文件。

    审计目录不存在时自动创建。record 原样序列化为一行 JSON(不排序、保留 UTF-8)。
    """
    path = audit_path(workspace, runs_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    line = json.dumps(
        sanitize_audit_record(record, level=level),
        ensure_ascii=False,
    )
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
