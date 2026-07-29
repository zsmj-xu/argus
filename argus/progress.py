"""Structured, append-only progress events for CLI and Web Console runs."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

_WRITE_LOCK = threading.Lock()


def progress_path(workspace: str, runs_root: str = "runs") -> str:
    return os.path.join(runs_root, workspace, "progress.jsonl")


def emit_progress(
    workspace: str,
    *,
    event: str,
    message: str,
    runs_root: str = "runs",
    level: str = "info",
    **details: Any,
) -> dict[str, Any]:
    """Persist and print one safe progress event without source or model content."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "level": level,
        "message": message,
        "details": details,
    }
    path = progress_path(workspace, runs_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _WRITE_LOCK:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(f"[argus-progress] {line}", flush=True)
    return record
