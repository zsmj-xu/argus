"""建图 —— 调 codegraph CLI 在目标仓库上构建代码图。"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess

CODEGRAPH_BIN = "/opt/homebrew/bin/codegraph"
CODEGRAPH_PROVIDER_ID = "graph.codegraph"


def _resolve_binary() -> str:
    """定位 codegraph 二进制;找不到抛 FileNotFoundError。"""
    binary = CODEGRAPH_BIN if shutil.which(CODEGRAPH_BIN) else shutil.which("codegraph")
    if binary is None:
        raise FileNotFoundError("codegraph CLI not found; install it (expected at /opt/homebrew/bin/codegraph)")
    return binary


def codegraph_provider_version() -> str:
    """Identify the exact provider binary without trusting a mutable version label."""
    binary = _resolve_binary()
    digest = hashlib.sha256()
    with open(binary, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def build_graph(repo_path: str) -> str:
    """用 `codegraph init <repo>` 在目标仓库构建代码图,返回 db 路径。

    返回 `<repo>/.codegraph/codegraph.db`。init 失败(非零退出)抛 RuntimeError。
    """
    binary = _resolve_binary()

    result = subprocess.run(
        [binary, "init", repo_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"codegraph init failed (exit {result.returncode}): {result.stderr.strip()}")

    return os.path.join(repo_path, ".codegraph", "codegraph.db")
