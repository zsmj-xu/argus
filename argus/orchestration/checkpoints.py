"""Checkpoint 持久化与 interrupt 检查点节点。

- make_checkpointer(workspace):返回指向 runs/<workspace>/state.db 的 SqliteSaver。
- review_enrichment / review_findings:两个 interrupt 检查点节点,按 config 决定是否停顿。

config.checkpoints 语义:
- True(默认):所有检查点都停下等人确认。
- False(--yolo 等价):全部跳过(pass-through),一次跑到底。
- list[str]:只在列出的检查点名停下,其余跳过。
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import interrupt

from argus.contracts import ArgusState
from argus.orchestration.state import workspace_dir

# ArgusState / Finding 里的枚举都是自定义 (str, Enum);显式登记到 msgpack 允许列表,
# 否则 LangGraph 反序列化时会把它们退化成普通 str(finding['severity'].value 会
# 在 report 节点抛 AttributeError),并在未来版本告警/拒绝。
_ALLOWED_MSGPACK_MODULES = [
    ("argus.contracts", "SourceMode"),
    ("argus.contracts", "Severity"),
    ("argus.contracts", "Confidence"),
]

# 两个检查点节点的稳定名。cli --yolo 及 config.checkpoints 用这些名字寻址。
REVIEW_ENRICHMENT = "review-enrichment"
REVIEW_FINDINGS = "review-findings"

# 每个检查点对应的、人应查看的产物在 ArgusState 里的 key。
# review-enrichment → 富化图;review-findings → 漏洞发现。
_CHECKPOINT_ARTIFACT_KEYS: dict[str, str] = {
    REVIEW_ENRICHMENT: "enriched_graph_path",
    REVIEW_FINDINGS: "findings_path",
}


def make_checkpointer(workspace: str, runs_root: str = "runs") -> SqliteSaver:
    """构造指向 runs/<workspace>/state.db 的 SqliteSaver。

    LangGraph 1.x 的 SqliteSaver 接收一个 sqlite3.Connection。用 check_same_thread=False
    以便 LangGraph 在其内部线程里复用连接。父目录不存在时创建。
    """
    ws_dir = workspace_dir(workspace, runs_root)
    os.makedirs(ws_dir, exist_ok=True)
    db_path = os.path.join(ws_dir, "state.db")

    conn = sqlite3.connect(db_path, check_same_thread=False)
    serde = JsonPlusSerializer(allowed_msgpack_modules=_ALLOWED_MSGPACK_MODULES)
    return SqliteSaver(conn, serde=serde)


def _checkpoint_enabled(config: dict[str, Any], checkpoint_name: str) -> bool:
    """依据 config.checkpoints 判断某检查点是否应停顿。"""
    setting = config.get("checkpoints", True)
    if setting is True:
        return True
    if setting is False or setting is None:
        return False
    if isinstance(setting, list):
        return checkpoint_name in setting
    # 未知类型:保守起见按开启处理。
    return True


def review_enrichment(state: ArgusState) -> dict[str, Any]:
    """富化阶段后的 interrupt 检查点。启用则停下等人 resume,否则 pass-through。"""
    return _run_review(state, REVIEW_ENRICHMENT)


def review_findings(state: ArgusState) -> dict[str, Any]:
    """漏洞分析后的 interrupt 检查点。启用则停下等人 resume,否则 pass-through。"""
    return _run_review(state, REVIEW_FINDINGS)


def _review_payload(state: ArgusState, checkpoint_name: str) -> dict[str, Any]:
    """构造给人看的 interrupt payload:检查点名、待审产物路径、放行提示。

    - stage:检查点名(review-enrichment / review-findings),CLI 据此提示。
    - artifact_path:人应打开审阅(并可就地编辑)的产物路径,来自 ArgusState。
    - message:人类可读提示,说明看什么、如何放行。
    """
    artifact_key = _CHECKPOINT_ARTIFACT_KEYS[checkpoint_name]
    artifact_path = state[artifact_key]  # type: ignore[literal-required]
    return {
        "stage": checkpoint_name,
        "artifact_path": artifact_path,
        "message": (
            f"paused at {checkpoint_name}: review {artifact_path}, "
            f"then run `argus continue -w {state['workspace']}` to proceed"
        ),
    }


def _run_review(state: ArgusState, checkpoint_name: str) -> dict[str, Any]:
    """检查点公共逻辑:按需 interrupt,然后把节点名记入 completed_nodes。"""
    if _checkpoint_enabled(state["config"], checkpoint_name):
        # interrupt 会暂停图执行,持久化状态;resume/continue 时从此处之后继续,本节点不重跑。
        interrupt(_review_payload(state, checkpoint_name))

    return {"completed_nodes": [*state["completed_nodes"], checkpoint_name]}
