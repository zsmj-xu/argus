"""Checkpoint 持久化与 interrupt 检查点节点。

- make_checkpointer(workspace):返回指向 runs/<workspace>/state.db 的 SqliteSaver。
- review_enrichment / review_findings:两个 interrupt 检查点节点,按 config 决定是否停顿。

config.checkpoints 语义:
- True(默认):所有检查点都停下等人确认。
- False(--yolo 等价):全部跳过(pass-through),一次跑到底。
- list[str]:只在列出的检查点名停下,其余跳过。
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any, NamedTuple

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import interrupt

from argus.contracts import ArgusState
from argus.orchestration.state import workspace_dir

logger = logging.getLogger(__name__)

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


class _CheckpointArtifact(NamedTuple):
    """把一个检查点关联到它守护的产物的两个 ArgusState key。

    - path_key:产物落盘路径的 key(enriched_graph_path / findings_path),人打开编辑此文件。
    - state_key:内存里累积产物的 key(enriched / findings),放行后用磁盘内容覆盖它。
    """

    path_key: str
    state_key: str


# 每个检查点对应的、人应查看并可就地编辑的产物。
# review-enrichment → 富化图;review-findings → 漏洞发现。
_CHECKPOINT_ARTIFACTS: dict[str, _CheckpointArtifact] = {
    REVIEW_ENRICHMENT: _CheckpointArtifact(path_key="enriched_graph_path", state_key="enriched"),
    REVIEW_FINDINGS: _CheckpointArtifact(path_key="findings_path", state_key="findings"),
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
    artifact_path = state[_CHECKPOINT_ARTIFACTS[checkpoint_name].path_key]  # type: ignore[literal-required]
    return {
        "stage": checkpoint_name,
        "artifact_path": artifact_path,
        "message": (
            f"paused at {checkpoint_name}: review {artifact_path}, "
            f"then run `argus continue -w {state['workspace']}` to proceed"
        ),
    }


def _reload_artifact(path: str) -> tuple[bool, Any]:
    """从磁盘容错重载一个产物文件。

    返回 (loaded, value):
    - 文件不存在 → (False, None):不重载,保留内存 state(安全兜底)。
    - JSON 解析失败 → (False, None):记 warning、不重载,别让人手抖写坏 JSON 就崩整条 pipeline。
    - 成功 → (True, 解析出的对象):调用方用它覆盖内存 state。
    """
    if not os.path.exists(path):
        return (False, None)

    try:
        with open(path, encoding="utf-8") as handle:
            return (True, json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to reload edited artifact %s, keeping in-memory state: %s", path, exc)
        return (False, None)


def _run_review(state: ArgusState, checkpoint_name: str) -> dict[str, Any]:
    """检查点公共逻辑:按需 interrupt,放行后从磁盘重载产物,再把节点名记入 completed_nodes。

    interrupt 只在检查点启用时触发。它返回之后即"放行后"—— 人可能已就地编辑了磁盘上的
    产物文件,故此时从 path_key 指向的文件重载,覆盖 state_key 下的内存值,人的编辑才生效。
    --yolo / 检查点关闭时不 interrupt、人没机会编辑,pass-through 不重载(避免多余磁盘读)。
    """
    updates: dict[str, Any] = {}

    if _checkpoint_enabled(state["config"], checkpoint_name):
        # interrupt 会暂停图执行,持久化状态;resume/continue 时从此处之后继续,本节点不重跑。
        interrupt(_review_payload(state, checkpoint_name))

        # 放行后:从磁盘重载人可能编辑过的产物,覆盖内存 state。
        artifact = _CHECKPOINT_ARTIFACTS[checkpoint_name]
        artifact_path = state[artifact.path_key]  # type: ignore[literal-required]
        loaded, value = _reload_artifact(artifact_path)
        if loaded:
            updates[artifact.state_key] = value

    updates["completed_nodes"] = [*state["completed_nodes"], checkpoint_name]
    return updates
