"""AuditedLLM —— 带审计包装的 LLM 客户端,实现 argus.contracts.LLMClient。

分析器通过它调模型;每次 complete() 前后把 {system, prompt, response, timestamp, model}
追加写审计文件。真正的 Anthropic client 可注入(测试用 mock),不注入时按 api_key 现建。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from argus.llm.audit import append_audit

# 当前可用的高性价比模型。契约 complete() 单轮补全,默认 8192 max_tokens。
DEFAULT_MODEL = "claude-sonnet-5"


def _extract_text(message: Any) -> str:
    """从 Anthropic Message 里抽出拼接的文本内容。

    message.content 是内容块列表;只取 type == "text" 的块的 .text 拼接。
    """
    parts: list[str] = []
    for block in message.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "".join(parts)


class AuditedLLM:
    """实现 LLMClient 协议。每次 complete() 落盘一条审计记录。"""

    def __init__(
        self,
        api_key: str,
        workspace: str,
        *,
        model: str = DEFAULT_MODEL,
        client: Any | None = None,
        runs_root: str = "runs",
    ) -> None:
        self.workspace = workspace
        self.model = model
        self.runs_root = runs_root
        self._client = client if client is not None else self._build_client(api_key)

    def _build_client(self, api_key: str) -> Any:
        """现建一个真实的 Anthropic client。隔离在此方法便于测试 patch/注入。"""
        import anthropic

        return anthropic.Anthropic(api_key=api_key)

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        """单轮补全,返回文本;调用后把本次交互追加写审计文件。"""
        message = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        response = _extract_text(message)

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": self.model,
            "system": system,
            "prompt": prompt,
            "response": response,
        }
        append_audit(self.workspace, record, runs_root=self.runs_root)

        return response
