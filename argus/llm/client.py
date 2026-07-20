"""Audited OpenAI-compatible chat-completions client."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import find_dotenv, load_dotenv

from argus.llm.audit import append_audit

ENV_BASE_URL = "ARGUS_LLM_BASE_URL"
ENV_API_KEY = "ARGUS_LLM_API_KEY"
ENV_MODEL = "ARGUS_LLM_MODEL"


def load_llm_environment() -> str | None:
    """Load the nearest .env and let it override inherited environment values."""
    dotenv_path = find_dotenv(usecwd=True)
    if not dotenv_path:
        return None
    load_dotenv(dotenv_path, override=True)
    return dotenv_path


def _chat_completions_url(base_url: str) -> str:
    base = base_url.strip().rstrip("/")
    if not base:
        raise ValueError(f"{ENV_BASE_URL} is required")
    if base.endswith("/v1/chat/completions"):
        return base
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    return f"{base}/v1/chat/completions"


def _extract_text(payload: Any) -> str:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("chat-completions response has no choices[0].message.content") from exc
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part["text"]
            for part in content
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
        )
    raise RuntimeError("chat-completions message content must be text")


class AuditedLLM:
    """实现 LLMClient 协议。每次 complete() 落盘一条审计记录。"""

    def __init__(
        self,
        api_key: str,
        workspace: str,
        *,
        base_url: str = "",
        model: str = "",
        client: Any | None = None,
        runs_root: str = "runs",
    ) -> None:
        self.workspace = workspace
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.runs_root = runs_root
        self._client = client if client is not None else self._build_client(api_key)

    @staticmethod
    def _build_client(api_key: str) -> httpx.Client:
        return httpx.Client(
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(120.0),
        )

    def complete(self, *, system: str, prompt: str, max_tokens: int = 8192) -> str:
        if not self.api_key:
            raise ValueError(f"{ENV_API_KEY} is required")
        if not self.model:
            raise ValueError(f"{ENV_MODEL} is required")
        endpoint = _chat_completions_url(self.base_url)
        http_response = self._client.post(
            endpoint,
            json={
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        http_response.raise_for_status()
        response = _extract_text(http_response.json())

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": self.model,
            "base_url": self.base_url,
            "system": system,
            "prompt": prompt,
            "response": response,
        }
        append_audit(self.workspace, record, runs_root=self.runs_root)

        return response
