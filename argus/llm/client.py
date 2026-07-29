"""Audited OpenAI-compatible chat-completions client."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import find_dotenv, load_dotenv

from argus.llm.audit import append_audit
from argus.progress import emit_progress

ENV_BASE_URL = "ARGUS_LLM_BASE_URL"
ENV_API_KEY = "ARGUS_LLM_API_KEY"
ENV_MODEL = "ARGUS_LLM_MODEL"
ENV_DISABLE_THINKING = "ARGUS_LLM_DISABLE_THINKING"
ENV_MAX_OUTPUT_TOKENS = "ARGUS_LLM_MAX_OUTPUT_TOKENS"
# 推理模型(如 deepseek-v4-pro)首 token 延迟高,120s 曾 ReadTimeout。
# 默认 600s;可用 ARGUS_LLM_TIMEOUT 覆盖(秒)。
ENV_TIMEOUT = "ARGUS_LLM_TIMEOUT"
DEFAULT_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_TOKENS = 32_768
HEAVY_MAX_TOKENS = 65_536
DEFAULT_MAX_OUTPUT_TOKENS = 384 * 1024
PROGRESS_HEARTBEAT_SECONDS = 30.0


class LLMOutputTruncatedError(RuntimeError):
    """Raised when the provider stops before producing a complete response."""


def load_llm_environment() -> str | None:
    """Load the nearest .env and let it override inherited environment values."""
    dotenv_path = find_dotenv(usecwd=True)
    if not dotenv_path:
        return None
    load_dotenv(dotenv_path, override=True)
    return dotenv_path


def _resolve_timeout() -> float:
    """Resolve the HTTP timeout from ``ARGUS_LLM_TIMEOUT`` (seconds), falling back to default."""
    raw = os.environ.get(ENV_TIMEOUT)
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{ENV_TIMEOUT} must be a number of seconds, got {raw!r}")
    if value <= 0:
        raise ValueError(f"{ENV_TIMEOUT} must be positive, got {value}")
    return value


def _thinking_disabled() -> bool:
    """Whether to request a concise non-reasoning response from compatible gateways."""
    return os.environ.get(ENV_DISABLE_THINKING, "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_max_output_tokens(initial: int) -> int:
    """Resolve the auto-retry ceiling, never below the caller's initial budget."""
    raw = os.environ.get(ENV_MAX_OUTPUT_TOKENS)
    if not raw:
        return max(initial, DEFAULT_MAX_OUTPUT_TOKENS)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{ENV_MAX_OUTPUT_TOKENS} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{ENV_MAX_OUTPUT_TOKENS} must be positive, got {value}")
    return max(initial, value)


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
        timeout = _resolve_timeout()
        return httpx.Client(
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(timeout),
        )

    def complete(self, *, system: str, prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
        if not self.api_key:
            raise ValueError(f"{ENV_API_KEY} is required")
        if not self.model:
            raise ValueError(f"{ENV_MODEL} is required")
        endpoint = _chat_completions_url(self.base_url)
        retry_ceiling = _resolve_max_output_tokens(max_tokens)
        current_max_tokens = max_tokens
        attempt = 1

        while True:
            request_payload: dict[str, Any] = {
                "model": self.model,
                "max_tokens": current_max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
            if _thinking_disabled():
                # DeepSeek-compatible gateways use this OpenAI-compatible extension;
                # omit it by default so other providers retain their normal behavior.
                request_payload["thinking"] = {"type": "disabled"}
            request_started = time.monotonic()
            emit_progress(
                self.workspace,
                event="llm_request_started",
                message=f"正在等待模型响应（第 {attempt} 次尝试，输出额度 {current_max_tokens:,} tokens）",
                runs_root=self.runs_root,
                model=self.model,
                attempt=attempt,
                max_tokens=current_max_tokens,
                prompt_chars=len(prompt),
                timeout_seconds=_resolve_timeout(),
            )
            request_finished = threading.Event()

            def heartbeat() -> None:
                while not request_finished.wait(PROGRESS_HEARTBEAT_SECONDS):
                    elapsed = round(time.monotonic() - request_started)
                    emit_progress(
                        self.workspace,
                        event="llm_request_waiting",
                        message=f"模型仍在生成响应，已等待 {elapsed} 秒",
                        runs_root=self.runs_root,
                        level="waiting",
                        model=self.model,
                        attempt=attempt,
                        max_tokens=current_max_tokens,
                        elapsed_seconds=elapsed,
                    )

            threading.Thread(
                target=heartbeat,
                name=f"argus-llm-progress-{self.workspace}",
                daemon=True,
            ).start()
            try:
                http_response = self._client.post(endpoint, json=request_payload)
                http_response.raise_for_status()
                payload = http_response.json()
            except Exception as exc:
                elapsed = round(time.monotonic() - request_started, 1)
                emit_progress(
                    self.workspace,
                    event="llm_request_failed",
                    message=f"模型请求失败：{type(exc).__name__}: {exc}",
                    runs_root=self.runs_root,
                    level="error",
                    model=self.model,
                    attempt=attempt,
                    max_tokens=current_max_tokens,
                    elapsed_seconds=elapsed,
                    error_type=type(exc).__name__,
                )
                raise
            finally:
                request_finished.set()
            try:
                response = _extract_text(payload)
            except Exception as exc:
                elapsed = round(time.monotonic() - request_started, 1)
                emit_progress(
                    self.workspace,
                    event="llm_response_invalid",
                    message=f"模型响应格式无效：{type(exc).__name__}: {exc}",
                    runs_root=self.runs_root,
                    level="error",
                    model=self.model,
                    attempt=attempt,
                    max_tokens=current_max_tokens,
                    elapsed_seconds=elapsed,
                    error_type=type(exc).__name__,
                )
                raise

            choices = payload.get("choices") if isinstance(payload, dict) else None
            first_choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
            usage = payload.get("usage") if isinstance(payload, dict) else None
            finish_reason = first_choice.get("finish_reason")

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": self.model,
                "base_url": self.base_url,
                "system": system,
                "prompt": prompt,
                "response": response,
                "finish_reason": finish_reason,
                "usage": usage if isinstance(usage, dict) else None,
                "attempt": attempt,
                "max_tokens": current_max_tokens,
            }
            append_audit(self.workspace, record, runs_root=self.runs_root)
            elapsed = round(time.monotonic() - request_started, 1)
            completion_tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
            emit_progress(
                self.workspace,
                event="llm_request_completed",
                message=f"模型响应完成：{finish_reason or '未知结束原因'}，耗时 {elapsed:.1f} 秒",
                runs_root=self.runs_root,
                level="warning" if finish_reason == "length" else "success",
                model=self.model,
                attempt=attempt,
                max_tokens=current_max_tokens,
                elapsed_seconds=elapsed,
                finish_reason=finish_reason,
                completion_tokens=completion_tokens,
                response_chars=len(response),
            )

            if finish_reason != "length":
                return response
            if current_max_tokens >= retry_ceiling:
                emit_progress(
                    self.workspace,
                    event="llm_output_exhausted",
                    message=f"模型连续截断，已达到最高输出额度 {current_max_tokens:,} tokens",
                    runs_root=self.runs_root,
                    level="error",
                    attempt=attempt,
                    max_tokens=current_max_tokens,
                )
                raise LLMOutputTruncatedError(
                    f"LLM response reached max_tokens={current_max_tokens} before completing the response"
                )

            next_max_tokens = min(current_max_tokens * 2, retry_ceiling)
            emit_progress(
                self.workspace,
                event="llm_retry_scheduled",
                message=f"响应被截断，自动把输出额度提高到 {next_max_tokens:,} tokens 后重试",
                runs_root=self.runs_root,
                level="warning",
                attempt=attempt,
                previous_max_tokens=current_max_tokens,
                next_max_tokens=next_max_tokens,
            )
            current_max_tokens = next_max_tokens
            attempt += 1
