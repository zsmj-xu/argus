"""LLM 客户端封装 —— 分析器通过 AuditedLLM 调模型,调用会被审计记录。"""

from __future__ import annotations

from argus.llm.audit import append_audit, audit_path
from argus.llm.client import AuditedLLM

__all__ = ["AuditedLLM", "append_audit", "audit_path"]
