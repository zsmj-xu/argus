"""报告渲染:把 findings 确定性渲染成 markdown 安全报告(不调 LLM)。"""

from __future__ import annotations

from argus.reporting.report import render_report

__all__ = ["render_report"]
from argus.reporting.exports import findings_json, findings_sarif

__all__ = ["findings_json", "findings_sarif"]
