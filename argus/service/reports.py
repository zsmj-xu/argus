"""Deterministic report renderers for persisted OCR findings."""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .models import ReportFormat, ScanReport


_STATUS_LABELS = {
    "queued": "排队中",
    "running": "扫描中",
    "completed": "已完成",
    "partial": "部分完成",
    "failed": "失败",
    "canceled": "已取消",
    "skipped": "已跳过",
}
_PHASE_LABELS = {
    "queued": "等待处理",
    "git_fetching": "拉取代码",
    "source_checking": "检查源码",
    "ocr_starting": "启动审查引擎",
    "ocr_running": "审查源码",
    "parsing": "解析结果",
    "persisting": "保存结果",
    "completed": "已完成",
    "failed": "失败",
}
_SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
    "unknown": "未知",
}
_CATEGORY_LABELS = {
    "security": "安全",
    "correctness": "正确性",
    "performance": "性能",
    "maintainability": "可维护性",
    "style": "代码风格",
}
_WARNING_LABELS = {
    "incomplete_coverage": "扫描覆盖不完整",
    "inconsistent_coverage": "扫描覆盖统计不一致",
}


def render_report(report: ScanReport, report_format: ReportFormat) -> tuple[str, str]:
    if report_format is ReportFormat.JSON:
        return (
            json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
            "application/json",
        )
    if report_format is ReportFormat.MARKDOWN:
        return render_markdown(report), "text/markdown; charset=utf-8"
    return (
        json.dumps(render_sarif(report), ensure_ascii=False, indent=2, sort_keys=True),
        "application/sarif+json",
    )


def render_markdown(report: ScanReport) -> str:
    scan = report.scan
    progress = scan.progress
    lines = [
        f"# Argus 白盒扫描报告 `{_md_text(scan.id)}`",
        "",
        f"- 代码仓库：`{_md_text(scan.repository_url)}`",
        f"- 分支或版本：`{_md_text(scan.ref or '默认')}`",
        f"- 提交：`{_md_text(scan.commit_sha or '未知')}`",
        f"- 状态：`{_md_text(_STATUS_LABELS.get(scan.status.value, scan.status.value))}`",
        f"- 阶段：`{_md_text(_PHASE_LABELS.get(scan.phase, scan.phase))}`",
        f"- 文件：已审查 `{progress.reviewed_files}/{progress.total_files}`",
        f"- 告警：`{len(report.findings)}` 条",
        "",
        "> 本报告来自静态白盒审查。Argus 未执行目标代码，也未进行动态验证。",
        "",
    ]
    if scan.error:
        lines.extend([f"- 错误：`{_md_text(scan.error)}`", ""])
    if scan.metadata:
        ocr_warnings = scan.metadata.get("ocr_warnings")
        if isinstance(ocr_warnings, list) and ocr_warnings:
            lines.extend(["## 覆盖范围警告", ""])
            lines.extend(f"- {_md_text(_WARNING_LABELS.get(str(item), str(item)))}" for item in ocr_warnings)
            lines.append("")
    if not report.findings:
        lines.extend(["## 扫描结果", "", "未返回任何告警。", ""])
    for index, finding in enumerate(report.findings, start=1):
        location = finding.file or "位置不可用"
        if finding.start_line is not None:
            location += f":{finding.start_line}"
            if finding.end_line is not None and finding.end_line != finding.start_line:
                location += f"-{finding.end_line}"
        lines.extend(
            [
                f"## {index}. {_md_text(finding.title)}",
                "",
                f"- 分类：`{_md_text(_CATEGORY_LABELS.get(finding.category.lower(), finding.category))}`",
                f"- 风险等级：`{_md_text(_SEVERITY_LABELS.get(finding.severity.lower(), finding.severity))}`",
                f"- 位置：`{_md_text(location)}`",
                "",
                _md_text(finding.message),
                "",
            ]
        )
        if finding.evidence:
            lines.extend(["### 代码证据", "", _code_block(finding.evidence), ""])
        if finding.remediation:
            lines.extend(["### 修复建议", "", _code_block(finding.remediation), ""])
    return "\n".join(lines)


def _md_text(value: str) -> str:
    """Escape untrusted OCR/repository text before placing it in Markdown."""

    escaped = html.escape(str(value), quote=False)
    for character in ("\\", "`", "*", "_", "[", "]", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _code_block(value: str) -> str:
    fence_length = max(3, max((len(run) for run in re.findall(r"`+", value)), default=0) + 1)
    fence = "`" * fence_length
    return f"{fence}text\n{html.escape(value, quote=False)}\n{fence}"


def render_sarif(report: ScanReport) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        severity = finding.severity.lower()
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note",
            "message": {"text": finding.message},
            "properties": {
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }
        if finding.file:
            physical: dict[str, Any] = {"artifactLocation": {"uri": finding.file}}
            if finding.start_line is not None:
                physical["region"] = {"startLine": finding.start_line}
                if finding.end_line is not None:
                    physical["region"]["endLine"] = finding.end_line
            result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus White-box Scan Service",
                        "informationUri": "https://github.com/alibaba/open-code-review",
                    }
                },
                "automationDetails": {"id": f"argus/{report.scan.id}"},
                "properties": {
                    "status": report.scan.status.value,
                    "commit": report.scan.commit_sha,
                },
                "results": results,
            }
        ],
    }
