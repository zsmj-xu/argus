"""Deterministic report renderers for persisted OCR findings."""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .models import ReportFormat, ScanReport


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
        f"# Argus white-box scan `{_md_text(scan.id)}`",
        "",
        f"- Repository: `{_md_text(scan.repository_url)}`",
        f"- Ref: `{_md_text(scan.ref or 'default')}`",
        f"- Commit: `{_md_text(scan.commit_sha or 'unknown')}`",
        f"- Status: `{_md_text(scan.status.value)}`",
        f"- Phase: `{_md_text(scan.phase)}`",
        f"- Files: `{progress.reviewed_files}/{progress.total_files}` reviewed",
        f"- Findings: `{len(report.findings)}`",
        "",
        "> This is a static white-box review. Argus did not execute target code or perform dynamic verification.",
        "",
    ]
    if scan.error:
        lines.extend([f"- Error: `{_md_text(scan.error)}`", ""])
    if scan.metadata:
        ocr_warnings = scan.metadata.get("ocr_warnings")
        if isinstance(ocr_warnings, list) and ocr_warnings:
            lines.extend(["## Coverage warnings", ""])
            lines.extend(f"- {_md_text(str(item))}" for item in ocr_warnings)
            lines.append("")
    if not report.findings:
        lines.extend(["## Result", "", "No findings were returned.", ""])
    for index, finding in enumerate(report.findings, start=1):
        location = finding.file or "location unavailable"
        if finding.start_line is not None:
            location += f":{finding.start_line}"
            if finding.end_line is not None and finding.end_line != finding.start_line:
                location += f"-{finding.end_line}"
        lines.extend(
            [
                f"## {index}. {_md_text(finding.title)}",
                "",
                f"- Category: `{_md_text(finding.category)}`",
                f"- Severity: `{_md_text(finding.severity)}`",
                f"- Location: `{_md_text(location)}`",
                "",
                _md_text(finding.message),
                "",
            ]
        )
        if finding.evidence:
            lines.extend(["### Evidence", "", _code_block(finding.evidence), ""])
        if finding.remediation:
            lines.extend(["### Remediation", "", _code_block(finding.remediation), ""])
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
