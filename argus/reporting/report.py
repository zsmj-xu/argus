"""确定性报告渲染 —— 把 findings 渲染成 markdown 安全报告。

`render_report` 是纯函数:输入 findings + state,输出 markdown 字符串,不调 LLM、
不落盘(落盘由 pipeline 的 report 节点负责)。风格移植自 Shannon 的执行摘要报告:
顶部元信息 + 按严重度分组的 findings,每条含位置 / 数据流 / 依据 / 证据 / 修复。

严重度与置信度在 Finding 里是枚举(Severity/Confidence),但 checkpoint 反序列化
回来的 finding 可能已退化成字符串。渲染时对二者统一用 `_as_str` 兼容枚举与字符串,
故报告永远不会因在字符串上取 `.value` 而崩。
"""

from __future__ import annotations

import os
from enum import Enum
from urllib.parse import quote

from argus.contracts import ArgusState, Finding

# 严重度降序:报告分组与汇总均按此顺序。未知严重度排到末尾(见 _severity_rank)。
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# 展示用标题大小写。
_SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

_CONFIDENCE_LABEL = {
    "high": "高",
    "medium": "中",
    "low": "低",
}


def _as_str(value: object) -> str:
    """把枚举或字符串统一成其字符串值。

    Severity/Confidence 是 (str, Enum);正常是枚举,checkpoint round-trip 后可能退化成
    普通字符串。两种情况都安全返回底层字符串,绝不在字符串上取 `.value`。
    """
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _severity_rank(severity: str) -> int:
    """严重度在降序表中的下标;未知值排到所有已知值之后。"""
    normalized = severity.strip().lower()
    if normalized in _SEVERITY_ORDER:
        return _SEVERITY_ORDER.index(normalized)
    return len(_SEVERITY_ORDER)


def _severity_label(severity: str) -> str:
    """严重度的中文展示标题；未知值保持原样。"""
    normalized = severity.strip().lower()
    return _SEVERITY_LABEL.get(normalized, severity.strip() or "未知")


def _confidence_label(confidence: str) -> str:
    """置信度的中文展示标题；未知值保持原样。"""
    normalized = confidence.strip().lower()
    return _CONFIDENCE_LABEL.get(normalized, confidence.strip() or "未知")


def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """按严重度字符串分组,组名保持归一化小写。"""
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        severity = _as_str(finding["severity"]).strip().lower()
        groups.setdefault(severity, []).append(finding)
    return groups


def _ordered_severities(groups: dict[str, list[Finding]]) -> list[str]:
    """出现过的严重度按降序排列,未知值排在末尾(内部按字母序稳定)。"""
    return sorted(groups.keys(), key=lambda sev: (_severity_rank(sev), sev))


def _render_header(findings: list[Finding], state: ArgusState) -> list[str]:
    """标题 + 元信息 + 按严重度的汇总计数表。"""
    groups = _group_by_severity(findings)
    lines = [
        f"# Argus 安全报告 — {state['workspace']}",
        "",
        f"- **仓库：** `{state['repo_path']}`",
        f"- **工作区：** `{state['workspace']}`",
        f"- **源码模式：** `{_as_str(state['source_mode'])}`",
        f"- **漏洞总数：** {len(findings)}",
        "",
        "## 风险等级汇总",
        "",
    ]

    if not findings:
        lines.append("_未发现漏洞——本次扫描没有识别出可报告的安全问题。_")
        lines.append("")
        return lines

    lines.append("| 风险等级 | 数量 |")
    lines.append("| --- | --- |")
    for severity in _ordered_severities(groups):
        lines.append(f"| {_severity_label(severity)} | {len(groups[severity])} |")
    lines.append("")
    return lines


def _code_fence(content: str) -> str:
    """为代码块选一个足够长的反引号围栏。

    默认三反引号;若内容自身含连续反引号(会提前闭合围栏),则用比内容里
    最长反引号串再多一个的围栏,保证正确包裹。
    """
    longest_run = 0
    current_run = 0
    for char in content:
        if char == "`":
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 0
    return "`" * max(3, longest_run + 1)


def _link_target(file: str, line: int, repo_path: str, report_dir: str) -> str:
    """算出从报告文件指向真实源码的可点击链接目标(含行号锚点)。

    `location["file"]` 是相对仓库根(repo_path)的路径,而报告实际写在 report_dir
    (runs/<ws>/)。Markdown 相对链接从报告所在目录解析,故必须计算「从 report_dir
    指向 repo_path/file」的相对路径,否则点击会落到 report_dir 下不存在的位置。

    路径部分用标准 URL 编码(quote),把空格、`#`(否则被当 fragment 分隔)、`)`
    (否则截断 Markdown 链接目标)等特殊字符编码掉;`/` 保留为路径分隔符。行号锚点
    `#L<line>` 在编码之后单独拼接,不参与编码。
    """
    absolute = os.path.join(repo_path, file)
    relative = os.path.relpath(absolute, report_dir)
    # quote 默认保留 "/",把空格 / # / ) 等编码掉,确保链接目标不会被 Markdown 截断。
    encoded = quote(relative)
    return f"{encoded}#L{line}"


def _location_link(file: str, line: int, repo_path: str, report_dir: str) -> str:
    """把 file+line 渲染成可点击的 Markdown 链接。

    链接文本为 `file:line`;目标由 _link_target 算出,是从报告文件出发、指向真实
    源码文件的相对路径 + 行号锚点。目标用尖括号 `<...>` 包裹,即使路径含已编码的
    特殊字符也不会破坏 Markdown 链接语法。
    """
    target = _link_target(file, line, repo_path, report_dir)
    return f"[{file}:{line}](<{target}>)"


def _render_locations(finding: Finding, repo_path: str, report_dir: str) -> list[str]:
    """位置列表:每条渲染成可点击的 Markdown 链接 + 节点 id。"""
    lines = ["**代码位置：**", ""]
    locations = finding["locations"]
    if not locations:
        lines.append("- _未记录代码位置。_")
        lines.append("")
        return lines

    for location in locations:
        link = _location_link(location["file"], location["line"], repo_path, report_dir)
        node_id = location.get("node_id", "")
        if node_id:
            lines.append(f"- {link}（节点：`{node_id}`）")
        else:
            lines.append(f"- {link}")
    lines.append("")
    return lines


def _render_finding(finding: Finding, index: int, repo_path: str, report_dir: str) -> list[str]:
    """渲染单条 finding:标题 + 徽章 + 元数据 + 位置 + 数据流 / 依据 / 证据 / 修复。"""
    severity = _severity_label(_as_str(finding["severity"]))
    confidence = _confidence_label(_as_str(finding["confidence"]))

    lines = [
        f"#### {index}. {finding['title']}",
        "",
        f"**风险等级：** {severity} · **置信度：** {confidence}",
        "",
        f"- **漏洞类别：** {finding['vuln_class']}",
        f"- **分析器：** {finding['analyzer']}",
        f"- **ID：** `{finding['id']}`",
        "",
    ]
    lines.extend(_render_locations(finding, repo_path, report_dir))

    data_flow = finding["data_flow"].strip()
    if data_flow:
        lines.extend(["**数据流：**", "", data_flow, ""])

    rationale = finding["rationale"].strip()
    lines.extend(["**风险说明：**", "", rationale or "_未提供。_", ""])

    evidence = finding["evidence"].strip()
    if evidence:
        fence = _code_fence(evidence)
        lines.extend(["**证据：**", "", fence, evidence, fence, ""])

    remediation = finding["remediation"].strip()
    lines.extend(["**修复建议：**", "", remediation or "_未提供。_", ""])

    return lines


def render_report(findings: list[Finding], state: ArgusState) -> str:
    """把 findings 渲染成 markdown 安全报告。

    findings 按严重度降序(critical → high → medium → low → info)分组,并跨分组
    全局连续编号;每条渲染标题、severity/confidence、vuln_class、analyzer、
    locations(可点击 Markdown 链接)、data_flow、rationale、evidence、remediation。
    findings 为空时返回一份合法的 "未发现漏洞" 报告。severity/confidence 同时兼容
    枚举与字符串。位置链接以报告落盘目录(report_path 所在目录)为基准,解析到
    repo_path 下的真实源码文件。
    """
    lines = _render_header(findings, state)

    if not findings:
        return "\n".join(lines).rstrip() + "\n"

    repo_path = state["repo_path"]
    report_dir = os.path.dirname(state["report_path"])

    lines.extend(["## 漏洞详情", ""])

    groups = _group_by_severity(findings)
    index = 0
    for severity in _ordered_severities(groups):
        lines.extend([f"### {_severity_label(severity)}", ""])
        for finding in groups[severity]:
            index += 1
            lines.extend(_render_finding(finding, index, repo_path, report_dir))

    return "\n".join(lines).rstrip() + "\n"
