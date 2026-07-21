"""Normalize Shannon deliverables into Argus ``Finding`` shape for ``score()``.

阶段 C 对照(C6):Shannon 产 ``*_exploitation_queue.json`` 5 个文件(每类一个),
每条是 SDK-validated 结构化 JSON(见 shannon/apps/worker/src/ai/queue-schemas.ts)。
本模块把它们归一成 ``argus.eval.score.score()`` 可消费的 ``list[Finding]``,
让 Shannon 与 Argus 用同一把尺(``score.py`` + 同一份 ``vampi.json``)打分。

映射要点:
- 文件名编码 vuln_class(injection/xss/auth/authz/ssrf)。
- 每条 entry 的 ``vulnerable_code_location`` 形如 ``api_views/books.py:51`` →
  拆成 file + line。Shannon 是黑盒、不锚 codegraph,故 node_id 用 ``file:line``
  (score.py 的 ``_node_symbol`` 提不出符号时退回 handler 文本匹配)。
- severity 不被 score.py 消费,按 confidence 近似填;confidence 直接取 entry 的。
- injection/xss 还有 ``path``/``sink_call``/``source`` 等字段,拼进 evidence 便于人工审阅。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from argus.contracts import CodeLocation, Confidence, Finding, Severity

# 文件名 → vuln_class。与 shannon queue-schemas.ts 的 VULN_AGENT_QUEUE_FILENAMES 对齐。
_QUEUE_FILES: dict[str, str] = {
    "injection_exploitation_queue.json": "injection",
    "xss_exploitation_queue.json": "xss",
    "auth_exploitation_queue.json": "auth",
    "ssrf_exploitation_queue.json": "ssrf",
    "authz_exploitation_queue.json": "authz",
}

# Shannon confidence(low/medium/high) → Argus Confidence 枚举。
_CONFIDENCE_MAP: dict[str, Confidence] = {
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
}

# 没有 severity 时,按 vuln_class 给一个保守默认(仅用于报告,score.py 不消费)。
_DEFAULT_SEVERITY: dict[str, Severity] = {
    "injection": Severity.HIGH,
    "xss": Severity.MEDIUM,
    "auth": Severity.HIGH,
    "authz": Severity.HIGH,
    "ssrf": Severity.HIGH,
}

# 匹配 "file:line" 或 "file:start-end"(取 start)。Shannon 实际产物形如
# "api_views/books.py:50-60" 或 "config.py:13 (SECRET_KEY='random'), models/...",
# 即行首一个路径后跟 :line,后面可能有括号注释或多段。路径字符排除空格/括号/逗号,
# 非贪婪匹配行首第一个 "路径:数字" 片段。
_FILE_LINE_RE = re.compile(r"^([^\s(),]+):(\d+)(?:-\d+)?")


def normalize_shannon_findings(deliverables_dir: str | Path) -> list[Finding]:
    """读 Shannon deliverables 目录下所有 ``*_exploitation_queue.json``,归一成 Finding 列表。

    缺失的 queue 文件(该类未跑或无产物)静默跳过。每个 entry 至少产出一条 Finding;
    若 entry 解析不出 file:line 锚点,仍产出 Finding 但 locations 为空——score.py 会
    因无 anchor 而不计入匹配(即自然算 FP),这如实反映"Shannon 报了但定位不到代码"。
    """
    base = Path(deliverables_dir)
    findings: list[Finding] = []
    for filename, vuln_class in _QUEUE_FILES.items():
        queue_path = base / filename
        if not queue_path.is_file():
            continue
        doc = _load_json(queue_path)
        entries = doc.get("vulnerabilities", []) if isinstance(doc, dict) else []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            finding = _entry_to_finding(entry, vuln_class)
            if finding is not None:
                findings.append(finding)
    return findings


def _entry_to_finding(entry: dict[str, Any], vuln_class: str) -> Finding | None:
    """把一条 Shannon queue entry 映射成一条 Finding。无 ID 的条目丢弃。"""
    entry_id = entry.get("ID")
    if not isinstance(entry_id, str) or not entry_id.strip():
        return None

    location = _parse_location(entry, vuln_class)
    locations: list[CodeLocation] = []
    if location is not None:
        file, line = location
        node_id = f"{file}:{line}"
        locations.append({"file": file, "line": line, "node_id": node_id})

    vuln_type = entry.get("vulnerability_type", vuln_class)
    title = vuln_type if isinstance(vuln_type, str) and vuln_type else vuln_class
    confidence = _confidence(entry)
    severity = _DEFAULT_SEVERITY.get(vuln_class, Severity.MEDIUM)

    return {
        "id": f"shannon:{vuln_class}:{entry_id}",
        "analyzer": f"shannon-{vuln_class}",
        "vuln_class": vuln_class,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "locations": locations,
        "data_flow": _data_flow(entry, vuln_class),
        "rationale": _rationale(entry, vuln_class),
        "evidence": _evidence(entry, vuln_class),
        "remediation": "",
    }


def _parse_location(entry: dict[str, Any], vuln_class: str) -> tuple[str, int] | None:
    """从 entry 提 (file, line)。优先 vulnerable_code_location,其次 source/path。"""
    for key in ("vulnerable_code_location", "source", "path", "source_endpoint", "endpoint"):
        value = entry.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        match = _FILE_LINE_RE.match(value.strip())
        if match is not None:
            return match.group(1), int(match.group(2))
    _ = vuln_class  # 目前不按 class 差异化;保留参数便于后续扩展
    return None


def _confidence(entry: dict[str, Any]) -> Confidence:
    raw = entry.get("confidence")
    if isinstance(raw, str):
        return _CONFIDENCE_MAP.get(raw.strip().lower(), Confidence.MEDIUM)
    return Confidence.MEDIUM


def _data_flow(entry: dict[str, Any], vuln_class: str) -> str:
    """injection/xss 有 source→sink 链;其他类用 endpoint 概述。"""
    if vuln_class in ("injection", "xss"):
        source = entry.get("source") or entry.get("source_detail") or ""
        sink = entry.get("sink_call") or entry.get("sink_function") or ""
        path = entry.get("path") or ""
        parts = [p for p in (f"source={source}", f"sink={sink}", f"path={path}") if p.split("=", 1)[1]]
        return " | ".join(parts) if parts else ""
    endpoint = entry.get("source_endpoint") or entry.get("endpoint") or ""
    return f"endpoint={endpoint}" if endpoint else ""


def _rationale(entry: dict[str, Any], vuln_class: str) -> str:
    for key in ("missing_defense", "guard_evidence", "mismatch_reason", "reason"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    _ = vuln_class
    return ""


def _evidence(entry: dict[str, Any], vuln_class: str) -> str:
    """拼接剩余结构化字段,便于人工审阅对照表。"""
    fields = (
        ("externally_exploitable", "exploitable"),
        ("verdict", "verdict"),
        ("role_context", "role"),
        ("side_effect", "side_effect"),
        ("witness_payload", "witness"),
        ("minimal_witness", "witness"),
        ("notes", "notes"),
    )
    parts: list[str] = []
    for src, label in fields:
        value = entry.get(src)
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        parts.append(f"{label}={text}")
    _ = vuln_class
    return " | ".join(parts)


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)
