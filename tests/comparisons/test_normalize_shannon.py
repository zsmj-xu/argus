"""Tests for Shannon → Finding normalization (C6)."""

from __future__ import annotations

import json
from pathlib import Path


from scripts.normalize_shannon import normalize_shannon_findings


def _write_queue(tmp_path: Path, filename: str, vulnerabilities: list[dict]) -> None:
    (tmp_path / filename).write_text(json.dumps({"vulnerabilities": vulnerabilities}), encoding="utf-8")


def test_authz_entry_maps_to_finding_with_file_line(tmp_path: Path) -> None:
    _write_queue(
        tmp_path,
        "authz_exploitation_queue.json",
        [
            {
                "ID": "AUTHZ-01",
                "vulnerability_type": "IDOR on books",
                "externally_exploitable": True,
                "confidence": "high",
                "endpoint": "GET /books/v1/{book_title}",
                "vulnerable_code_location": "api_views/books.py:51",
                "guard_evidence": "no ownership check on book.user_id",
                "side_effect": "read other users secret_content",
                "notes": "vuln mode flag disables the check",
            }
        ],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "shannon:authz:AUTHZ-01"
    assert f["analyzer"] == "shannon-authz"
    assert f["vuln_class"] == "authz"
    assert f["title"] == "IDOR on books"
    assert f["confidence"] == "high"
    assert f["locations"] == [{"file": "api_views/books.py", "line": 51, "node_id": "api_views/books.py:51"}]
    assert "no ownership check" in f["rationale"]
    assert "endpoint=GET /books/v1/{book_title}" in f["data_flow"]


def test_injection_entry_uses_source_sink_data_flow(tmp_path: Path) -> None:
    _write_queue(
        tmp_path,
        "injection_exploitation_queue.json",
        [
            {
                "ID": "INJ-01",
                "vulnerability_type": "SQL Injection",
                "confidence": "medium",
                "source": "request.args['username']",
                "sink_call": "cursor.execute",
                "path": "api_views/users.py -> models/user_model.py",
                "vulnerable_code_location": "models/user_model.py:73",
                "verdict": "f-string concat into SQL",
            }
        ],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_class"] == "injection"
    assert "source=request.args['username']" in f["data_flow"]
    assert "sink=cursor.execute" in f["data_flow"]
    assert "verdict=f-string concat into SQL" in f["evidence"]


def test_missing_queue_files_are_skipped(tmp_path: Path) -> None:
    _write_queue(tmp_path, "auth_exploitation_queue.json", [{"ID": "A-1", "vulnerability_type": "x"}])
    # 其余 4 个 queue 文件不存在

    findings = normalize_shannon_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0]["vuln_class"] == "auth"


def test_entry_without_id_is_dropped(tmp_path: Path) -> None:
    _write_queue(
        tmp_path,
        "xss_exploitation_queue.json",
        [{"vulnerability_type": "reflected XSS"}, {"ID": "XSS-02", "vulnerability_type": "stored XSS"}],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0]["id"] == "shannon:xss:XSS-02"


def test_entry_without_file_line_produces_empty_locations(tmp_path: Path) -> None:
    """Shannon 报了但定位不到代码 → locations 空 → score.py 自然算 FP(如实反映)。"""
    _write_queue(
        tmp_path,
        "ssrf_exploitation_queue.json",
        [{"ID": "SSRF-01", "vulnerability_type": "SSRF", "source_endpoint": "POST /fetch"}],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0]["locations"] == []


def test_line_range_format_uses_start_line(tmp_path: Path) -> None:
    """Shannon 实际产物用行范围(如 'api_views/books.py:50-60'),取 start line。"""
    _write_queue(
        tmp_path,
        "authz_exploitation_queue.json",
        [{"ID": "AZ-01", "vulnerability_type": "IDOR", "vulnerable_code_location": "api_views/books.py:50-60"}],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert findings[0]["locations"] == [{"file": "api_views/books.py", "line": 50, "node_id": "api_views/books.py:50"}]


def test_all_five_classes_loaded(tmp_path: Path) -> None:
    for filename, cls in [
        ("injection_exploitation_queue.json", "injection"),
        ("xss_exploitation_queue.json", "xss"),
        ("auth_exploitation_queue.json", "auth"),
        ("ssrf_exploitation_queue.json", "ssrf"),
        ("authz_exploitation_queue.json", "authz"),
    ]:
        _write_queue(tmp_path, filename, [{"ID": f"{cls}-1", "vulnerability_type": cls}])

    findings = normalize_shannon_findings(tmp_path)

    assert {f["vuln_class"] for f in findings} == {"injection", "xss", "auth", "ssrf", "authz"}


def test_unknown_confidence_defaults_to_medium(tmp_path: Path) -> None:
    _write_queue(
        tmp_path,
        "auth_exploitation_queue.json",
        [{"ID": "A-1", "vulnerability_type": "x", "confidence": "very-high"}],
    )

    findings = normalize_shannon_findings(tmp_path)

    assert findings[0]["confidence"] == "medium"


def test_empty_directory_returns_empty_list(tmp_path: Path) -> None:
    assert normalize_shannon_findings(tmp_path) == []


def test_normalized_findings_scoreable_against_vampi_gt(tmp_path: Path) -> None:
    """归一后的 Finding 能被 score.py 消费(端到端 smoke)。

    vampi.json 的 GT 多数无 line(只有 handler),score.py 走 handler 文本匹配:
    finding 的 title/rationale/evidence 须含 handler 名(get_by_title)。
    真实 Shannon 产物的 vulnerability_type/notes 通常含 handler,这里如实构造。
    """
    from argus.eval.score import score

    _write_queue(
        tmp_path,
        "authz_exploitation_queue.json",
        [
            {
                "ID": "S-BOLA-BOOKS",
                "vulnerability_type": "IDOR in get_by_title handler",
                "confidence": "high",
                "vulnerable_code_location": "api_views/books.py:50",
                "guard_evidence": "no ownership check in get_by_title",
                "notes": "get_by_title returns book without owner check",
            }
        ],
    )
    gt = {
        "vulnerabilities": [
            {
                "id": "vampi-bola-books-get",
                "in_scope": True,
                "invariant_kind": "ownership",
                "location": "api_views/books.py",
                "handler": "get_by_title",
            }
        ]
    }

    findings = normalize_shannon_findings(tmp_path)
    result = score(findings, gt)

    assert result["tp"] == 1
    assert result["recall"] == 1.0
