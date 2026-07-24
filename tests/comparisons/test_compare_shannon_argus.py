"""Tests for Shannon vs Argus comparison scoring (C7)."""

from __future__ import annotations

import json
from pathlib import Path

from evaluation.scripts.compare_shannon_argus import compare, render_markdown


def _write_shannon_queue(deliverables: Path, cls: str, entries: list[dict]) -> None:
    deliverables.mkdir(parents=True, exist_ok=True)
    (deliverables / f"{cls}_exploitation_queue.json").write_text(
        json.dumps({"vulnerabilities": entries}), encoding="utf-8"
    )


def _write_argus_findings(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings), encoding="utf-8")


def _vampi_gt() -> dict:
    return {
        "vulnerabilities": [
            {
                "id": "vampi-bola-books-get",
                "in_scope": True,
                "invariant_kind": "ownership",
                "location": "api_views/books.py",
                "handler": "get_by_title",
            },
            {
                "id": "vampi-auth-debug",
                "in_scope": True,
                "invariant_kind": "authentication",
                "location": "api_views/users.py",
                "handler": "debug",
            },
        ]
    }


def test_compare_scores_both_sides_against_same_gt(tmp_path: Path) -> None:
    deliverables = tmp_path / "deliverables"
    # Shannon 命中 books BOLA,漏 debug
    _write_shannon_queue(
        deliverables,
        "authz",
        [
            {
                "ID": "S-1",
                "vulnerability_type": "IDOR in get_by_title",
                "vulnerable_code_location": "api_views/books.py:50",
                "confidence": "high",
                "guard_evidence": "no ownership check in get_by_title",
            },
        ],
    )
    # Argus 命中 books + debug
    argus_path = tmp_path / "argus" / "findings.json"
    _write_argus_findings(
        argus_path,
        [
            {
                "id": "argus:authz:1",
                "analyzer": "authz",
                "vuln_class": "authz",
                "title": "IDOR get_by_title",
                "severity": "high",
                "confidence": "high",
                "locations": [{"file": "api_views/books.py", "line": 51, "node_id": "function:abc|get_by_title"}],
                "data_flow": "",
                "rationale": "",
                "evidence": "",
                "remediation": "",
            },
            {
                "id": "argus:auth:2",
                "analyzer": "auth",
                "vuln_class": "auth",
                "title": "Missing auth on debug endpoint",
                "severity": "high",
                "confidence": "high",
                "locations": [{"file": "api_views/users.py", "line": 25, "node_id": "function:def|debug"}],
                "data_flow": "",
                "rationale": "",
                "evidence": "",
                "remediation": "",
            },
        ],
    )
    gt_path = tmp_path / "vampi.json"
    gt_path.write_text(json.dumps(_vampi_gt()), encoding="utf-8")

    result = compare(deliverables, argus_path, gt_path)

    assert result["shannon"]["detection_score"]["tp"] == 1
    assert result["shannon"]["detection_score"]["fn"] == 1
    assert result["argus"]["detection_score"]["tp"] == 2
    assert result["argus"]["detection_score"]["fn"] == 0
    assert "precision" not in result["argus"]["taxonomy_agreement"]
    assert "fp" not in result["argus"]["taxonomy_agreement"]
    assert result["argus"]["per_class_detection"]["authz"]["recall"] == 1.0
    assert result["argus"]["per_class_detection"]["xss"]["recall"] is None


def test_compare_uses_comparison_scope_without_changing_invariant_scope(tmp_path: Path) -> None:
    deliverables = tmp_path / "deliverables"
    _write_shannon_queue(
        deliverables,
        "injection",
        [
            {
                "ID": "SQL-1",
                "vulnerability_type": "SQL Injection",
                "sink_call": "models/user_model.py:73 execute",
            }
        ],
    )
    argus_path = tmp_path / "argus" / "findings.json"
    _write_argus_findings(
        argus_path,
        [
            {
                "id": "argus:injection:1",
                "analyzer": "injection",
                "vuln_class": "injection",
                "title": "SQL Injection",
                "severity": "high",
                "confidence": "high",
                "locations": [{"file": "models/user_model.py", "line": 73, "node_id": "method:User.get_user"}],
                "data_flow": "",
                "rationale": "",
                "evidence": "",
                "remediation": "",
            }
        ],
    )
    gt_path = tmp_path / "vampi.json"
    gt_path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "sqli",
                        "in_scope": False,
                        "comparison_in_scope": True,
                        "comparison_vuln_class": "injection",
                        "invariant_kind": "n/a",
                        "location": "models/user_model.py",
                        "line": 73,
                        "handler": "get_user",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = compare(deliverables, argus_path, gt_path)

    assert result["shannon"]["detection_score"]["tp"] == 1
    assert result["argus"]["detection_score"]["tp"] == 1


def test_overlap_computed_correctly(tmp_path: Path) -> None:
    deliverables = tmp_path / "deliverables"
    _write_shannon_queue(
        deliverables,
        "authz",
        [
            {
                "ID": "S-1",
                "vulnerability_type": "IDOR in get_by_title",
                "vulnerable_code_location": "api_views/books.py:50",
                "guard_evidence": "get_by_title no check",
            },
        ],
    )
    argus_path = tmp_path / "argus" / "findings.json"
    _write_argus_findings(
        argus_path,
        [
            {
                "id": "argus:authz:1",
                "analyzer": "authz",
                "vuln_class": "authz",
                "title": "IDOR get_by_title",
                "severity": "high",
                "confidence": "high",
                "locations": [{"file": "api_views/books.py", "line": 51, "node_id": "function:x|get_by_title"}],
                "data_flow": "",
                "rationale": "",
                "evidence": "",
                "remediation": "",
            },
        ],
    )
    gt_path = tmp_path / "vampi.json"
    gt_path.write_text(json.dumps(_vampi_gt()), encoding="utf-8")

    result = compare(deliverables, argus_path, gt_path)

    assert result["overlap"]["both_hit"] == ["vampi-bola-books-get"]
    assert result["overlap"]["only_shannon"] == []
    assert result["overlap"]["only_argus"] == []


def test_render_markdown_contains_both_tools(tmp_path: Path) -> None:
    deliverables = tmp_path / "deliverables"
    _write_shannon_queue(deliverables, "authz", [])
    argus_path = tmp_path / "argus" / "findings.json"
    _write_argus_findings(argus_path, [])
    gt_path = tmp_path / "vampi.json"
    gt_path.write_text(json.dumps(_vampi_gt()), encoding="utf-8")

    result = compare(deliverables, argus_path, gt_path)
    md = render_markdown(result)

    assert "Shannon" in md
    assert "Argus" in md
    assert "Recall" in md
    assert "Precision" in md
    assert "不报告 Precision" in md
    assert "N/A (无正样本)" in md


def test_adjudication_reports_unknown_findings_instead_of_assuming_false(tmp_path: Path) -> None:
    deliverables = tmp_path / "deliverables"
    _write_shannon_queue(
        deliverables,
        "auth",
        [{"ID": "A-1", "vulnerability_type": "Missing auth", "vulnerable_code_location": "api/users.py:10"}],
    )
    argus_path = tmp_path / "argus" / "findings.json"
    _write_argus_findings(argus_path, [])
    gt_path = tmp_path / "gt.json"
    gt_path.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "id": "auth",
                        "in_scope": True,
                        "invariant_kind": "authentication",
                        "location": "api/users.py:10",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    adjudication_path = tmp_path / "adjudication.json"
    adjudication_path.write_text(json.dumps({"shannon": {}, "argus": {}}), encoding="utf-8")

    result = compare(deliverables, argus_path, gt_path, adjudication_path)

    summary = result["shannon"]["adjudication"]
    assert summary["adjudicated"] == 0
    assert summary["unadjudicated"] == ["shannon:auth:A-1"]
    assert summary["validity_precision"] is None
