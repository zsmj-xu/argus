"""Tests for Shannon vs Argus comparison scoring (C7)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.compare_shannon_argus import compare, render_markdown


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

    assert result["shannon"]["score"]["tp"] == 1
    assert result["shannon"]["score"]["fn"] == 1
    assert result["argus"]["score"]["tp"] == 2
    assert result["argus"]["score"]["fn"] == 0


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
