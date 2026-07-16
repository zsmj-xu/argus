"""T16: deterministic Finding-to-ground-truth scoring."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path

from argus.contracts import Confidence, Finding, Severity
from argus.eval.score import score

ROOT = Path(__file__).resolve().parents[2]


def _finding(
    finding_id: str,
    vuln_class: str,
    file: str,
    line: int,
    *,
    node_id: str | None = None,
    title: str = "Detected vulnerability",
) -> Finding:
    return {
        "id": finding_id,
        "analyzer": "test",
        "vuln_class": vuln_class,
        "title": title,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "locations": [{"file": file, "line": line, "node_id": node_id or f"function:{file}:{line}"}],
        "data_flow": "request -> sink",
        "rationale": "test rationale",
        "evidence": "test evidence",
        "remediation": "test remediation",
    }


def test_scores_exact_and_nearby_locations() -> None:
    ground_truth = {
        "vulns": [
            {"id": "v1", "vuln_class": "authz", "file": "api/a.py", "line": 10},
            {"id": "v2", "vuln_class": "injection", "file": "api/b.py", "line": 40},
        ]
    }
    findings = [
        _finding("f1", "authz", "./api/a.py", 10),
        _finding("f2", "injection", "/repo/api/b.py", 47),
        _finding("f3", "xss", "api/other.py", 1),
    ]

    result = score(findings, ground_truth)

    assert result == {
        "recall": 1.0,
        "precision": 2 / 3,
        "tp": 2,
        "fp": 1,
        "fn": 0,
        "matched": [
            {"ground_truth_id": "v1", "finding_index": 0, "finding_id": "f1"},
            {"ground_truth_id": "v2", "finding_index": 1, "finding_id": "f2"},
        ],
    }


def test_filters_out_of_scope_and_matches_imported_business_logic_schema() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "refund-replay",
                "in_scope": True,
                "invariant_kind": "replay",
                "vuln_type": "Refund replay",
                "location": "api/orders.py",
                "handler": "refund_order",
                "source": "api/orders.py:120 refund_order lacks an idempotency guard",
            },
            {
                "id": "orders-sqli",
                "in_scope": False,
                "invariant_kind": "n/a",
                "vuln_type": "SQL Injection",
                "location": "api/orders.py",
                "handler": "search_orders",
                "source": "api/orders.py:20 query interpolation",
            },
        ]
    }
    findings = [
        _finding(
            "business-logic:replay:1",
            "business-logic",
            "api/orders.py",
            125,
            node_id="function:api/orders.py:refund_order",
            title="Refund can be replayed",
        ),
        _finding("injection:sql:1", "injection", "api/orders.py", 20),
    ]

    result = score(findings, ground_truth)

    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["fn"] == 0
    assert result["recall"] == 1.0
    assert result["precision"] == 0.5
    assert result["matched"] == [
        {"ground_truth_id": "refund-replay", "finding_index": 0, "finding_id": "business-logic:replay:1"}
    ]


def test_requires_compatible_class_and_location() -> None:
    ground_truth = {
        "vulns": [
            {"id": "v1", "vuln_class": "authz", "file": "api/a.py", "line": 10},
            {"id": "v2", "vuln_class": "authz", "file": "api/b.py", "line": 20},
        ]
    }
    findings = [
        _finding("wrong-class", "injection", "api/a.py", 10),
        _finding("wrong-file", "authz", "api/c.py", 20),
        _finding("too-far", "authz", "api/b.py", 100),
    ]

    result = score(findings, ground_truth)

    assert result["tp"] == 0
    assert result["fp"] == 3
    assert result["fn"] == 2
    assert result["recall"] == 0.0
    assert result["precision"] == 0.0
    assert result["matched"] == []


def test_matching_is_one_to_one_and_maximizes_hits() -> None:
    ground_truth = {
        "vulns": [
            {"id": "v1", "vuln_class": "authz", "file": "api/a.py", "line": 10},
            {"id": "v2", "vuln_class": "authz", "file": "api/a.py", "line": 18},
        ]
    }
    flexible = _finding("flexible", "authz", "api/a.py", 14)
    flexible["locations"].append({"file": "api/a.py", "line": 18, "node_id": "function:a:v2"})
    findings = [flexible, _finding("only-v1", "authz", "api/a.py", 10)]

    result = score(findings, ground_truth)

    assert result["tp"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert {match["ground_truth_id"] for match in result["matched"]} == {"v1", "v2"}
    assert {match["finding_id"] for match in result["matched"]} == {"flexible", "only-v1"}


def test_empty_inputs_are_zero_and_inputs_are_not_mutated() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "ignored",
                "in_scope": False,
                "invariant_kind": "n/a",
                "vuln_type": "SQL Injection",
                "location": "api/a.py",
            }
        ]
    }
    findings: list[Finding] = []
    original_ground_truth = deepcopy(ground_truth)

    result = score(findings, ground_truth)

    assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 0, "fn": 0, "matched": []}
    assert ground_truth == original_ground_truth


def test_real_ground_truth_counts_only_in_scope_vulnerabilities() -> None:
    false_negatives = 0
    for path in sorted((ROOT / "ground_truth").glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            result = score([], json.load(handle))
        false_negatives += result["fn"]
        assert result["tp"] == 0
        assert result["fp"] == 0

    assert false_negatives == 18


def test_real_ground_truth_entries_are_matchable() -> None:
    for path in sorted((ROOT / "ground_truth").glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            ground_truth = json.load(handle)

        findings: list[Finding] = []
        expected_count = 0
        for vulnerability in ground_truth["vulnerabilities"]:
            if not vulnerability["in_scope"]:
                continue
            expected_count += 1
            location = vulnerability["location"]
            line_match = re.search(rf"{re.escape(location)}:(\d+)", vulnerability["source"])
            line = int(line_match.group(1)) if line_match else 1
            handler = vulnerability["handler"]
            findings.append(
                _finding(
                    f"finding:{vulnerability['id']}",
                    "business-logic",
                    location,
                    line,
                    node_id=f"function:{location}:{handler}",
                    title=f"Detected {handler}",
                )
            )

        result = score(findings, ground_truth)
        assert result["tp"] == expected_count, path.name
        assert result["fp"] == 0, path.name
        assert result["fn"] == 0, path.name
        assert result["recall"] == 1.0, path.name
        assert result["precision"] == 1.0, path.name
