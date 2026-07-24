"""T16: deterministic Finding-to-ground-truth scoring."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import cast

from argus.contracts import Confidence, Finding, Severity
from argus.eval.score import score, score_detection

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


def test_detection_score_ignores_taxonomy_but_requires_source_anchor() -> None:
    ground_truth = {"vulns": [{"id": "debug", "vuln_class": "auth", "file": "api/users.py", "line": 10}]}
    findings = [
        _finding("same-vulnerability-different-class", "authz", "api/users.py", 11),
        _finding("wrong-location", "auth", "api/other.py", 10),
    ]

    result = score_detection(findings, ground_truth)

    assert result == {
        "recall": 1.0,
        "tp": 1,
        "fn": 0,
        "matched": [
            {
                "ground_truth_id": "debug",
                "finding_index": 0,
                "finding_id": "same-vulnerability-different-class",
            }
        ],
    }


def test_detection_score_accepts_a_ground_truth_source_range() -> None:
    ground_truth = {
        "vulns": [
            {
                "id": "login-enumeration",
                "vuln_class": "auth",
                "location": {"file": "api/users.py", "line": 85, "end_line": 106},
            }
        ]
    }
    findings = [
        _finding("handler-entry", "auth", "api/users.py", 85),
        _finding("vulnerable-branch", "auth", "api/users.py", 101),
    ]

    result = score_detection(findings, ground_truth)

    assert result["tp"] == 1
    assert result["fn"] == 0
    assert result["recall"] == 1.0


def test_detection_score_does_not_cross_unrelated_vulnerability_families() -> None:
    ground_truth = {"vulns": [{"id": "coupon-sqli", "vuln_class": "injection", "file": "api/coupon.py", "line": 40}]}
    findings = [_finding("nearby-authz", "authz", "api/coupon.py", 40)]

    result = score_detection(findings, ground_truth)

    assert result == {"recall": 0.0, "tp": 0, "fn": 1, "matched": []}


def test_handler_fallback_rejects_a_different_structured_handler() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "wallet-auth",
                "in_scope": True,
                "invariant_kind": "authentication",
                "location": "api/users.py",
                "handler": "get_wallet",
                "source": "api/users.py get_wallet requires authentication",
            }
        ]
    }
    finding = _finding(
        "wrong-handler",
        "auth",
        "api/users.py",
        1,
        node_id="function:0123456789abcdef|register",
        title="Missing authentication on registration",
    )

    result = score([finding], ground_truth)

    assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 1, "fn": 1, "matched": []}


def test_handler_fallback_treats_hash_only_codegraph_id_as_opaque() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "wallet-auth",
                "in_scope": True,
                "invariant_kind": "authentication",
                "location": "api/users.py",
                "handler": "get_wallet",
                "source": "api/users.py get_wallet requires authentication",
            }
        ]
    }
    finding = _finding(
        "hash-only-node-id",
        "auth",
        "api/users.py",
        79,
        node_id="function:35835a02b83d77772ccba3d4b39e61cc",
        title="Missing authentication in get_wallet",
    )

    result = score(findings=[finding], ground_truth=ground_truth)

    assert result["tp"] == 1
    assert result["fn"] == 0
    assert result["recall"] == 1.0


def test_handler_fallback_does_not_accept_substrings_or_free_text_override() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "register-boundary",
                "in_scope": True,
                "invariant_kind": "trust_boundary",
                "location": "api/users.py",
                "handler": "register",
                "source": "api/users.py register trusts client-controlled fields",
            }
        ]
    }
    finding = _finding(
        "substring-handler",
        "business-logic",
        "api/users.py",
        1,
        node_id="function:0123456789abcdef|registered_users",
        title="Trust boundary issue for registered users",
    )
    finding["evidence"] = "The report mentions register, but the anchored handler is registered_users."

    result = score([finding], ground_truth)

    assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 1, "fn": 1, "matched": []}


def test_handler_fallback_rejects_prefixed_symbol_names() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "wallet-auth",
                "in_scope": True,
                "invariant_kind": "authentication",
                "location": "api/users.py",
                "handler": "get_wallet",
                "source": "api/users.py get_wallet requires authentication",
            }
        ]
    }

    for symbol in ("pre_get_wallet", "admin_get_wallet"):
        finding = _finding(
            f"wrong-{symbol}",
            "auth",
            "api/users.py",
            1,
            node_id=f"function:0123456789abcdef|{symbol}",
            title="Missing authentication on wallet access",
        )

        result = score([finding], ground_truth)

        assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 1, "fn": 1, "matched": []}


def test_generic_business_logic_requires_matching_invariant_semantics() -> None:
    ground_truth = {
        "vulnerabilities": [
            {
                "id": "order-owner",
                "in_scope": True,
                "invariant_kind": "ownership",
                "location": "api/orders.py:40",
                "handler": "get_order",
                "source": "api/orders.py:40 get_order lacks an ownership check",
            }
        ]
    }
    finding = _finding(
        "nearby-replay",
        "business-logic",
        "api/orders.py",
        42,
        node_id="api/orders.py::refund_order",
        title="Refund replay due to missing idempotency guard",
    )
    finding["data_flow"] = "duplicate refund request -> repeated credit"
    finding["rationale"] = "The operation is replayable."
    finding["evidence"] = "No idempotency key is checked."

    result = score([finding], ground_truth)

    assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 1, "fn": 1, "matched": []}


def test_malformed_finding_is_counted_as_false_positive_instead_of_crashing() -> None:
    ground_truth = {"vulns": [{"id": "v1", "vuln_class": "authz", "file": "api/a.py", "line": 10}]}
    malformed = cast(
        Finding,
        {"id": "malformed", "vuln_class": "authz", "locations": [{"file": "api/a.py", "line": 10}]},
    )

    result = score([malformed], ground_truth)

    assert result == {"recall": 0.0, "precision": 0.0, "tp": 0, "fp": 1, "fn": 1, "matched": []}


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
    for path in sorted((ROOT / "evaluation" / "ground_truth").glob("*.json")):
        with path.open(encoding="utf-8") as handle:
            result = score([], json.load(handle))
        false_negatives += result["fn"]
        assert result["tp"] == 0
        assert result["fp"] == 0

    assert false_negatives == 16


def test_real_ground_truth_entries_are_matchable() -> None:
    for path in sorted((ROOT / "evaluation" / "ground_truth").glob("*.json")):
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
                    node_id=f"function:0123456789abcdef|{handler}",
                    title=f"Detected {vulnerability['invariant_kind']} violation in {handler}",
                )
            )

        result = score(findings, ground_truth)
        assert result["tp"] == expected_count, path.name
        assert result["fp"] == 0, path.name
        assert result["fn"] == 0, path.name
        assert result["recall"] == 1.0, path.name
        assert result["precision"] == 1.0, path.name
