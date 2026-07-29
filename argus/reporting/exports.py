"""Deterministic interchange exports from Canonical Finding records."""

from __future__ import annotations

import json
from typing import Any

from argus.domain.models import StaticFindingV2


def _ordered(findings: list[StaticFindingV2]) -> list[StaticFindingV2]:
    return sorted(findings, key=lambda finding: (finding.fingerprint, str(finding.id)))


def findings_json(findings: list[StaticFindingV2]) -> str:
    payload = [finding.model_dump(mode="json") for finding in _ordered(findings)]
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def findings_sarif(findings: list[StaticFindingV2]) -> str:
    ordered = _ordered(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    severity_levels = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    for finding in ordered:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.vuln_class,
                "shortDescription": {"text": finding.title},
                "properties": {
                    "ruleVersion": finding.rule_version,
                    "weaknessId": finding.weakness_id,
                },
            },
        )
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location.file},
                    "region": {"startLine": location.line},
                }
            }
            for location in finding.locations
        ]
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": severity_levels[finding.severity.value],
                "message": {"text": finding.rationale},
                "locations": locations,
                "fingerprints": {"argus/v2": finding.fingerprint},
                "properties": {
                    "findingId": str(finding.id),
                    "staticConfidence": finding.static_confidence.value,
                    "status": finding.status.value,
                    "remediation": finding.remediation,
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
