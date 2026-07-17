"""Side-by-side graph and isolated-baseline evaluation."""

from __future__ import annotations

from typing import Any, TypedDict

from argus.contracts import Finding
from argus.eval.score import ScoreResult, score


class ComparisonResult(TypedDict):
    graph: ScoreResult
    baseline: ScoreResult


def compare(
    graph_findings: list[Finding],
    baseline_findings: list[Finding],
    ground_truth: dict[str, Any],
) -> ComparisonResult:
    """Score graph and no-graph findings against the same ground truth."""
    return {
        "graph": score(graph_findings, ground_truth),
        "baseline": score(baseline_findings, ground_truth),
    }
