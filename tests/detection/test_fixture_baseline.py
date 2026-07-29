from __future__ import annotations

import json
from pathlib import Path

from argus.detection.builtin.injection.provider import InjectionCandidateProvider

from .test_candidate_pipeline import _injection_context


def test_m6_fixture_recall_and_false_positive_baseline() -> None:
    baseline = json.loads((Path(__file__).parent / "fixtures" / "m6_baseline.json").read_text(encoding="utf-8"))[
        "injection"
    ]
    candidates = InjectionCandidateProvider().generate(_injection_context())
    detected = {candidate.primary_node_ids[0] for candidate in candidates}
    expected = set(baseline["expected_candidates"])
    safe = set(baseline["expected_safe_exclusions"])
    recall = len(detected & expected) / len(expected)
    false_positives = len(detected & safe)

    assert recall >= baseline["minimum_fixture_recall"]
    assert false_positives <= baseline["maximum_fixture_false_positives"]
