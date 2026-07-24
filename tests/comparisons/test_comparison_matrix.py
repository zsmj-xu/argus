"""Matrix orchestration distinguishes missing artifacts from zero scores."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from evaluation.scripts.run_comparison_matrix import build_matrix, render_markdown

ROOT = Path(__file__).resolve().parents[2]


def test_missing_run_artifacts_are_unavailable_not_zero(tmp_path: Path) -> None:
    gt = tmp_path / "gt.json"
    gt.write_text('{"vulnerabilities": []}', encoding="utf-8")
    manifest = tmp_path / "matrix.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "targets": [
                    {
                        "id": "pending",
                        "ground_truth": str(gt),
                        "argus_findings": str(tmp_path / "missing-findings.json"),
                        "shannon_deliverables": str(tmp_path / "missing-deliverables"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    matrix = build_matrix(manifest)

    target = matrix["targets"][0]
    assert target["status"] == "unavailable"
    assert set(target["missing_artifacts"]) == {"argus_findings", "shannon_deliverables"}
    assert target["scope"]["comparison_positive_count"] == 0
    assert "0.000" not in render_markdown(matrix)
    assert "N/A" in render_markdown(matrix)


def test_partial_run_exposes_available_side_without_marking_complete(tmp_path: Path) -> None:
    gt = tmp_path / "gt.json"
    gt.write_text(
        '{"vulnerabilities": [{"id": "known", "vuln_class": "auth", '
        '"comparison_in_scope": true, "comparison_location": '
        '{"file": "app.py", "line": 10}}]}',
        encoding="utf-8",
    )
    findings = tmp_path / "findings.json"
    findings.write_text(
        '[{"id": "f-1", "vuln_class": "auth", "title": "missing auth", '
        '"locations": [{"file": "app.py", "line": 10, "node_id": "function:test"}]}]',
        encoding="utf-8",
    )
    manifest = tmp_path / "matrix.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "targets": [
                    {
                        "id": "partial",
                        "ground_truth": str(gt),
                        "argus_findings": str(findings),
                        "shannon_deliverables": str(tmp_path / "missing-deliverables"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    matrix = build_matrix(manifest)

    target = matrix["targets"][0]
    assert target["status"] == "unavailable"
    assert target["missing_artifacts"] == ["shannon_deliverables"]
    assert target["available_results"]["argus"]["detection_score"]["recall"] == 1.0
    rendered = render_markdown(matrix)
    assert "| partial | unavailable | N/A | 1.000 |" in rendered
    assert "available: argus only" in rendered


def test_repository_matrix_references_existing_inputs_and_configs() -> None:
    manifest = ROOT / "docs" / "comparisons" / "comparison-matrix.yaml"
    with manifest.open(encoding="utf-8") as handle:
        targets = yaml.safe_load(handle)["targets"]

    assert [target["id"] for target in targets] == [
        "vampi",
        "flowmart",
        "crapi-workshop",
        "crapi-community",
    ]
    for target in targets:
        for field in ("source", "ground_truth", "argus_config"):
            assert (ROOT / target[field]).exists(), (target["id"], field)


def test_flowmart_matrix_discloses_replay_as_outside_five_class_comparison() -> None:
    matrix = build_matrix(ROOT / "docs" / "comparisons" / "comparison-matrix.yaml")
    flowmart = next(target for target in matrix["targets"] if target["id"] == "flowmart")

    assert flowmart["scope"]["comparison_positive_count"] == 6
    assert flowmart["scope"]["business_scope_excluded_ids"] == ["flowmart-refund-replay"]
    assert "flowmart-refund-replay" in render_markdown(matrix)


def test_invalid_ground_truth_shape_is_rejected(tmp_path: Path) -> None:
    gt = tmp_path / "gt.json"
    gt.write_text('{"vulnerabilities": "not-a-list"}', encoding="utf-8")
    manifest = tmp_path / "matrix.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "targets": [
                    {
                        "id": "invalid",
                        "ground_truth": str(gt),
                        "argus_findings": str(tmp_path / "missing.json"),
                        "shannon_deliverables": str(tmp_path / "missing"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid ground truth"):
        build_matrix(manifest)
