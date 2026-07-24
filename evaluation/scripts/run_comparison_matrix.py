"""Build the cross-target Argus vs Shannon comparison matrix from available artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus.contracts import Finding  # noqa: E402
from argus.eval.score import score, score_detection  # noqa: E402
from evaluation.scripts.compare_shannon_argus import (  # noqa: E402
    _comparison_ground_truth,
    _load_findings,
    compare,
)
from evaluation.scripts.normalize_shannon import normalize_shannon_findings  # noqa: E402


def _resolve(value: str, manifest_path: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    root_candidate = ROOT / path
    if root_candidate.exists() or not value.startswith("../"):
        return root_candidate
    return (manifest_path.parent / path).resolve()


def _scope_summary(ground_truth_path: Path) -> dict[str, Any]:
    with ground_truth_path.open(encoding="utf-8") as handle:
        ground_truth = json.load(handle)
    vulnerabilities = ground_truth.get("vulnerabilities", []) if isinstance(ground_truth, dict) else []
    if not isinstance(vulnerabilities, list) or not all(isinstance(item, dict) for item in vulnerabilities):
        raise ValueError(f"invalid ground truth vulnerabilities: {ground_truth_path}")
    comparison_ids = [
        item["id"] for item in vulnerabilities if item.get("comparison_in_scope", item.get("in_scope", True))
    ]
    excluded_ids = [
        item["id"]
        for item in vulnerabilities
        if item.get("in_scope", True) and not item.get("comparison_in_scope", item.get("in_scope", True))
    ]
    return {
        "comparison_positive_count": len(comparison_ids),
        "comparison_ids": comparison_ids,
        "business_scope_excluded_ids": excluded_ids,
    }


def _side_score(findings: list[Finding], ground_truth: dict[str, Any]) -> dict[str, Any]:
    detection = score_detection(findings, ground_truth)
    taxonomy = score(findings, ground_truth)
    return {
        "findings_count": len(findings),
        "detection_score": detection,
        "taxonomy_agreement": {key: taxonomy[key] for key in ("recall", "tp", "fn", "matched")},
    }


def build_matrix(manifest_path: Path) -> dict[str, Any]:
    with manifest_path.open(encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    targets = payload.get("targets", []) if isinstance(payload, dict) else []
    if not isinstance(targets, list):
        raise ValueError("comparison matrix targets must be a list")

    results: list[dict[str, Any]] = []
    for raw in targets:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise ValueError("each comparison target must have a string id")
        target_id = raw["id"]
        required = ("ground_truth", "argus_findings", "shannon_deliverables")
        missing_fields = [field for field in required if not isinstance(raw.get(field), str)]
        if missing_fields:
            raise ValueError(f"target {target_id} missing fields: {', '.join(missing_fields)}")

        paths = {field: _resolve(raw[field], manifest_path) for field in required}
        missing_artifacts = [field for field, path in paths.items() if not path.exists()]
        scope = _scope_summary(paths["ground_truth"])
        record: dict[str, Any] = {"id": target_id, "scope": scope}
        if missing_artifacts:
            source_ground_truth = json.loads(paths["ground_truth"].read_text(encoding="utf-8"))
            comparison_ground_truth = _comparison_ground_truth(source_ground_truth)
            available_results: dict[str, Any] = {}
            if paths["argus_findings"].is_file():
                available_results["argus"] = _side_score(
                    _load_findings(paths["argus_findings"]), comparison_ground_truth
                )
            if paths["shannon_deliverables"].is_dir():
                available_results["shannon"] = _side_score(
                    normalize_shannon_findings(paths["shannon_deliverables"]), comparison_ground_truth
                )
            record.update(
                {
                    "status": "unavailable",
                    "missing_artifacts": missing_artifacts,
                    "reason": "required run artifacts do not exist; unavailable is not scored as zero",
                    "available_results": available_results,
                }
            )
        else:
            adjudication = (
                _resolve(raw["adjudication"], manifest_path) if isinstance(raw.get("adjudication"), str) else None
            )
            record.update(
                {
                    "status": "complete",
                    "result": compare(
                        paths["shannon_deliverables"],
                        paths["argus_findings"],
                        paths["ground_truth"],
                        adjudication,
                    ),
                }
            )
        results.append(record)
    return {"manifest": str(manifest_path), "targets": results}


def render_markdown(matrix: dict[str, Any]) -> str:
    lines = [
        "# Argus vs Shannon comparison matrix",
        "",
        "| Target | Status | Shannon recall | Argus recall | Detail |",
        "|---|---|---:|---:|---|",
    ]
    for target in matrix["targets"]:
        if target["status"] == "complete":
            result = target["result"]
            shannon = result["shannon"]["detection_score"]["recall"]
            argus = result["argus"]["detection_score"]["recall"]
            excluded = target["scope"]["business_scope_excluded_ids"]
            detail = "scored" + (f"; excluded: {', '.join(excluded)}" if excluded else "")
            lines.append(f"| {target['id']} | complete | {shannon:.3f} | {argus:.3f} | {detail} |")
        else:
            missing = ", ".join(target["missing_artifacts"])
            excluded = target["scope"]["business_scope_excluded_ids"]
            available = target.get("available_results", {})
            shannon = available.get("shannon", {}).get("detection_score", {}).get("recall")
            argus = available.get("argus", {}).get("detection_score", {}).get("recall")
            shannon_cell = f"{shannon:.3f}" if isinstance(shannon, (int, float)) else "N/A"
            argus_cell = f"{argus:.3f}" if isinstance(argus, (int, float)) else "N/A"
            available_names = ", ".join(sorted(available))
            detail = f"missing: {missing}"
            if available_names:
                detail += f"; available: {available_names} only"
            if excluded:
                detail += f"; excluded: {', '.join(excluded)}"
            lines.append(f"| {target['id']} | unavailable | {shannon_cell} | {argus_cell} | {detail} |")
    lines.extend(["", "> Unavailable targets are never converted to zero recall.", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "docs" / "comparisons" / "comparison-matrix.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs" / "comparisons" / "comparison-matrix.json",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=ROOT / "docs" / "comparisons" / "comparison-matrix.md",
    )
    args = parser.parse_args(argv)

    matrix = build_matrix(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(render_markdown(matrix), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
