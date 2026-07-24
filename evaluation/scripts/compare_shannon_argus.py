"""Compare Shannon vs Argus detection against the same VAmPI ground truth (C7).

主指标按源码锚点衡量已知漏洞是否检出,不把分类标签差异算成漏检。旧的分类
兼容评分保留为诊断项。由于 VAmPI GT 不完整,未匹配 finding 不判为 FP,
也不计算 precision。

公平口径(见设计文档 §2):
- Shannon exploit=false,只到漏洞发现层
- Argus 只用移植自 Shannon 的 5 类分析器
- 两边对同一 GT 打分

用法:
    uv run python evaluation/scripts/compare_shannon_argus.py \
        --shannon-deliverables ../shannon/workspaces/vampi-shannon/deliverables \
        --argus-findings runs/vampi-5class/findings.json \
        --ground-truth evaluation/ground_truth/vampi.json \
        --output docs/comparisons/vampi-comparison.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

# 作为脚本直接运行时,仓库根目录不在 sys.path。显式注入后可导入
# 产品包与 evaluation.scripts 中的兄弟模块。
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus.contracts import Finding  # noqa: E402
from argus.eval.score import DetectionScoreResult, score, score_detection  # noqa: E402
from evaluation.scripts.normalize_shannon import normalize_shannon_findings  # noqa: E402

COMPARISON_CLASSES = ("injection", "xss", "auth", "authz", "ssrf")
_DEFAULT_INVARIANT_CLASS = {
    "ownership": "authz",
    "authentication": "auth",
    "role": "authz",
    "trust_boundary": "authz",
}


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_findings(path: Path) -> list[Finding]:
    data = _load_json(path)
    if not isinstance(data, list):
        raise ValueError(f"findings file must be a JSON array: {path}")
    return cast(list[Finding], data)


def _comparison_ground_truth(ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Project cross-tool scope onto the shared evaluation ground truth.

    ``in_scope`` remains reserved for the business-invariant evaluation. The
    optional comparison fields admit known vulnerabilities handled by the five
    Shannon-compatible analyzers without changing that existing contract.
    """
    raw_vulns = ground_truth.get("vulnerabilities", ground_truth.get("vulns", []))
    if not isinstance(raw_vulns, list):
        raise ValueError("ground truth vulnerabilities must be a list")

    comparison_vulns: list[dict[str, Any]] = []
    for raw in raw_vulns:
        if not isinstance(raw, dict):
            raise ValueError("ground truth vulnerability must be an object")
        item = dict(raw)
        item["in_scope"] = raw.get("comparison_in_scope", raw.get("in_scope", True))
        if isinstance(raw.get("comparison_vuln_class"), str):
            item["vuln_class"] = raw["comparison_vuln_class"]
        elif isinstance(raw.get("invariant_kind"), str) and raw["invariant_kind"] in _DEFAULT_INVARIANT_CLASS:
            item["vuln_class"] = _DEFAULT_INVARIANT_CLASS[raw["invariant_kind"]]
        if isinstance(raw.get("comparison_location"), dict):
            item["location"] = raw["comparison_location"]
        comparison_vulns.append(item)

    return {"vulnerabilities": comparison_vulns}


def _matched_details(
    findings: list[Finding], ground_truth: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """返回 (matched, missed GT ids, 未被不完整 GT 裁决的 findings)。"""
    result = score_detection(findings, ground_truth)
    matched_gt_ids = {m["ground_truth_id"] for m in result["matched"]}
    gt_vulns = ground_truth.get("vulnerabilities", ground_truth.get("vulns", []))
    in_scope = [v for v in gt_vulns if v.get("in_scope", True)]
    fn_ids = [v["id"] for v in in_scope if v["id"] not in matched_gt_ids]
    matched_indices = {m["finding_index"] for m in result["matched"]}
    unadjudicated = [
        {"id": f.get("id"), "vuln_class": f.get("vuln_class"), "title": f.get("title", "")[:80]}
        for i, f in enumerate(findings)
        if i not in matched_indices
    ]
    matched_details: list[dict[str, Any]] = [
        {
            "gt_id": m["ground_truth_id"],
            "finding_id": m["finding_id"],
            "finding": next((f for i, f in enumerate(findings) if i == m["finding_index"]), {}),
        }
        for m in result["matched"]
    ]
    return matched_details, fn_ids, unadjudicated


def _per_class_detection(
    detection_score: DetectionScoreResult, ground_truth: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    matched_ids = {item["ground_truth_id"] for item in detection_score["matched"]}
    expected_by_class: dict[str, list[str]] = {vuln_class: [] for vuln_class in COMPARISON_CLASSES}
    for item in ground_truth["vulnerabilities"]:
        if not item.get("in_scope", True):
            continue
        vuln_class = item.get("vuln_class")
        if vuln_class in expected_by_class:
            expected_by_class[vuln_class].append(item["id"])

    result: dict[str, dict[str, Any]] = {}
    for vuln_class, expected_ids in expected_by_class.items():
        hits = len(set(expected_ids) & matched_ids)
        total = len(expected_ids)
        result[vuln_class] = {
            "expected": total,
            "detected": hits,
            "missed": total - hits,
            "recall": hits / total if total else None,
        }
    return result


def _adjudication_summary(findings: list[Finding], tool: str, adjudication_path: Path | None) -> dict[str, Any] | None:
    if adjudication_path is None or not adjudication_path.is_file():
        return None
    payload = _load_json(adjudication_path)
    entries = payload.get(tool, {}) if isinstance(payload, dict) else {}
    if not isinstance(entries, dict):
        raise ValueError(f"adjudication entries for {tool} must be an object")

    counts = {"true": 0, "duplicate": 0, "false": 0}
    unknown: list[str] = []
    for finding in findings:
        finding_id = finding.get("id")
        decision = entries.get(finding_id)
        if not isinstance(decision, list) or len(decision) != 2 or decision[0] not in counts:
            unknown.append(str(finding_id))
            continue
        counts[decision[0]] += 1

    adjudicated = sum(counts.values())
    valid = counts["true"] + counts["duplicate"]
    unique = counts["true"] + counts["false"]
    return {
        "counts": counts,
        "total_findings": len(findings),
        "adjudicated": adjudicated,
        "unadjudicated": unknown,
        "validity_precision": valid / adjudicated if adjudicated else None,
        "deduplicated_precision": counts["true"] / unique if unique else None,
        "duplicate_rate": counts["duplicate"] / adjudicated if adjudicated else None,
    }


def compare(
    shannon_deliverables: Path,
    argus_findings_path: Path,
    ground_truth_path: Path,
    adjudication_path: Path | None = None,
) -> dict[str, Any]:
    """给两边打分并组装对照结果。"""
    source_ground_truth = cast(dict[str, Any], _load_json(ground_truth_path))
    ground_truth = _comparison_ground_truth(source_ground_truth)
    shannon_findings = normalize_shannon_findings(shannon_deliverables)
    argus_findings = _load_findings(argus_findings_path)

    shannon_detection = score_detection(shannon_findings, ground_truth)
    argus_detection = score_detection(argus_findings, ground_truth)
    shannon_legacy = score(shannon_findings, ground_truth)
    argus_legacy = score(argus_findings, ground_truth)
    shannon_class_diagnostic = {key: shannon_legacy[key] for key in ("recall", "tp", "fn", "matched")}
    argus_class_diagnostic = {key: argus_legacy[key] for key in ("recall", "tp", "fn", "matched")}
    shannon_per_class = _per_class_detection(shannon_detection, ground_truth)
    argus_per_class = _per_class_detection(argus_detection, ground_truth)

    shannon_matched, shannon_fn, shannon_fp = _matched_details(shannon_findings, ground_truth)
    argus_matched, argus_fn, argus_fp = _matched_details(argus_findings, ground_truth)

    # 交集:两边都命中的 GT id
    shannon_hit = {m["gt_id"] for m in shannon_matched}
    argus_hit = {m["gt_id"] for m in argus_matched}
    both_hit = sorted(shannon_hit & argus_hit)
    only_shannon = sorted(shannon_hit - argus_hit)
    only_argus = sorted(argus_hit - shannon_hit)

    return {
        "ground_truth_path": str(ground_truth_path.relative_to(ROOT))
        if ground_truth_path.is_relative_to(ROOT)
        else str(ground_truth_path),
        "shannon": {
            "findings_count": len(shannon_findings),
            "detection_score": shannon_detection,
            "per_class_detection": shannon_per_class,
            "taxonomy_agreement": shannon_class_diagnostic,
            "adjudication": _adjudication_summary(shannon_findings, "shannon", adjudication_path),
            "matched": shannon_matched,
            "missed_ground_truth": shannon_fn,
            "unadjudicated_findings": shannon_fp,
        },
        "argus": {
            "findings_count": len(argus_findings),
            "detection_score": argus_detection,
            "per_class_detection": argus_per_class,
            "taxonomy_agreement": argus_class_diagnostic,
            "adjudication": _adjudication_summary(argus_findings, "argus", adjudication_path),
            "matched": argus_matched,
            "missed_ground_truth": argus_fn,
            "unadjudicated_findings": argus_fp,
        },
        "overlap": {
            "both_hit": both_hit,
            "only_shannon": only_shannon,
            "only_argus": only_argus,
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    """把对照结果渲染成 Markdown 表格段落(供 C8 文档嵌入)。"""
    s = result["shannon"]["detection_score"]
    a = result["argus"]["detection_score"]
    lines = [
        "## 漏洞检出对照(同一 ground truth,分类与检出分离)",
        "",
        "| 工具 | findings 数 | 已检出 GT | 未检出 GT | Detection Recall |",
        "|---|---:|---:|---:|---:|",
        f"| Shannon | {result['shannon']['findings_count']} | {s['tp']} | {s['fn']} | {s['recall']:.3f} |",
        f"| Argus | {result['argus']['findings_count']} | {a['tp']} | {a['fn']} | {a['recall']:.3f} |",
        "",
        "> GT 不完整,未匹配 finding 不能判定为 FP,因此不报告 Precision。",
        "",
        "### 分类别正样本召回",
        "",
        "| 类别 | Shannon | Argus |",
        "|---|---:|---:|",
    ]
    for vuln_class in COMPARISON_CLASSES:
        shannon_class = result["shannon"]["per_class_detection"][vuln_class]
        argus_class = result["argus"]["per_class_detection"][vuln_class]
        shannon_value = (
            f"{shannon_class['detected']}/{shannon_class['expected']} ({shannon_class['recall']:.3f})"
            if shannon_class["recall"] is not None
            else "N/A (无正样本)"
        )
        argus_value = (
            f"{argus_class['detected']}/{argus_class['expected']} ({argus_class['recall']:.3f})"
            if argus_class["recall"] is not None
            else "N/A (无正样本)"
        )
        lines.append(f"| {vuln_class} | {shannon_value} | {argus_value} |")
    lines.extend(
        [
            "",
            "### GT 命中交集",
            "",
            f"- 两边都命中: {', '.join(result['overlap']['both_hit']) or '无'}",
            f"- 仅 Shannon: {', '.join(result['overlap']['only_shannon']) or '无'}",
            f"- 仅 Argus: {', '.join(result['overlap']['only_argus']) or '无'}",
            "",
        ]
    )
    if result["shannon"].get("adjudication") and result["argus"].get("adjudication"):
        lines.extend(
            [
                "",
                "### 人工裁决质量(非 GT 召回)",
                "",
                "| 工具 | true | duplicate | false | Validity precision | Duplicate rate |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for tool in ("shannon", "argus"):
            adjudication = result[tool]["adjudication"]
            counts = adjudication["counts"]
            lines.append(
                f"| {tool.title()} | {counts['true']} | {counts['duplicate']} | {counts['false']} | "
                f"{adjudication['validity_precision']:.3f} | {adjudication['duplicate_rate']:.3f} |"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shannon-deliverables", type=Path, required=True, help="Shannon .shannon/deliverables 目录")
    parser.add_argument("--argus-findings", type=Path, required=True, help="Argus findings.json 路径")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=ROOT / "evaluation" / "ground_truth" / "vampi.json",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "comparisons" / "vampi-comparison.json")
    parser.add_argument("--markdown", type=Path, default=None, help="可选:同时写出 Markdown 段落")
    parser.add_argument(
        "--adjudication",
        type=Path,
        default=None,
        help="可选:逐条人工裁决 JSON;VAmPI GT 默认自动使用 vampi-adjudication.json",
    )
    args = parser.parse_args(argv)

    adjudication = args.adjudication
    if adjudication is None and args.ground_truth.stem == "vampi":
        adjudication = ROOT / "docs" / "comparisons" / "vampi-adjudication.json"
    result = compare(args.shannon_deliverables, args.argus_findings, args.ground_truth, adjudication)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[compare] 对照结果写出: {args.output}")

    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(result), encoding="utf-8")
        print(f"[compare] Markdown 段落写出: {args.markdown}")

    s = result["shannon"]["detection_score"]
    a = result["argus"]["detection_score"]
    print(f"[compare] Shannon: detection_recall={s['recall']:.3f} (TP={s['tp']} FN={s['fn']})")
    print(f"[compare] Argus:   detection_recall={a['recall']:.3f} (TP={a['tp']} FN={a['fn']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
