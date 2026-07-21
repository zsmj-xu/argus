"""Score Shannon vs Argus findings against the same VAmPI ground truth (C7).

阶段 C 对照打分(C7):用同一个 ``argus/eval/score.py`` + 同一份 ``vampi.json``
给 Shannon 与 Argus 两边打分,产出对照表。唯一变量是"哪个工具检出的"。

公平口径(见设计文档 §2):
- Shannon exploit=false,只到漏洞发现层
- Argus 只用移植自 Shannon 的 5 类分析器
- 两边对同一 GT 打分

用法:
    uv run python scripts/compare_shannon_argus.py \
        --shannon-deliverables targets/VAmPI/.shannon/deliverables \
        --argus-findings runs/vampi-5class/findings.json \
        --ground-truth ground_truth/vampi.json \
        --output docs/comparisons/vampi-comparison.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

# 作为脚本直接运行时(uv run python scripts/xxx.py),根目录不在 sys.path,
# 无法 import sibling scripts 模块。显式注入,与 `python -m scripts.xxx` 等效。
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus.contracts import Finding  # noqa: E402
from argus.eval.score import score  # noqa: E402
from scripts.normalize_shannon import normalize_shannon_findings  # noqa: E402


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_findings(path: Path) -> list[Finding]:
    data = _load_json(path)
    if not isinstance(data, list):
        raise ValueError(f"findings file must be a JSON array: {path}")
    return cast(list[Finding], data)


def _matched_details(
    findings: list[Finding], ground_truth: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """返回 (matched 列表, FN 的 gt_id 列表, FP 的 finding 摘要列表)。"""
    result = score(findings, ground_truth)
    matched_gt_ids = {m["ground_truth_id"] for m in result["matched"]}
    gt_vulns = ground_truth.get("vulnerabilities", ground_truth.get("vulns", []))
    in_scope = [v for v in gt_vulns if v.get("in_scope", True)]
    fn_ids = [v["id"] for v in in_scope if v["id"] not in matched_gt_ids]
    matched_indices = {m["finding_index"] for m in result["matched"]}
    fp_summaries = [
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
    return matched_details, fn_ids, fp_summaries


def compare(
    shannon_deliverables: Path,
    argus_findings_path: Path,
    ground_truth_path: Path,
) -> dict[str, Any]:
    """给两边打分并组装对照结果。"""
    ground_truth = cast(dict[str, Any], _load_json(ground_truth_path))
    shannon_findings = normalize_shannon_findings(shannon_deliverables)
    argus_findings = _load_findings(argus_findings_path)

    shannon_score = score(shannon_findings, ground_truth)
    argus_score = score(argus_findings, ground_truth)

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
            "score": shannon_score,
            "matched": shannon_matched,
            "false_negatives": shannon_fn,
            "false_positives": shannon_fp,
        },
        "argus": {
            "findings_count": len(argus_findings),
            "score": argus_score,
            "matched": argus_matched,
            "false_negatives": argus_fn,
            "false_positives": argus_fp,
        },
        "overlap": {
            "both_hit": both_hit,
            "only_shannon": only_shannon,
            "only_argus": only_argus,
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    """把对照结果渲染成 Markdown 表格段落(供 C8 文档嵌入)。"""
    s = result["shannon"]["score"]
    a = result["argus"]["score"]
    lines = [
        "## 打分对照(同一 vampi.json + 同一 score.py)",
        "",
        "| 工具 | findings 数 | TP | FP | FN | Recall | Precision |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| Shannon | {result['shannon']['findings_count']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['recall']:.3f} | {s['precision']:.3f} |",
        f"| Argus | {result['argus']['findings_count']} | {a['tp']} | {a['fp']} | {a['fn']} | {a['recall']:.3f} | {a['precision']:.3f} |",
        "",
        "### GT 命中交集",
        "",
        f"- 两边都命中: {', '.join(result['overlap']['both_hit']) or '无'}",
        f"- 仅 Shannon: {', '.join(result['overlap']['only_shannon']) or '无'}",
        f"- 仅 Argus: {', '.join(result['overlap']['only_argus']) or '无'}",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shannon-deliverables", type=Path, required=True, help="Shannon .shannon/deliverables 目录")
    parser.add_argument("--argus-findings", type=Path, required=True, help="Argus findings.json 路径")
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "ground_truth" / "vampi.json")
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "comparisons" / "vampi-comparison.json")
    parser.add_argument("--markdown", type=Path, default=None, help="可选:同时写出 Markdown 段落")
    args = parser.parse_args(argv)

    result = compare(args.shannon_deliverables, args.argus_findings, args.ground_truth)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[compare] 对照结果写出: {args.output}")

    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(result), encoding="utf-8")
        print(f"[compare] Markdown 段落写出: {args.markdown}")

    s = result["shannon"]["score"]
    a = result["argus"]["score"]
    print(
        f"[compare] Shannon: recall={s['recall']:.3f} precision={s['precision']:.3f} (TP={s['tp']} FP={s['fp']} FN={s['fn']})"
    )
    print(
        f"[compare] Argus:   recall={a['recall']:.3f} precision={a['precision']:.3f} (TP={a['tp']} FP={a['fp']} FN={a['fn']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
