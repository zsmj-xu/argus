"""Run and resume the Argus graph/baseline evaluation matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, cast

from argus.analyzers.baseline.analyzer import BaselineAnalyzer, NoGraphHandle
from argus.contracts import AnalysisContext, Finding, SourceMode
from argus.eval.score import ScoreResult, score
from argus.graph.build import build_graph
from argus.graph.codegraph import CodegraphHandle
from argus.llm.client import ENV_API_KEY, ENV_BASE_URL, ENV_MODEL, AuditedLLM
from argus.orchestration.pipeline import _FileSourceAccess

ROOT = Path(__file__).resolve().parents[1]
RUNS_ROOT = ROOT / "runs"
RESULTS_PATH = ROOT / "docs" / "EVAL-RESULTS.md"
AVOID_SENTINEL = "__argus_eval_disable_raw_graph_explore__"
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".go", ".h", ".hpp", ".java", ".js", ".jsx", ".py", ".pyw", ".ts", ".tsx"}


@dataclass(frozen=True)
class ScanUnit:
    key: str
    target: str
    scan_root: Path
    ground_truth: Path


@dataclass(frozen=True)
class Arm:
    key: str
    enrichment: tuple[str, ...]
    baseline: bool = False


@dataclass(frozen=True)
class EvaluationResult:
    unit: ScanUnit
    arm: Arm
    workspace: str
    status: str
    score: ScoreResult | None
    error: str = ""


SCAN_UNITS = (
    ScanUnit("vampi", "VAmPI", ROOT / "targets" / "VAmPI", ROOT / "ground_truth" / "vampi.json"),
    ScanUnit(
        "crapi-workshop",
        "crAPI",
        ROOT / "targets" / "crAPI" / "services" / "workshop",
        ROOT / "ground_truth" / "crapi.json",
    ),
    ScanUnit(
        "crapi-community",
        "crAPI",
        ROOT / "targets" / "crAPI" / "services" / "community",
        ROOT / "ground_truth" / "crapi-community.json",
    ),
    ScanUnit("flowmart", "flowmart", ROOT / "targets" / "flowmart", ROOT / "ground_truth" / "flowmart.json"),
)

ARMS = (
    Arm("graph-invariant", ("business-flow", "invariant")),
    Arm("graph-no-invariant", ("business-flow",)),
    Arm("baseline", (), baseline=True),
)


def evaluation_matrix() -> list[tuple[ScanUnit, Arm]]:
    return [(unit, arm) for unit in SCAN_UNITS for arm in ARMS]


def aggregate_scores(scores: list[ScoreResult]) -> ScoreResult:
    tp = sum(item["tp"] for item in scores)
    fp = sum(item["fp"] for item in scores)
    fn = sum(item["fn"] for item in scores)
    matched = [match for item in scores for match in item["matched"]]
    return {
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "matched": matched,
    }


def _workspace(run_id: str, unit: ScanUnit, arm: Arm) -> str:
    return f"eval-{run_id}-{unit.key}-{arm.key}"


def _git_revision() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 and completed.stdout.strip() else "unknown"


def _expected_meta(unit: ScanUnit, arm: Arm, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "revision": _git_revision(),
        "target": unit.target,
        "scan_unit": unit.key,
        "scan_root": str(unit.scan_root),
        "ground_truth_sha256": hashlib.sha256(unit.ground_truth.read_bytes()).hexdigest(),
        "arm": arm.key,
        "enrichment": list(arm.enrichment),
        "source_mode": SourceMode.STRIPPED.value,
        "model": os.environ.get(ENV_MODEL, ""),
        "base_url": os.environ.get(ENV_BASE_URL, ""),
        "avoid": AVOID_SENTINEL,
    }


def _prepare_workspace_meta(workspace: str, expected: dict[str, Any]) -> Path:
    workspace_dir = RUNS_ROOT / workspace
    meta_path = workspace_dir / "eval-meta.json"
    if meta_path.is_file():
        stored = _load_json(meta_path)
        if not isinstance(stored, dict) or any(stored.get(key) != value for key, value in expected.items()):
            raise RuntimeError(f"workspace metadata does not match current experiment: {workspace}")
        return meta_path

    if workspace_dir.exists() and any(workspace_dir.iterdir()):
        raise RuntimeError(f"workspace has artifacts but no eval metadata; refusing unsafe reuse: {workspace}")
    _atomic_json(meta_path, {**expected, "status": "running"})
    return meta_path


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _json_default(value: object) -> Any:
    return value.value if isinstance(value, Enum) else str(value)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=_json_default)
        handle.write("\n")
    os.replace(temporary, path)


def _preflight(*, execute: bool) -> list[str]:
    errors: list[str] = []
    for unit in SCAN_UNITS:
        if not unit.scan_root.is_dir():
            errors.append(f"scan root missing: {unit.scan_root}")
        if not unit.ground_truth.is_file():
            errors.append(f"ground truth missing: {unit.ground_truth}")
        if any(AVOID_SENTINEL in str(path.relative_to(unit.scan_root)) for path in unit.scan_root.rglob("*")):
            errors.append(f"avoid sentinel collides with target path: {unit.scan_root}")
    if execute:
        for variable in (ENV_BASE_URL, ENV_API_KEY, ENV_MODEL):
            if not os.environ.get(variable):
                errors.append(f"{variable} is not set")
        if shutil.which("codegraph") is None and not Path("/opt/homebrew/bin/codegraph").exists():
            errors.append("codegraph CLI is not installed")
    return errors


def _graph_command(unit: ScanUnit, arm: Arm, workspace: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "argus.cli",
        "start",
        "-r",
        str(unit.scan_root),
        "-w",
        workspace,
        "--yolo",
        "--set",
        "source_mode=stripped",
        "--set",
        f"analyzers.enrichment={json.dumps(list(arm.enrichment))}",
        "--set",
        'analyzers.vuln=["business-logic"]',
        "--set",
        f"avoid={AVOID_SENTINEL}",
    ]


def _run_command(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}")


def _run_graph(unit: ScanUnit, arm: Arm, workspace: str) -> list[Finding]:
    workspace_dir = RUNS_ROOT / workspace
    findings_path = workspace_dir / "findings.json"
    report_path = workspace_dir / "report.md"
    state_path = workspace_dir / "state.db"

    if findings_path.is_file() and report_path.is_file():
        return cast(list[Finding], _load_json(findings_path))
    if state_path.is_file():
        _run_command([sys.executable, "-m", "argus.cli", "resume", "-w", workspace])
    else:
        _run_command(_graph_command(unit, arm, workspace))
    if not findings_path.is_file():
        raise RuntimeError(f"graph arm produced no findings artifact: {findings_path}")
    return cast(list[Finding], _load_json(findings_path))


def _baseline_inputs(unit: ScanUnit) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
    db_path = unit.scan_root / ".codegraph" / "codegraph.db"
    if not db_path.is_file():
        build_graph(str(unit.scan_root))
    graph = CodegraphHandle(str(db_path))
    anchors: dict[str, list[dict[str, Any]]] = {}
    for node in graph.query(""):
        file_path = node.get("file_path")
        node_id = node.get("id")
        start_line = node.get("start_line")
        end_line = node.get("end_line")
        kind = str(node.get("kind", "")).lower()
        if (
            isinstance(file_path, str)
            and isinstance(node_id, str)
            and isinstance(start_line, int)
            and not isinstance(start_line, bool)
            and isinstance(end_line, int)
            and not isinstance(end_line, bool)
            and end_line >= start_line > 0
            and Path(file_path).suffix.lower() in SOURCE_EXTENSIONS
        ):
            path = file_path.replace("\\", "/")
            anchors.setdefault(path, []).append(
                {"node_id": node_id, "kind": kind, "start_line": start_line, "end_line": end_line}
            )
    callable_anchors = {
        path: items for path, items in anchors.items() if any(item["kind"] in {"function", "method"} for item in items)
    }
    if not callable_anchors:
        raise RuntimeError(f"codegraph has no callable source anchors: {db_path}")
    return sorted(callable_anchors), callable_anchors


def _run_baseline(unit: ScanUnit, workspace: str) -> list[Finding]:
    workspace_dir = RUNS_ROOT / workspace
    findings_path = workspace_dir / "findings.json"
    if findings_path.is_file():
        return cast(list[Finding], _load_json(findings_path))

    files, anchors = _baseline_inputs(unit)
    llm = AuditedLLM(
        api_key=os.environ[ENV_API_KEY],
        base_url=os.environ[ENV_BASE_URL],
        model=os.environ[ENV_MODEL],
        workspace=workspace,
        runs_root=str(RUNS_ROOT),
    )
    context: AnalysisContext = {
        "graph": NoGraphHandle(),
        "enriched": {},
        "source": _FileSourceAccess(str(unit.scan_root), SourceMode.STRIPPED),
        "config": {"baseline": {"files": files, "anchors": anchors}},
        "llm": llm,
        "workspace": workspace,
    }
    result = BaselineAnalyzer().run(context)
    _atomic_json(findings_path, result["findings"])
    return result["findings"]


def _run_one(unit: ScanUnit, arm: Arm, run_id: str) -> EvaluationResult:
    workspace = _workspace(run_id, unit, arm)
    expected_meta = _expected_meta(unit, arm, run_id)
    try:
        meta_path = _prepare_workspace_meta(workspace, expected_meta)
        findings = _run_baseline(unit, workspace) if arm.baseline else _run_graph(unit, arm, workspace)
        ground_truth = cast(dict[str, Any], _load_json(unit.ground_truth))
        scored = score(findings, ground_truth)
        _atomic_json(RUNS_ROOT / workspace / "score.json", scored)
        _atomic_json(meta_path, {**expected_meta, "status": "complete"})
        return EvaluationResult(unit, arm, workspace, "complete", scored)
    except Exception as exc:  # noqa: BLE001 - batch continues and records each failed unit
        return EvaluationResult(unit, arm, workspace, "failed", None, f"{type(exc).__name__}: {exc}")


def render_results(results: list[EvaluationResult]) -> str:
    lines = [
        "# Argus evaluation results",
        "",
        "Results are generated by `uv run python scripts/run_eval.py`. Failed units are never scored as zero.",
        "",
        "| Target | Scan unit | Arm | TP | FP | FN | Recall | Precision | Workspace | Status |",
        "|---|---|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for result in results:
        item = result.score
        values = (
            (str(item["tp"]), str(item["fp"]), str(item["fn"]), f"{item['recall']:.3f}", f"{item['precision']:.3f}")
            if item is not None
            else ("—", "—", "—", "—", "—")
        )
        status = result.status if not result.error else f"{result.status}: {result.error}"
        lines.append(
            f"| {result.unit.target} | {result.unit.key} | {result.arm.key} | {values[0]} | {values[1]} | "
            f"{values[2]} | {values[3]} | {values[4]} | `{result.workspace}` | {status} |"
        )

    lines.extend(["", "## Aggregated target scores", ""])
    lines.append("| Target | Arm | TP | FP | FN | Recall | Precision |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for target in ("VAmPI", "crAPI", "flowmart"):
        for arm in ARMS:
            scores = [
                result.score
                for result in results
                if result.unit.target == target and result.arm.key == arm.key and result.score is not None
            ]
            expected_units = sum(1 for unit in SCAN_UNITS if unit.target == target)
            if len(scores) != expected_units:
                lines.append(f"| {target} | {arm.key} | — | — | — | — | — |")
                continue
            total = aggregate_scores(scores)
            lines.append(
                f"| {target} | {arm.key} | {total['tp']} | {total['fp']} | {total['fn']} | "
                f"{total['recall']:.3f} | {total['precision']:.3f} |"
            )
    lines.append("")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=_git_revision(), help="Stable id used in resumable workspace names")
    parser.add_argument("--dry-run", action="store_true", help="Print the 12-unit matrix without API calls")
    parser.add_argument("--results", type=Path, default=RESULTS_PATH, help="Markdown output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = _preflight(execute=not args.dry_run)
    if errors:
        for error in errors:
            print(f"[eval] preflight: {error}", file=sys.stderr)
        return 2

    if args.dry_run:
        for unit, arm in evaluation_matrix():
            print(f"{_workspace(args.run_id, unit, arm)}\t{unit.scan_root}\t{arm.key}")
        return 0

    results: list[EvaluationResult] = []
    for unit, arm in evaluation_matrix():
        result = _run_one(unit, arm, args.run_id)
        results.append(result)
        print(f"[eval] {result.workspace}: {result.status}{' - ' + result.error if result.error else ''}")
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(render_results(results), encoding="utf-8")
    return 1 if any(result.status != "complete" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
