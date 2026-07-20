"""Deterministic T18 runner structure without external LLM or codegraph calls."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.eval.score import ScoreResult
from scripts import run_eval
from scripts.run_eval import (
    ARMS,
    SCAN_UNITS,
    Arm,
    EvaluationResult,
    ScanUnit,
    _prepare_workspace_meta,
    aggregate_scores,
    evaluation_matrix,
    main,
    render_results,
)


def _score(tp: int, fp: int, fn: int) -> ScoreResult:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "matched": [],
    }


def test_matrix_has_four_scan_units_and_three_meaningful_arms() -> None:
    matrix = evaluation_matrix()
    assert len(SCAN_UNITS) == 4
    assert [arm.key for arm in ARMS] == ["graph-invariant", "graph-no-invariant", "baseline"]
    assert len(matrix) == 12
    assert len(set((unit.key, arm.key) for unit, arm in matrix)) == 12


def test_aggregate_sums_counts_before_calculating_ratios() -> None:
    result = aggregate_scores([_score(1, 0, 9), _score(9, 9, 1)])
    assert result["tp"] == 10
    assert result["fp"] == 9
    assert result["fn"] == 10
    assert result["recall"] == 0.5
    assert result["precision"] == 10 / 19


def test_render_does_not_turn_failed_units_into_zero_scores() -> None:
    arm = Arm("baseline", (), baseline=True)
    complete = EvaluationResult(SCAN_UNITS[0], arm, "ws-ok", "complete", _score(1, 0, 0))
    failed = EvaluationResult(SCAN_UNITS[1], arm, "ws-fail", "failed", None, "network unavailable")

    rendered = render_results([complete, failed])

    assert "| VAmPI | vampi | baseline | 1 | 0 | 0 | 1.000 | 1.000 |" in rendered
    assert "| crAPI | crapi-workshop | baseline | — | — | — | — | — |" in rendered
    assert "failed: network unavailable" in rendered


def test_dry_run_needs_no_api_key_and_prints_all_workspaces(monkeypatch, capsys) -> None:
    monkeypatch.delenv("ARGUS_LLM_API_KEY", raising=False)

    assert main(["--dry-run", "--run-id", "test"]) == 0

    output = capsys.readouterr().out
    assert output.count("eval-test-") == 12
    assert "eval-test-vampi-graph-invariant" in output
    assert "eval-test-flowmart-baseline" in output


def test_execute_preflight_requires_all_chat_completion_settings(monkeypatch) -> None:
    for variable in ("ARGUS_LLM_BASE_URL", "ARGUS_LLM_API_KEY", "ARGUS_LLM_MODEL"):
        monkeypatch.delenv(variable, raising=False)

    errors = run_eval._preflight(execute=True)

    assert "ARGUS_LLM_BASE_URL is not set" in errors
    assert "ARGUS_LLM_API_KEY is not set" in errors
    assert "ARGUS_LLM_MODEL is not set" in errors


def test_main_loads_dotenv_before_running(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / ".env").write_text(
        "ARGUS_LLM_BASE_URL=https://dotenv.example.test\nARGUS_LLM_API_KEY=dotenv-key\nARGUS_LLM_MODEL=dotenv-model\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://environment.example.test")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "environment-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "environment-model")

    assert main(["--dry-run", "--run-id", "dotenv"]) == 0

    capsys.readouterr()
    assert run_eval.os.environ["ARGUS_LLM_MODEL"] == "dotenv-model"


def test_workspace_metadata_prevents_stale_artifact_reuse(tmp_path: Path, monkeypatch) -> None:
    ground_truth = tmp_path / "gt.json"
    ground_truth.write_text('{"vulnerabilities": []}', encoding="utf-8")
    unit = ScanUnit("unit", "Target", tmp_path, ground_truth)
    arm = Arm("baseline", (), baseline=True)
    monkeypatch.setattr(run_eval, "RUNS_ROOT", tmp_path / "runs")
    expected = run_eval._expected_meta(unit, arm, "run")

    meta_path = _prepare_workspace_meta("workspace", expected)
    assert meta_path.is_file()

    with pytest.raises(RuntimeError, match="metadata does not match"):
        _prepare_workspace_meta("workspace", {**expected, "revision": "different"})
