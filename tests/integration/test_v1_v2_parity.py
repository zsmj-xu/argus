from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

import pytest

from argus import cli
from argus.control.db import Database, control_db_path
from argus.control.repositories import Repositories
from argus.control.services import ControlServices
from argus.contracts import (
    AnalysisContext,
    AnalyzerResult,
    Confidence,
    Finding,
    Phase,
    Severity,
)
from argus.domain.enums import ReviewStatus, ScanEngine, ScanStatus

RUN_ORDER: list[str] = []


class FixtureEnricher:
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    def __init__(self, name: str, winner: str) -> None:
        self.name = name
        self.winner = winner

    def run(self, _ctx: AnalysisContext) -> AnalyzerResult:
        RUN_ORDER.append(self.name)
        return {
            "analyzer": self.name,
            "findings": [],
            "enrichment": {"winner": self.winner, self.name: True},
        }


class FixtureDetector:
    name = "fixture-detector"
    phase = Phase.VULN_ANALYSIS
    requires = ["enriched-graph"]

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        RUN_ORDER.append(self.name)
        finding: Finding = {
            "id": "fixture:authorization:001",
            "analyzer": self.name,
            "vuln_class": "authorization",
            "title": "Fixture authorization finding",
            "severity": Severity.HIGH,
            "confidence": Confidence.HIGH,
            "locations": [
                {
                    "file": "app.py",
                    "line": 1,
                    "node_id": "file:app.py",
                }
            ],
            "data_flow": "request -> fixture",
            "rationale": f"winner={ctx['enriched']['winner']}",
            "evidence": "fixture evidence",
            "remediation": "fixture remediation",
        }
        return {
            "analyzer": self.name,
            "findings": [finding],
            "enrichment": {},
        }


class FixtureFailingDetector:
    name = "fixture-failure"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def run(self, _ctx: AnalysisContext) -> AnalyzerResult:
        RUN_ORDER.append(self.name)
        raise RuntimeError("fixture failure")


def _analyzers() -> dict[str, Any]:
    instances: list[FixtureEnricher | FixtureDetector] = [
        FixtureEnricher("zeta-flow", "zeta"),
        FixtureEnricher("alpha-flow", "alpha"),
        FixtureDetector(),
    ]
    return {item.name: item for item in instances}


def _build_fixture_graph(repository_path: str) -> str:
    path = Path(repository_path) / ".codegraph" / "codegraph.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()
    return str(path)


def _args(repository: Path, workspace: str, *, engine: str | None = None, yolo: bool) -> argparse.Namespace:
    values: dict[str, Any] = {
        "repo": str(repository),
        "workspace": workspace,
        "config": None,
        "set": [
            'analyzers.enrichment=["zeta-flow","alpha-flow"]',
            'analyzers.vuln=["fixture-detector"]',
        ],
        "yolo": yolo,
    }
    if engine is not None:
        values["engine"] = engine
    return argparse.Namespace(**values)


def _normalize_report(report: str) -> list[str]:
    return [
        re.sub(r"_data/snapshots/[^/]+/", "_data/snapshots/<snapshot>/", line)
        for line in report.splitlines()
        if not line.startswith(("# Argus 安全报告", "- **仓库：**", "- **工作区：**"))
    ]


def _patch_runtime(
    monkeypatch: pytest.MonkeyPatch,
    analyzers: dict[str, Any],
) -> None:
    def run_fixture_in_process(
        _runner: object,
        registered: Any,
        context: Any,
        inputs: Any,
    ) -> Any:
        """Keep this semantic parity fixture observable in the parent process.

        M10 process isolation is exercised separately by the executor security
        test; monkeypatches and RUN_ORDER intentionally cannot cross that boundary.
        """
        module_name, object_name = registered.spec.entrypoint.split(":", maxsplit=1)
        runtime = getattr(importlib.import_module(module_name), object_name)
        return runtime(context, inputs)

    monkeypatch.setattr(cli, "discover_analyzers", lambda: analyzers)
    monkeypatch.setattr("argus.execution.local.discover_analyzers", lambda: analyzers)
    monkeypatch.setattr("argus.plugins.legacy_runtime.discover_analyzers", lambda: analyzers)
    monkeypatch.setattr("argus.orchestration.pipeline.build_graph", _build_fixture_graph)
    monkeypatch.setattr("argus.plugins.legacy_runtime.build_graph", _build_fixture_graph)
    monkeypatch.setattr(
        "argus.plugins.process_runtime.ProcessPluginRunner.run",
        run_fixture_in_process,
    )
    monkeypatch.setattr(
        "argus.snapshots.compat.codegraph_provider_version",
        lambda: "sha256:" + "a" * 64,
    )
    monkeypatch.setattr(
        "argus.execution.scan.codegraph_provider_version",
        lambda: "sha256:" + "a" * 64,
    )


def test_v1_v2_business_outputs_and_analyzer_order_are_equivalent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    analyzers = _analyzers()
    _patch_runtime(monkeypatch, analyzers)

    legacy_root = tmp_path / "legacy-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(legacy_root))
    RUN_ORDER.clear()
    assert cli.cmd_start(_args(repository, "parity", yolo=True)) == 0
    legacy_order = list(RUN_ORDER)
    legacy_enrichment = json.loads((legacy_root / "parity" / "enriched-graph.json").read_text())
    legacy_findings = json.loads((legacy_root / "parity" / "findings.json").read_text())
    legacy_report = (legacy_root / "parity" / "report.md").read_text()

    v2_root = tmp_path / "v2-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(v2_root))
    RUN_ORDER.clear()
    assert cli.cmd_scan(_args(repository, "parity", engine="v2", yolo=True)) == 0
    v2_order = list(RUN_ORDER)
    v2_enrichment = json.loads((v2_root / "parity" / "enriched-graph.json").read_text())
    v2_findings = json.loads((v2_root / "parity" / "findings.json").read_text())
    v2_report = (v2_root / "parity" / "report.md").read_text()

    assert (
        legacy_order
        == v2_order
        == [
            "zeta-flow",
            "alpha-flow",
            "fixture-detector",
        ]
    )
    assert legacy_enrichment == v2_enrichment
    assert legacy_findings == v2_findings
    assert _normalize_report(legacy_report) == _normalize_report(v2_report)

    database = Database(control_db_path(v2_root))
    try:
        scan = Repositories(database).scans.list()[0]
        assert scan.engine is ScanEngine.V2
        assert scan.status is ScanStatus.COMPLETED
    finally:
        database.close()


def test_v2_review_pause_and_resume_are_persistent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    analyzers = _analyzers()
    _patch_runtime(monkeypatch, analyzers)

    legacy_root = tmp_path / "legacy-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(legacy_root))
    RUN_ORDER.clear()
    assert cli.cmd_start(_args(repository, "reviewed", yolo=False)) == 0
    assert RUN_ORDER == ["zeta-flow", "alpha-flow"]
    legacy_continue = argparse.Namespace(
        workspace="reviewed",
        set=[],
        focus=None,
    )
    assert cli.cmd_continue(legacy_continue) == 0
    assert RUN_ORDER[-1] == "fixture-detector"
    assert cli.cmd_continue(legacy_continue) == 0
    legacy_findings = json.loads((legacy_root / "reviewed" / "findings.json").read_text())

    runs_root = tmp_path / "v2-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(runs_root))
    RUN_ORDER.clear()

    assert cli.cmd_scan(_args(repository, "reviewed", engine="v2", yolo=False)) == 0
    assert RUN_ORDER == ["zeta-flow", "alpha-flow"]
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.WAITING_REVIEW
        first = [item for item in repositories.reviews.list(scan_id=scan.id) if item.status is ReviewStatus.OPEN][0]
        ControlServices(repositories).reviews.decide(
            first.id,
            ReviewStatus.APPROVED,
            reviewer="fixture-reviewer",
            reason="enrichment accepted",
        )
        scan_id = scan.id
    finally:
        database.close()

    assert cli.cmd_scan_resume(argparse.Namespace(scan_id=str(scan_id))) == 0
    assert RUN_ORDER[-1] == "fixture-detector"
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.get(scan_id)
        assert scan.status is ScanStatus.WAITING_REVIEW
        second = [item for item in repositories.reviews.list(scan_id=scan.id) if item.status is ReviewStatus.OPEN][0]
        ControlServices(repositories).reviews.decide(
            second.id,
            ReviewStatus.APPROVED,
            reviewer="fixture-reviewer",
            reason="findings accepted",
        )
    finally:
        database.close()

    assert cli.cmd_scan_resume(argparse.Namespace(scan_id=str(scan_id))) == 0
    database = Database(control_db_path(runs_root))
    try:
        assert Repositories(database).scans.get(scan_id).status is ScanStatus.COMPLETED
    finally:
        database.close()
    assert legacy_findings == json.loads((runs_root / "reviewed" / "findings.json").read_text())


def test_v1_v2_failure_propagation_is_equivalent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    failing = FixtureFailingDetector()
    analyzers: dict[str, Any] = {failing.name: failing}
    _patch_runtime(monkeypatch, analyzers)
    arguments = argparse.Namespace(
        repo=str(repository),
        workspace="failure",
        config=None,
        set=[
            "analyzers.enrichment=[]",
            'analyzers.vuln=["fixture-failure"]',
        ],
        yolo=True,
    )

    legacy_root = tmp_path / "legacy-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(legacy_root))
    RUN_ORDER.clear()
    with pytest.raises(RuntimeError, match="fixture failure"):
        cli.cmd_start(arguments)
    legacy_order = list(RUN_ORDER)

    v2_root = tmp_path / "v2-runs"
    monkeypatch.setattr(cli, "RUNS_ROOT", str(v2_root))
    RUN_ORDER.clear()
    v2_arguments = argparse.Namespace(**vars(arguments), engine="v2")
    assert cli.cmd_scan(v2_arguments) == 1
    assert legacy_order == RUN_ORDER == ["fixture-failure"]
    database = Database(control_db_path(v2_root))
    try:
        scan = Repositories(database).scans.list()[0]
        assert scan.status is ScanStatus.FAILED
        assert scan.error_code == "TASK_FAILED"
    finally:
        database.close()
