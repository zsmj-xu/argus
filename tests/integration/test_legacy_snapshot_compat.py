from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from argus import cli
from argus.control.db import Database, control_db_path
from argus.control.repositories import Repositories
from argus.contracts import AnalysisContext, AnalyzerResult, Phase
from argus.domain.enums import ScanStatus, TaskStatus
from argus.domain.errors import SchemaValidationError


class FailOnceAnalyzer:
    name = "fail-once"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def __init__(self) -> None:
        self.should_fail = True

    def run(self, _ctx: AnalysisContext) -> AnalyzerResult:
        if self.should_fail:
            raise RuntimeError("fixture failure")
        return {"analyzer": self.name, "findings": [], "enrichment": {}}


def _fake_codegraph(tmp_path: Path) -> tuple[Path, Path]:
    counter = tmp_path / "codegraph-invocations.txt"
    binary = tmp_path / "codegraph"
    binary.write_text(
        "#!/bin/sh\n"
        f"printf 'init\\n' >> '{counter}'\n"
        'mkdir -p "$2/.codegraph"\n'
        'printf "fake-codegraph-db" > "$2/.codegraph/codegraph.db"\n',
        encoding="utf-8",
    )
    binary.chmod(0o755)
    return binary, counter


def _start(repository: Path, workspace: str, *, codegraph_config: str | None = None) -> int:
    overrides = ["analyzers.enrichment=[]", "analyzers.vuln=[]"]
    if codegraph_config is not None:
        overrides.append(f"codegraph.mode={codegraph_config}")
    return cli.cmd_start(
        argparse.Namespace(
            repo=str(repository),
            workspace=workspace,
            config=None,
            set=overrides,
            yolo=True,
        )
    )


def _start_with_reviews(repository: Path, workspace: str) -> int:
    return cli.cmd_start(
        argparse.Namespace(
            repo=str(repository),
            workspace=workspace,
            config=None,
            set=["analyzers.enrichment=[]", "analyzers.vuln=[]"],
            yolo=False,
        )
    )


def test_legacy_scans_use_snapshots_register_artifacts_and_invalidate_graph_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    source = repository / "app.py"
    source.write_text("print('v1')\n", encoding="utf-8")
    original_bytes = source.read_bytes()
    runs_root = tmp_path / "runs"
    binary, counter = _fake_codegraph(tmp_path)
    monkeypatch.setattr(cli, "RUNS_ROOT", str(runs_root))
    monkeypatch.setattr("argus.graph.build._resolve_binary", lambda: str(binary))

    assert _start(repository, "scan-one") == 0
    assert _start(repository, "scan-two") == 0
    assert counter.read_text(encoding="utf-8").splitlines() == ["init"]
    assert source.read_bytes() == original_bytes
    assert not (repository / ".codegraph").exists()

    source.write_text("print('v2')\n", encoding="utf-8")
    assert _start(repository, "scan-three") == 0
    assert counter.read_text(encoding="utf-8").splitlines() == ["init", "init"]

    assert _start(repository, "scan-four", codegraph_config="different") == 0
    assert counter.read_text(encoding="utf-8").splitlines() == ["init", "init", "init"]

    binary.write_text(binary.read_text(encoding="utf-8") + "# provider changed\n", encoding="utf-8")
    assert _start(repository, "scan-five") == 0
    assert counter.read_text(encoding="utf-8").splitlines() == ["init", "init", "init", "init"]

    assert not (repository / ".codegraph").exists()
    assert source.read_bytes() != original_bytes
    assert source.read_text(encoding="utf-8") == "print('v2')\n"

    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        projects = repositories.projects.list()
        assert len(projects) == 1
        scans = repositories.scans.list(project_id=projects[0].id)
        snapshots = repositories.snapshots.list(project_id=projects[0].id)
        assert len(scans) == 5
        assert len(snapshots) == 5
        assert all(scan.status is ScanStatus.COMPLETED for scan in scans)
        assert snapshots[0].tree_hash == snapshots[1].tree_hash
        assert snapshots[1].tree_hash != snapshots[2].tree_hash
        assert snapshots[2].tree_hash == snapshots[3].tree_hash
        assert snapshots[3].tree_hash == snapshots[4].tree_hash

        for index, (scan, snapshot) in enumerate(zip(scans, snapshots, strict=True)):
            tasks = repositories.tasks.list(scan_id=scan.id)
            artifacts = repositories.artifacts.list(scan_id=scan.id)
            legacy_tasks = [task for task in tasks if task.plan_id is None]
            planned_tasks = [task for task in tasks if task.plan_id == scan.plan_id]
            assert len(legacy_tasks) == 5
            assert len(planned_tasks) == 7
            assert all(task.status is TaskStatus.SUCCEEDED for task in legacy_tasks)
            assert (
                next(task for task in planned_tasks if task.plugin_id == "core.plan-compiler").status
                is TaskStatus.SUCCEEDED
            )
            assert all(
                task.status is TaskStatus.PENDING for task in planned_tasks if task.plugin_id != "core.plan-compiler"
            )
            task_by_plugin = {task.plugin_id: task for task in legacy_tasks}
            assert task_by_plugin["graph.codegraph"].depends_on == [task_by_plugin["source.snapshot"].id]
            assert task_by_plugin["legacy.report.markdown"].depends_on == [
                task_by_plugin["legacy.findings.aggregate"].id
            ]
            assert {artifact.artifact_type for artifact in artifacts} == {
                "source.snapshot.manifest.v1",
                "code.graph.codegraph.v1",
                "legacy.enrichment.aggregate.v1",
                "legacy.findings.aggregate.v1",
                "legacy.report.markdown.v1",
                "task.plan.v1",
            }
            assert all(artifact.snapshot_id == snapshot.id for artifact in artifacts)
            assert Path(snapshot.materialized_path, ".codegraph", "codegraph.db").is_file()
            assert (runs_root / f"scan-{['one', 'two', 'three', 'four', 'five'][index]}" / "report.md").is_file()
    finally:
        database.close()


def test_legacy_review_continue_registers_artifacts_incrementally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('review')\n", encoding="utf-8")
    runs_root = tmp_path / "runs"
    binary, _counter = _fake_codegraph(tmp_path)
    monkeypatch.setattr(cli, "RUNS_ROOT", str(runs_root))
    monkeypatch.setattr("argus.graph.build._resolve_binary", lambda: str(binary))

    assert _start_with_reviews(repository, "reviewed") == 0
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.WAITING_REVIEW
        assert {artifact.artifact_type for artifact in repositories.artifacts.list(scan_id=scan.id)} == {
            "source.snapshot.manifest.v1",
            "code.graph.codegraph.v1",
            "legacy.enrichment.aggregate.v1",
            "task.plan.v1",
        }
    finally:
        database.close()

    continue_args = argparse.Namespace(workspace="reviewed", set=[], focus="app.py")
    assert cli.cmd_continue(continue_args) == 0
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.WAITING_REVIEW
        assert scan.config["focus"] == "app.py"
        task_by_plugin = {
            task.plugin_id: task for task in repositories.tasks.list(scan_id=scan.id) if task.plan_id is None
        }
        assert task_by_plugin["legacy.findings.aggregate"].config_hash == scan.config_hash
        assert task_by_plugin["legacy.report.markdown"].config_hash == scan.config_hash
        assert {artifact.artifact_type for artifact in repositories.artifacts.list(scan_id=scan.id)} == {
            "source.snapshot.manifest.v1",
            "code.graph.codegraph.v1",
            "legacy.enrichment.aggregate.v1",
            "legacy.findings.aggregate.v1",
            "task.plan.v1",
        }
    finally:
        database.close()

    assert cli.cmd_continue(continue_args) == 0
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.COMPLETED
        assert len(repositories.artifacts.list(scan_id=scan.id)) == 6
        assert all(
            task.status is TaskStatus.SUCCEEDED
            for task in repositories.tasks.list(scan_id=scan.id)
            if task.plan_id is None or task.plugin_id == "core.plan-compiler"
        )
    finally:
        database.close()
    assert not (repository / ".codegraph").exists()


def test_review_cannot_change_completed_snapshot_or_graph_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('review')\n", encoding="utf-8")
    runs_root = tmp_path / "runs"
    binary, _counter = _fake_codegraph(tmp_path)
    monkeypatch.setattr(cli, "RUNS_ROOT", str(runs_root))
    monkeypatch.setattr("argus.graph.build._resolve_binary", lambda: str(binary))
    assert _start_with_reviews(repository, "reject-config") == 0

    with pytest.raises(SchemaValidationError, match="cannot change"):
        cli.cmd_continue(
            argparse.Namespace(
                workspace="reject-config",
                set=["codegraph.mode=different"],
                focus=None,
            )
        )

    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.WAITING_REVIEW
        assert "codegraph" not in scan.config
    finally:
        database.close()

    assert cli.cmd_continue(argparse.Namespace(workspace="reject-config", set=[], focus=None)) == 0


def test_interrupted_legacy_scan_registers_completed_artifacts_and_can_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "target"
    repository.mkdir()
    (repository / "app.py").write_text("print('recover')\n", encoding="utf-8")
    runs_root = tmp_path / "runs"
    binary, _counter = _fake_codegraph(tmp_path)
    analyzer = FailOnceAnalyzer()
    monkeypatch.setattr(cli, "RUNS_ROOT", str(runs_root))
    monkeypatch.setattr("argus.graph.build._resolve_binary", lambda: str(binary))
    monkeypatch.setattr(cli, "discover_analyzers", lambda: {analyzer.name: analyzer})

    with pytest.raises(RuntimeError, match="fixture failure"):
        cli.cmd_start(
            argparse.Namespace(
                repo=str(repository),
                workspace="recover",
                config=None,
                set=[
                    "analyzers.enrichment=[]",
                    f"analyzers.vuln=[{analyzer.name}]",
                ],
                yolo=True,
            )
        )

    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.RUNNING
        assert {artifact.artifact_type for artifact in repositories.artifacts.list(scan_id=scan.id)} == {
            "source.snapshot.manifest.v1",
            "code.graph.codegraph.v1",
            "legacy.enrichment.aggregate.v1",
            "task.plan.v1",
        }
        assert any(event.event_type == "scan.legacy_interrupted" for event in repositories.events.list(scan_id=scan.id))
    finally:
        database.close()

    analyzer.should_fail = False
    assert cli.cmd_resume(argparse.Namespace(workspace="recover", set=[], focus=None)) == 0
    database = Database(control_db_path(runs_root))
    repositories = Repositories(database)
    try:
        scan = repositories.scans.list()[0]
        assert scan.status is ScanStatus.COMPLETED
        assert len(repositories.artifacts.list(scan_id=scan.id)) == 6
    finally:
        database.close()
