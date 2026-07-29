from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from argus.web import (
    APIError,
    ArgusConsoleHandler,
    ConsoleService,
    Job,
    build_project_scan_command,
    build_start_command,
)
from argus.orchestration.checkpoints import REVIEW_ENRICHMENT, make_checkpointer
from argus.orchestration.pipeline import build_pipeline
from argus.orchestration.state import make_initial_state


class FakeLauncher:
    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}

    def launch(self, workspace: str, action: str, command: list[str]) -> Job:
        job = Job(
            workspace=workspace,
            action=action,
            command=command,
            started_at=1.0,
            log_path=f"runs/{workspace}/web-console.log",
            pid=123,
        )
        self.jobs[workspace] = job
        return job

    def get(self, workspace: str) -> Job | None:
        return self.jobs.get(workspace)


def _service(tmp_path: Path, launcher: FakeLauncher | None = None) -> ConsoleService:
    return ConsoleService(
        project_root=tmp_path,
        runs_root=tmp_path / "runs",
        launcher=launcher or FakeLauncher(),
    )


def test_build_start_command_requires_disclosure_acknowledgement(tmp_path: Path) -> None:
    with pytest.raises(APIError, match="披露"):
        build_start_command(
            {
                "repo": str(tmp_path),
                "workspace": "scan-001",
                "source_mode": "stripped",
                "analyzers": ["authz"],
            },
            {"authz"},
        )


def test_security_graph_api_routes_are_scan_scoped_and_bounded() -> None:
    scan_id = UUID("12345678-1234-5678-1234-567812345678")

    assert ArgusConsoleHandler._scan_graph_route(f"/api/scans/{scan_id}/graph/nodes") == (scan_id, "nodes", None)
    assert ArgusConsoleHandler._scan_graph_route(f"/api/scans/{scan_id}/graph/nodes/sir%3Aroute%3Aabc") == (
        scan_id,
        "nodes",
        "sir:route:abc",
    )
    assert ArgusConsoleHandler._scan_graph_route(f"/api/scans/{scan_id}/graph/slice") == (scan_id, "slice", None)
    with pytest.raises(APIError, match="UUID"):
        ArgusConsoleHandler._scan_graph_route("/api/scans/not-a-uuid/graph/nodes")
    with pytest.raises(APIError, match="整数"):
        ArgusConsoleHandler._query_int(
            {"max_nodes": ["unbounded"]},
            "max_nodes",
        )


def test_build_start_command_uses_argv_not_shell(tmp_path: Path) -> None:
    workspace, command = build_start_command(
        {
            "repo": str(tmp_path),
            "workspace": "scan-001",
            "source_mode": "stripped",
            "analyzers": ["authz", "xss"],
            "enrichment_analyzers": ["invariant"],
            "checkpoints": False,
            "disclosure_acknowledged": True,
        },
        {"authz", "xss", "invariant"},
    )

    assert workspace == "scan-001"
    assert command[:4] == [sys.executable, "-m", "argus.cli", "start"]
    assert "--yolo" in command
    assert 'analyzers.vuln=["authz", "xss"]' in command


def test_build_start_command_adds_safe_advanced_llm_settings(tmp_path: Path) -> None:
    _, command = build_start_command(
        {
            "repo": str(tmp_path),
            "workspace": "scan-advanced",
            "source_mode": "stripped",
            "analyzers": ["authz"],
            "enrichment_analyzers": ["business-flow", "invariant"],
            "output_token_limit": "65536",
            "business_flow_batch_size": 8,
            "disclosure_acknowledged": True,
        },
        {"authz", "business-flow", "invariant"},
    )

    assert "business-flow.batch_size=8" in command
    assert "business-flow.max_tokens=65536" in command
    assert "invariant.max_tokens=65536" in command
    assert "authz.max_tokens=65536" in command


def test_project_scan_command_uses_v2_and_persisted_defaults(
    tmp_path: Path,
) -> None:
    workspace, command = build_project_scan_command(
        {
            "repository_path": str(tmp_path),
            "default_config": {"strict_outputs": True},
        },
        {
            "workspace": "v2-control-scan",
            "source_mode": "stripped",
            "analysis_mode": "compare",
            "analyzers": ["authz"],
            "enrichment_analyzers": ["business-flow"],
            "disclosure_acknowledged": True,
        },
        {"authz", "business-flow"},
    )

    assert workspace == "v2-control-scan"
    assert command[:4] == [sys.executable, "-m", "argus.cli", "scan"]
    assert command[command.index("--engine") + 1] == "v2"
    assert "strict_outputs=true" in command
    assert "analysisMode=compare" in command


@pytest.mark.parametrize("output_token_limit", [4096, 393217, "many"])
def test_build_start_command_rejects_unsafe_output_limit(tmp_path: Path, output_token_limit: object) -> None:
    with pytest.raises(APIError, match="输出额度"):
        build_start_command(
            {
                "repo": str(tmp_path),
                "workspace": "scan-001",
                "analyzers": ["authz"],
                "output_token_limit": output_token_limit,
                "disclosure_acknowledged": True,
            },
            {"authz"},
        )


@pytest.mark.parametrize("workspace", ["../escape", "a/b", "", ".hidden"])
def test_build_start_command_rejects_unsafe_workspace(tmp_path: Path, workspace: str) -> None:
    with pytest.raises(APIError, match="工作区名称"):
        build_start_command(
            {
                "repo": str(tmp_path),
                "workspace": workspace,
                "source_mode": "stripped",
                "analyzers": ["authz"],
                "disclosure_acknowledged": True,
            },
            {"authz"},
        )


def test_workspace_summary_reads_real_artifacts(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    workspace = runs_root / "demo-001"
    workspace.mkdir(parents=True)
    (workspace / "state.db").write_bytes(b"checkpoint")
    (workspace / "findings.json").write_text(
        json.dumps(
            [
                {"severity": "critical", "title": "Critical finding"},
                {"severity": "high", "title": "High finding"},
            ]
        ),
        encoding="utf-8",
    )

    summary = _service(tmp_path).workspace_summary("demo-001")

    assert summary["status"] == "checkpoint"
    assert summary["finding_count"] == 2
    assert summary["severity_counts"]["critical"] == 1
    assert summary["artifacts"]["findings"] is True


def test_failed_job_with_checkpoint_is_resumable(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    workspace = tmp_path / "runs" / "retry-me"
    workspace.mkdir(parents=True)
    (workspace / "state.db").write_bytes(b"checkpoint")
    job = launcher.launch("retry-me", "start", ["argus", "start"])
    job.returncode = 1

    summary = _service(tmp_path, launcher).workspace_summary("retry-me")

    assert summary["status"] == "resumable"
    assert summary["job"]["status"] == "failed"


def test_running_job_handle_does_not_override_persistent_workspace_state(
    tmp_path: Path,
) -> None:
    launcher = FakeLauncher()
    workspace = tmp_path / "runs" / "transient-handle"
    workspace.mkdir(parents=True)
    launcher.launch("transient-handle", "start", ["argus", "start"])

    summary = _service(tmp_path, launcher).workspace_summary("transient-handle")

    assert summary["job"]["status"] == "running"
    assert summary["status"] == "created"


def test_create_scan_rejects_existing_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "runs" / "scan-001").mkdir(parents=True)
    service = _service(tmp_path)
    monkeypatch.setattr("argus.web.discover_analyzers", lambda: {"authz": object()})

    with pytest.raises(APIError, match="已存在"):
        service.create_scan(
            {
                "repo": str(tmp_path),
                "workspace": "scan-001",
                "source_mode": "stripped",
                "analyzers": ["authz"],
                "disclosure_acknowledged": True,
            }
        )


def test_advance_builds_continue_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = FakeLauncher()
    state_path = tmp_path / "runs" / "demo-001" / "state.db"
    state_path.parent.mkdir(parents=True)
    state_path.write_bytes(b"checkpoint")
    service = _service(tmp_path, launcher)
    monkeypatch.setattr("argus.web.discover_analyzers", lambda: {"authz": object()})
    monkeypatch.setattr(
        service,
        "runtime",
        lambda _workspace: {
            "config": {
                "focus": "",
                "analyzers": ["authz"],
                "enrichment_analyzers": [],
                "output_token_limit": None,
                "business_flow_batch_size": 8,
                "strict_outputs": False,
            }
        },
    )

    job = service.advance("demo-001", "continue", {"focus": "src/orders"})

    assert job.command == [
        sys.executable,
        "-m",
        "argus.cli",
        "continue",
        "-w",
        "demo-001",
        "--set",
        "analyzers.enrichment=[]",
        "--set",
        'analyzers.vuln=["authz"]',
        "--set",
        "strict_outputs=false",
        "--focus",
        "src/orders",
    ]


def test_advance_resume_applies_safe_recovery_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    launcher = FakeLauncher()
    state_path = tmp_path / "runs" / "retry-me" / "state.db"
    state_path.parent.mkdir(parents=True)
    state_path.write_bytes(b"checkpoint")
    service = _service(tmp_path, launcher)
    monkeypatch.setattr(
        "argus.web.discover_analyzers",
        lambda: {"business-flow": object(), "authz": object()},
    )
    monkeypatch.setattr(
        service,
        "runtime",
        lambda _workspace: {
            "config": {
                "focus": "",
                "analyzers": ["authz"],
                "enrichment_analyzers": ["business-flow"],
                "output_token_limit": None,
                "business_flow_batch_size": 8,
                "strict_outputs": True,
            }
        },
    )

    job = service.advance(
        "retry-me",
        "resume",
        {
            "focus": "src/orders",
            "analyzers": ["authz"],
            "enrichment_analyzers": ["business-flow"],
            "output_token_limit": 131072,
            "business_flow_batch_size": 4,
            "strict_outputs": False,
        },
    )

    assert job.command[:6] == [sys.executable, "-m", "argus.cli", "resume", "-w", "retry-me"]
    assert "business-flow.batch_size=4" in job.command
    assert "business-flow.max_tokens=131072" in job.command
    assert "authz.max_tokens=131072" in job.command
    assert "strict_outputs=false" in job.command
    assert job.command[-2:] == ["--focus", "src/orders"]


def test_advance_rejects_invalid_recovery_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state_path = tmp_path / "runs" / "retry-me" / "state.db"
    state_path.parent.mkdir(parents=True)
    state_path.write_bytes(b"checkpoint")
    service = _service(tmp_path)
    monkeypatch.setattr("argus.web.discover_analyzers", lambda: {"authz": object()})
    monkeypatch.setattr(
        service,
        "runtime",
        lambda _workspace: {
            "config": {
                "focus": "",
                "analyzers": ["authz"],
                "enrichment_analyzers": [],
                "output_token_limit": None,
                "business_flow_batch_size": 8,
                "strict_outputs": False,
            }
        },
    )

    with pytest.raises(APIError, match="输出额度"):
        service.advance("retry-me", "resume", {"output_token_limit": 4096})


def test_runtime_exposes_safe_checkpoint_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = "paused"
    runs_root = tmp_path / "runs"
    state = make_initial_state(
        repo_path=str(tmp_path),
        workspace=workspace,
        config={
            "analyzers": {"enrichment": [], "vuln": []},
            "checkpoints": [REVIEW_ENRICHMENT],
            "source_mode": "raw",
            "focus": "src/api",
            "strict_outputs": True,
        },
        runs_root=str(runs_root),
    )
    state["graph_db_path"] = str(Path(__file__).parent / "fixtures" / "mini.db")
    checkpointer = make_checkpointer(workspace, runs_root=str(runs_root))
    app = build_pipeline({}, checkpointer)
    result = app.invoke(state, {"configurable": {"thread_id": workspace}})
    assert "__interrupt__" in result
    (runs_root / workspace / "web-console.log").write_text("secret-free failure detail\n", encoding="utf-8")
    monkeypatch.setattr("argus.web.discover_analyzers", lambda: {})

    runtime = _service(tmp_path).runtime(workspace)

    assert runtime["stage"] == REVIEW_ENRICHMENT
    assert runtime["config"]["focus"] == "src/api"
    assert runtime["config"]["strict_outputs"] is True
    assert runtime["log_tail"] == "secret-free failure detail"
    assert "repo_path" not in runtime


def test_progress_returns_bounded_safe_events(tmp_path: Path) -> None:
    workspace = tmp_path / "runs" / "active"
    workspace.mkdir(parents=True)
    (workspace / "progress.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-07-28T09:20:00+00:00",
                        "event": "batch_started",
                        "level": "info",
                        "message": "开始业务流批次 3/12",
                        "details": {"batch_index": 3, "batch_count": 12},
                    }
                ),
                "not-json",
            ]
        ),
        encoding="utf-8",
    )

    progress = _service(tmp_path).progress("active")

    assert progress["status"] == "created"
    assert progress["events"] == [
        {
            "timestamp": "2026-07-28T09:20:00+00:00",
            "event": "batch_started",
            "level": "info",
            "message": "开始业务流批次 3/12",
            "details": {"batch_index": 3, "batch_count": 12},
        }
    ]


def test_dashboard_selects_latest_workspace_with_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "runs" / "demo-001"
    workspace.mkdir(parents=True)
    findings: list[dict[str, Any]] = [{"severity": "high", "title": "Example"}]
    (workspace / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    monkeypatch.setattr("argus.web.discover_analyzers", lambda: {})

    dashboard = _service(tmp_path).dashboard()

    assert dashboard["selected_workspace"]["workspace"] == "demo-001"
    assert dashboard["findings"] == findings


def test_all_findings_adds_workspace_and_sorts_by_severity(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    first = runs_root / "first"
    second = runs_root / "second"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "findings.json").write_text(
        json.dumps([{"id": "low-1", "severity": "low", "title": "Low"}]),
        encoding="utf-8",
    )
    (second / "findings.json").write_text(
        json.dumps([{"id": "critical-1", "severity": "critical", "title": "Critical"}]),
        encoding="utf-8",
    )

    findings = _service(tmp_path).all_findings()

    assert [finding["id"] for finding in findings] == ["critical-1", "low-1"]
    assert findings[0]["_workspace"] == "second"


def test_settings_only_exposes_safe_llm_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "do-not-leak")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://llm.example.test/v1")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "test-model")
    monkeypatch.setattr("argus.web.load_llm_environment", lambda: None)

    settings = _service(tmp_path).settings()

    assert settings["llm"] == {
        "api_key_configured": True,
        "base_url_configured": True,
        "endpoint": "llm.example.test",
        "model": "test-model",
        "default_max_tokens": 32768,
        "heavy_max_tokens": 65536,
        "retry_ceiling": 393216,
    }
    assert "do-not-leak" not in json.dumps(settings)


def test_review_finding_persists_reversible_status(tmp_path: Path) -> None:
    workspace = tmp_path / "runs" / "demo"
    workspace.mkdir(parents=True)
    path = workspace / "findings.json"
    path.write_text(
        json.dumps([{"id": "finding-1", "severity": "high", "title": "Example"}]),
        encoding="utf-8",
    )
    service = _service(tmp_path)

    reviewed = service.review_finding("demo", {"finding_id": "finding-1", "status": "false_positive"})
    assert reviewed["review_status"] == "false_positive"
    assert "reviewed_at" in reviewed

    reset = service.review_finding("demo", {"finding_id": "finding-1", "status": "unreviewed"})
    assert "review_status" not in reset
    assert "reviewed_at" not in reset
