from pathlib import Path
import os

import pytest

from argus.ocr_adapter import OCRComment, OCRRunResult, OCRStatus
from argus.service.integration import (
    GitWorkspaceProvider,
    OpenCodeReviewServiceRunner,
    RepositoryLimitError,
    _classify_git_failure,
    _safe_ocr_warning_categories,
)
from argus.service.models import ScanCreateRequest, ScanStatus
from argus.service.store import ScanStore, WorkerScan


class FakeOCR:
    config = None

    def run(self, workspace: Path, config, **_kwargs) -> OCRRunResult:
        assert workspace.is_dir()
        assert config.no_plan and config.no_dedup and config.no_summary
        self.config = config
        return OCRRunResult(
            status=OCRStatus.COMPLETE,
            comments=(
                OCRComment(
                    path="src/auth.py",
                    start_line=3,
                    end_line=3,
                    category="security",
                    severity="high",
                    content="Check ownership before returning this object.",
                    existing_code="return object",
                    suggestion_code="return authorize(object)",
                ),
            ),
            summary={"files_reviewed": 2, "comments": 1, "total_tokens": 40},
            session_id="ocr-session-1",
            llm={"model": "test-model"},
        )


def test_structured_ocr_warning_categories_use_safe_fields() -> None:
    assert _safe_ocr_warning_categories(
        (
            {"type": "token_budget_reached", "file": "src/app.py", "message": "stopped"},
            {"type": "scan_subtask_error", "file": "src/auth.py", "message": "request timed out"},
        )
    ) == ["budget", "timeout"]


def test_ocr_result_is_mapped_to_service_finding() -> None:
    store = ScanStore(":memory:")
    scan, _ = store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    fake_ocr = FakeOCR()
    service_runner = OpenCodeReviewServiceRunner(fake_ocr, token_budget=1000, timeout_minutes=2)
    result = service_runner.run(claimed, Path("."), lambda _progress: None, lambda: False)

    assert result.status is ScanStatus.COMPLETED
    assert result.session_id == "ocr-session-1"
    assert result.reviewed_files == 2
    assert result.findings[0].rule_id == "ocr/security"
    assert result.findings[0].start_line == 3
    assert result.findings[0].metadata["fingerprint"]
    assert result.metadata["ocr_expected_deadline_seconds"] == 1800.0
    assert result.metadata["ocr_engine"] == "opencodereview"
    assert result.metadata["ocr_output_language"] == "zh-CN"
    assert fake_ocr.config is not None
    assert "简体中文" in fake_ocr.config.background
    assert scan.status is ScanStatus.QUEUED


def test_service_runner_preserves_background_and_appends_chinese_output_contract() -> None:
    store = ScanStore(":memory:")
    store.create_scan(
        ScanCreateRequest(
            repository_url="https://example.com/repo.git",
            background="重点检查访问控制。",
        )
    )
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    fake_ocr = FakeOCR()

    OpenCodeReviewServiceRunner(fake_ocr, token_budget=1000, timeout_minutes=2).run(
        claimed,
        Path("."),
        lambda _progress: None,
        lambda: False,
    )

    assert fake_ocr.config is not None
    assert fake_ocr.config.background.startswith("重点检查访问控制。")
    assert fake_ocr.config.background.endswith("不要翻译代码。")


def test_git_workspace_provider_enforces_file_limit(monkeypatch, tmp_path) -> None:
    provider = GitWorkspaceProvider(tmp_path / "workspaces", max_files=1)

    def fake_git(args, **_kwargs):
        if "clone" in args:
            destination = Path(args[-1])
            (destination / "one.py").write_text("x = 1\n", encoding="utf-8")
            (destination / "two.py").write_text("x = 2\n", encoding="utf-8")
        return type("Completed", (), {"stdout": "a" * 40})()

    monkeypatch.setattr(provider, "_run_git", fake_git)
    scan = WorkerScan(
        id="scan",
        repository_url="https://example.com/repo.git",
        ref="main",
        commit_sha=None,
        include=(),
        exclude=(),
        background=None,
        attempt=1,
        cancel_requested=False,
    )
    with pytest.raises(RepositoryLimitError):
        provider.prepare(scan)


def test_git_workspace_provider_emits_source_checking_after_clone(monkeypatch, tmp_path) -> None:
    provider = GitWorkspaceProvider(tmp_path / "workspaces")
    events: list[dict[str, object]] = []

    def fake_git(args, **_kwargs):
        if "clone" in args:
            destination = Path(args[-1])
            (destination / "app.py").write_text("value = 1\n", encoding="utf-8")
        return type("Completed", (), {"stdout": "a" * 40})()

    monkeypatch.setattr(provider, "_run_git", fake_git)
    scan = WorkerScan(
        id="scan",
        repository_url="https://example.com/repo.git",
        ref="main",
        commit_sha=None,
        include=(),
        exclude=(),
        background=None,
        attempt=1,
        cancel_requested=False,
    )
    prepared = provider.prepare(scan, event_callback=events.append)
    try:
        assert any(event["type"] == "phase" and event["stage"] == "source_checking" for event in events)
        assert any(event["type"] == "progress" and event["data"] == {"total_files": 1} for event in events)
    finally:
        prepared.__exit__(None, None, None)


def test_git_workspace_provider_rejects_symlinks(tmp_path) -> None:
    provider = GitWorkspaceProvider(tmp_path / "workspaces")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("private", encoding="utf-8")
    os.symlink(target, checkout / "link.txt")

    with pytest.raises(RepositoryLimitError, match="symbolic link"):
        provider._check_limits(checkout)


def test_service_runner_downgrades_missing_coverage_and_filters_metadata() -> None:
    class IncompleteOCR:
        def run(self, *_args, **_kwargs) -> OCRRunResult:
            return OCRRunResult(
                status=OCRStatus.COMPLETE,
                summary={"unexpected": "source should not be exposed"},
                message="m" * 3_000,
                llm={"model": "safe-model", "token": "secret"},
            )

    store = ScanStore(":memory:")
    store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    result = OpenCodeReviewServiceRunner(IncompleteOCR(), token_budget=1000, timeout_minutes=2).run(
        claimed,
        Path("."),
        lambda _progress: None,
        lambda: False,
    )

    assert result.status is ScanStatus.PARTIAL
    assert result.metadata["ocr_status"] == "partial"
    assert result.metadata["ocr_summary"] == {}
    assert result.metadata["ocr_llm"] == {"model": "safe-model"}
    assert "ocr_message" not in result.metadata
    assert result.metadata["ocr_warning_count"] == 0
    assert result.metadata["ocr_warnings"] == ["incomplete_coverage"]
    assert "m" * 100 not in str(result.metadata)


def test_service_runner_does_not_turn_warning_count_into_failed_files() -> None:
    class WarningOCR:
        def run(self, *_args, **_kwargs) -> OCRRunResult:
            return OCRRunResult(
                status=OCRStatus.COMPLETE,
                summary={"total_files": 3, "files_reviewed": 2, "files_failed": 1},
                warnings=("a warning from one completed file",),
            )

    store = ScanStore(":memory:")
    store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    progress: list[object] = []
    result = OpenCodeReviewServiceRunner(WarningOCR(), token_budget=1000, timeout_minutes=2).run(
        claimed,
        Path("."),
        progress.append,
        lambda: False,
    )

    assert result.status is ScanStatus.PARTIAL
    assert result.total_files == 3
    assert result.reviewed_files == 2
    assert result.failed_files == 1
    assert result.metadata["ocr_warning_count"] == 1
    assert progress[0].failed_files == 1


def test_partial_coverage_without_total_stays_unknown() -> None:
    class PartialOCR:
        def run(self, *_args, **_kwargs) -> OCRRunResult:
            return OCRRunResult(status=OCRStatus.PARTIAL, summary={"files_reviewed": 2})

    store = ScanStore(":memory:")
    created, _ = store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker")
    assert claimed is not None
    result = OpenCodeReviewServiceRunner(PartialOCR(), token_budget=1000, timeout_minutes=1).run(
        claimed,
        Path("."),
        lambda _progress: None,
        lambda: False,
    )
    store.finish(claimed.id, "worker", result, lease_token=claimed.lease_token)
    observation = store.get_scan(created.id).observation
    assert observation.coverage.reviewed == 2
    assert observation.coverage.total is None
    assert observation.coverage.percent is None


def test_service_runner_forwards_and_sanitizes_future_engine_events() -> None:
    class EventOCR:
        def run(self, *_args, event_callback=None, **_kwargs) -> OCRRunResult:
            assert event_callback is not None
            event_callback(
                {
                    "type": "llm.request.completed",
                    "source": "ocr",
                    "stage": "ocr_running",
                    "level": "info",
                    "code": "llm_request_completed",
                    "message": "raw model response must not persist",
                    "data": {"request_id": "req-1", "total_tokens": 40, "secret": "drop"},
                }
            )
            return OCRRunResult(status=OCRStatus.COMPLETE, summary={"files_reviewed": 1})

    store = ScanStore(":memory:")
    store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    events: list[dict[str, object]] = []
    result = OpenCodeReviewServiceRunner(EventOCR(), token_budget=1000, timeout_minutes=2).run(
        claimed,
        Path("."),
        lambda _progress: None,
        lambda: False,
        events.append,
    )

    assert result.status is ScanStatus.COMPLETED
    future = next(event for event in events if event["type"] == "llm.request.completed")
    assert set(future) == {"type", "source", "stage", "level", "code", "message", "data"}
    assert future["data"] == {"request_id": "req-1", "total_tokens": 40}
    assert "raw model response" not in str(future)


@pytest.mark.parametrize(
    ("diagnostic", "code"),
    [
        ("fatal: unable to access: Could not resolve host", "dns"),
        ("fatal: unable to access: Failed to connect", "connect"),
        ("SSL certificate problem: unable to get local issuer", "tls"),
        ("remote: Authentication failed", "auth"),
        ("remote: Repository not found", "repo_missing"),
        ("fatal: couldn't find remote ref missing", "ref_missing"),
        ("connection timed out", "timeout"),
        ("scan canceled", "cancel"),
        ("fatal: unexpected git failure", "unknown"),
    ],
)
def test_git_diagnostic_classification_is_stable(diagnostic: str, code: str) -> None:
    failure = _classify_git_failure(diagnostic)
    assert failure.code == code
    assert failure.message
    assert failure.suggestion


def test_ocr_environment_does_not_forward_argus_api_key(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ARGUS_API_KEY", "service-key")
    monkeypatch.setenv("ARGUS_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("ARGUS_LLM_API_KEY", "llm-key")
    monkeypatch.setenv("ARGUS_LLM_MODEL", "model")
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    runner = OpenCodeReviewServiceRunner.from_environment()

    environment = runner.runner.environment or {}
    assert "ARGUS_API_KEY" not in environment
    assert "ARGUS_LLM_API_KEY" not in environment
    assert environment["OCR_LLM_TOKEN"] == "llm-key"
    assert environment["OCR_LLM_PROTOCOL"] == "openai"


def test_ocr_environment_opt_in_enables_structured_events_and_pinned_identity(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ARGUS_OCR_EVENT_PROTOCOL", "1")
    monkeypatch.setenv("ARGUS_OCR_COMMIT", "a" * 40)
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    runner = OpenCodeReviewServiceRunner.from_environment()

    assert runner.event_protocol_enabled is True
    assert runner.runner.structured_event_protocol is True
    assert runner.engine_commit == "a" * 40
    assert runner.runner.environment is not None
    assert runner.runner.environment["ARGUS_OCR_EVENT_PROTOCOL"] == "1"
