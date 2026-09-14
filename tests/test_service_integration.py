from pathlib import Path
import os

import pytest

from argus.ocr_adapter import OCRComment, OCRRunResult, OCRStatus
from argus.service.integration import GitWorkspaceProvider, OpenCodeReviewServiceRunner, RepositoryLimitError
from argus.service.models import ScanCreateRequest, ScanStatus
from argus.service.store import ScanStore, WorkerScan


class FakeOCR:
    def run(self, workspace: Path, config, **_kwargs) -> OCRRunResult:
        assert workspace.is_dir()
        assert config.no_plan and config.no_dedup and config.no_summary
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


def test_ocr_result_is_mapped_to_service_finding() -> None:
    store = ScanStore(":memory:")
    scan, _ = store.create_scan(ScanCreateRequest(repository_url="https://example.com/repo.git"))
    claimed = store.claim_next("worker-1")
    assert claimed is not None
    service_runner = OpenCodeReviewServiceRunner(FakeOCR(), token_budget=1000, timeout_minutes=2)
    result = service_runner.run(claimed, Path("."), lambda _progress: None, lambda: False)

    assert result.status is ScanStatus.COMPLETED
    assert result.session_id == "ocr-session-1"
    assert result.reviewed_files == 2
    assert result.findings[0].rule_id == "ocr/security"
    assert result.findings[0].start_line == 3
    assert result.findings[0].metadata["fingerprint"]
    assert scan.status is ScanStatus.QUEUED


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
    assert len(result.metadata["ocr_message"]) == 2_000
    assert result.metadata["ocr_warnings"]


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
