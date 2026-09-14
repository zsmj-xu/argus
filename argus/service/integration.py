"""Git checkout and OpenCodeReview integration for the production worker."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import signal
from collections.abc import Mapping
from typing import Callable

from argus.ocr_adapter import OCRComment, OCRScanConfig, OCRStatus, OpenCodeReviewRunner
from argus.repositories import normalize_git_url

from .models import FindingCreate, ScanProgress, ScanStatus, ServiceScanResult
from .store import WorkerScan


_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")


class RepositoryFetchError(RuntimeError):
    """A repository could not be cloned or checked out."""


class RepositoryLimitError(RepositoryFetchError):
    """A cloned repository exceeded a configured safety limit."""


@dataclass
class PreparedWorkspace(AbstractContextManager[Path]):
    path: Path
    commit_sha: str

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *_args: object) -> None:
        shutil.rmtree(self.path, ignore_errors=True)


class GitWorkspaceProvider:
    """Create a disposable checkout for exactly one scan attempt."""

    def __init__(
        self,
        root: str | Path,
        *,
        timeout_seconds: int = 600,
        max_bytes: int = 1 << 30,
        max_files: int = 50_000,
    ) -> None:
        if timeout_seconds <= 0 or max_bytes <= 0 or max_files <= 0:
            raise ValueError("repository limits must be positive")
        self.root = Path(root).resolve()
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.root.mkdir(parents=True, exist_ok=True)

    def prepare(self, scan: WorkerScan, should_cancel: Callable[[], bool] | None = None) -> PreparedWorkspace:
        self.root.mkdir(parents=True, exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix=f"{scan.id}-", dir=self.root))
        try:
            if should_cancel is not None and should_cancel():
                raise RepositoryFetchError("repository fetch canceled")
            repository_url = normalize_git_url(scan.repository_url)
            target = scan.commit_sha or scan.ref
            clone_ref = None if target and _COMMIT.fullmatch(target) else target
            clone_args = [
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-tags",
            ]
            if clone_ref:
                clone_args.extend(["--branch", clone_ref])
            clone_args.extend(["--", repository_url, str(path)])
            self._run_git(clone_args, cancel_check=should_cancel)
            if target and _COMMIT.fullmatch(target):
                self._run_git(
                    [
                        "-c",
                        "protocol.file.allow=never",
                        "-C",
                        str(path),
                        "fetch",
                        "--depth",
                        "1",
                        "origin",
                        target,
                    ],
                    cancel_check=should_cancel,
                )
                self._run_git(
                    [
                        "-c",
                        "protocol.file.allow=never",
                        "-C",
                        str(path),
                        "checkout",
                        "--detach",
                        "FETCH_HEAD",
                    ],
                    cancel_check=should_cancel,
                )
            project_config = path / ".opencodereview"
            if project_config.is_dir():
                shutil.rmtree(project_config)
            elif project_config.exists():
                project_config.unlink()
            self._check_limits(path)
            commit = self._run_git(
                ["-c", "protocol.file.allow=never", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True,
                cancel_check=should_cancel,
            ).stdout.strip()
            if not _COMMIT.fullmatch(commit):
                raise RepositoryFetchError("repository did not resolve to a valid commit")
            return PreparedWorkspace(path, commit)
        except Exception as exc:
            shutil.rmtree(path, ignore_errors=True)
            if isinstance(exc, RepositoryFetchError):
                raise
            raise RepositoryFetchError("repository fetch or checkout failed") from exc

    def _check_limits(self, path: Path) -> None:
        files = 0
        total_bytes = 0
        for root, directories, names in os.walk(path):
            retained_directories: list[str] = []
            for name in directories:
                candidate = Path(root) / name
                if name == ".git":
                    if candidate.is_symlink():
                        raise RepositoryLimitError("repository contains an unsupported symbolic link")
                    continue
                if candidate.is_symlink():
                    raise RepositoryLimitError("repository contains an unsupported symbolic link")
                retained_directories.append(name)
            directories[:] = retained_directories
            for name in names:
                candidate = Path(root) / name
                try:
                    if candidate.is_symlink():
                        raise RepositoryLimitError("repository contains an unsupported symbolic link")
                    size = candidate.stat().st_size
                except OSError as exc:
                    raise RepositoryFetchError("repository could not be inspected") from exc
                files += 1
                total_bytes += size
                if files > self.max_files:
                    raise RepositoryLimitError("repository exceeds the maximum file count")
                if total_bytes > self.max_bytes:
                    raise RepositoryLimitError("repository exceeds the maximum source size")

    def _run_git(
        self,
        args: list[str],
        *,
        capture_output: bool = False,
        cancel_check: Callable[[], bool] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        source_environment = os.environ
        environment = {
            name: source_environment[name]
            for name in (
                "PATH",
                "HOME",
                "LANG",
                "LC_ALL",
                "SSH_AUTH_SOCK",
                "GIT_SSH_COMMAND",
                "GIT_SSH",
                "GIT_SSH_VARIANT",
                "GIT_CONFIG_GLOBAL",
            )
            if source_environment.get(name)
        }
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        command = ["git", *args]
        if cancel_check is None:
            try:
                return subprocess.run(
                    command,
                    env=environment,
                    stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                    stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=True,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise RepositoryFetchError("repository fetch or checkout failed") from exc

        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                command,
                env=environment,
                stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            deadline = time.monotonic() + self.timeout_seconds
            while process.poll() is None:
                if cancel_check():
                    _terminate_git_process(process)
                    process.communicate()
                    raise RepositoryFetchError("repository fetch canceled")
                if time.monotonic() >= deadline:
                    _terminate_git_process(process)
                    process.communicate()
                    raise RepositoryFetchError("repository fetch timed out")
                time.sleep(0.1)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise RepositoryFetchError("repository fetch or checkout failed")
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except RepositoryFetchError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            if process is not None and process.poll() is None:
                _terminate_git_process(process)
                process.communicate()
            raise RepositoryFetchError("repository fetch or checkout failed") from exc


def _terminate_git_process(process: subprocess.Popen[str]) -> None:
    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    process.kill()


def _safe_title(content: str) -> str:
    first = " ".join(content.splitlines()).strip()
    return first[:200] or "OpenCodeReview finding"


def _finding_from_comment(comment: OCRComment) -> FindingCreate:
    category = comment.category or "security"
    severity = comment.severity or "unknown"
    fingerprint = hashlib.sha256(
        "\0".join(
            [
                comment.path,
                str(comment.start_line or 0),
                str(comment.end_line or 0),
                category,
                comment.content,
            ]
        ).encode("utf-8")
    ).hexdigest()
    return FindingCreate(
        rule_id=f"ocr/{category}",
        title=_safe_title(comment.content),
        category=category,
        severity=severity,
        file=comment.path,
        start_line=comment.start_line,
        end_line=comment.end_line,
        message=comment.content,
        evidence=comment.existing_code or "",
        remediation=comment.suggestion_code or "",
        metadata={
            "fingerprint": fingerprint,
            "ocr_category": category,
            "ocr_severity": severity,
        },
    )


class OpenCodeReviewServiceRunner:
    """Adapt one OCR invocation to the service worker result contract."""

    def __init__(self, runner: OpenCodeReviewRunner, *, token_budget: int | None, timeout_minutes: int | None) -> None:
        self.runner = runner
        self.token_budget = token_budget
        self.timeout_minutes = timeout_minutes

    @classmethod
    def from_environment(cls) -> OpenCodeReviewServiceRunner:
        environment = os.environ.copy()
        environment.pop("ARGUS_API_KEY", None)
        if environment.get("ARGUS_LLM_BASE_URL") and not environment.get("OCR_LLM_URL"):
            environment["OCR_LLM_URL"] = environment["ARGUS_LLM_BASE_URL"]
        if environment.get("ARGUS_LLM_API_KEY") and not environment.get("OCR_LLM_TOKEN"):
            environment["OCR_LLM_TOKEN"] = environment["ARGUS_LLM_API_KEY"]
        environment.pop("ARGUS_LLM_API_KEY", None)
        if environment.get("ARGUS_LLM_MODEL") and not environment.get("OCR_LLM_MODEL"):
            environment["OCR_LLM_MODEL"] = environment["ARGUS_LLM_MODEL"]
        if environment.get("ARGUS_LLM_PROTOCOL") and not environment.get("OCR_LLM_PROTOCOL"):
            environment["OCR_LLM_PROTOCOL"] = environment["ARGUS_LLM_PROTOCOL"]
        if not environment.get("OCR_LLM_PROTOCOL") and not environment.get("OCR_USE_ANTHROPIC"):
            environment["OCR_LLM_PROTOCOL"] = "openai"
        ocr_home = Path(environment.get("ARGUS_DATA_DIR", "data")).resolve() / "ocr-home"
        ocr_home.mkdir(parents=True, exist_ok=True)
        environment["HOME"] = str(ocr_home)
        executable = environment.get("OCR_BINARY", "ocr")
        token_budget = _positive_int(environment.get("OCR_MAX_TOKENS_BUDGET")) or 1_000_000
        timeout_minutes = _nonnegative_int(environment.get("OCR_TIMEOUT_MINUTES"))
        if timeout_minutes is None:
            timeout_minutes = 30
        return cls(
            OpenCodeReviewRunner(executable, environment=environment),
            token_budget=token_budget,
            timeout_minutes=timeout_minutes,
        )

    def run(
        self,
        scan: WorkerScan,
        workspace: Path,
        progress: Callable[[ScanProgress], None],
        should_cancel: Callable[[], bool],
    ) -> ServiceScanResult:
        if should_cancel():
            return ServiceScanResult(status=ScanStatus.PARTIAL, error="cancel requested")
        progress(ScanProgress(percent=5))
        result = self.runner.run(
            workspace,
            OCRScanConfig(
                paths=scan.include,
                excludes=scan.exclude,
                background=scan.background,
                token_budget=self.token_budget,
                timeout_minutes=self.timeout_minutes,
                process_timeout_seconds=_process_timeout_seconds(),
                no_plan=True,
                no_dedup=True,
                no_summary=True,
            ),
            cancel_check=should_cancel,
        )
        comments = [_finding_from_comment(comment) for comment in result.comments]
        summary = _safe_ocr_summary(result.summary)
        reviewed_value = _nonnegative_int(summary.get("files_reviewed"))
        reviewed = reviewed_value if reviewed_value is not None else 0
        warnings = _safe_ocr_warnings(result.warnings)
        ocr_status = result.status
        if ocr_status is OCRStatus.COMPLETE and reviewed_value is None:
            warnings.append("OCR did not return a valid files_reviewed coverage value")
            ocr_status = OCRStatus.PARTIAL
        total = reviewed + len(warnings)
        progress(
            ScanProgress(
                total_files=total,
                reviewed_files=reviewed,
                failed_files=len(warnings),
                skipped_files=0,
                percent=100 if ocr_status in {OCRStatus.COMPLETE, OCRStatus.SKIPPED} else 50,
            )
        )
        metadata = {
            "ocr_status": ocr_status.value,
            "ocr_summary": summary,
            "ocr_warnings": warnings,
            "ocr_message": result.message[:2_000] if isinstance(result.message, str) else None,
            "ocr_llm": _safe_ocr_llm(result.llm),
            "ocr_exit_code": result.exit_code,
        }
        status = {
            OCRStatus.COMPLETE: ScanStatus.COMPLETED,
            OCRStatus.PARTIAL: ScanStatus.PARTIAL,
            OCRStatus.SKIPPED: ScanStatus.SKIPPED,
            OCRStatus.FAILED: ScanStatus.FAILED,
        }[ocr_status]
        return ServiceScanResult(
            status=status,
            findings=comments,
            session_id=result.session_id,
            total_files=total,
            reviewed_files=reviewed,
            failed_files=len(warnings),
            skipped_files=0,
            metadata=metadata,
            error=result.error,
        )


def _positive_int(value: str | None) -> int | None:
    try:
        parsed = int(value) if value is not None else 0
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed >= 0 else None


def _safe_ocr_summary(value: object) -> dict[str, int | str]:
    """Keep only bounded, non-sensitive coverage and usage counters."""

    if not isinstance(value, Mapping):
        return {}
    allowed = {
        "files_reviewed",
        "comments",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "elapsed",
    }
    summary: dict[str, int | str] = {}
    for key in allowed:
        item = value.get(key)
        if key == "elapsed":
            if isinstance(item, str) and item.strip():
                summary[key] = item.strip()[:64]
            continue
        parsed = _nonnegative_int(item)
        if parsed is not None:
            summary[key] = parsed
    return summary


def _safe_ocr_llm(value: object) -> dict[str, str]:
    """Expose provider identity only; never persist arbitrary LLM metadata."""

    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key in ("provider", "model"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            result[key] = item.strip()[:256]
    return result


def _safe_ocr_warnings(value: object) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item.strip()[:2_000] for item in value if isinstance(item, str) and item.strip()][:1_000]


def _process_timeout_seconds() -> float:
    value = os.getenv("OCR_PROCESS_TIMEOUT_SECONDS", "1800")
    try:
        parsed = float(value)
    except ValueError:
        return 1800.0
    return parsed if parsed > 0 else 1800.0
