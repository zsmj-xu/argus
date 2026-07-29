"""Local-only HTTP console for Argus workspaces and scan orchestration."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlparse

from argus.llm.client import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_MAX_TOKENS,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MODEL,
    HEAVY_MAX_TOKENS,
    load_llm_environment,
)
from argus.orchestration.registry import discover_analyzers
from argus.orchestration.checkpoints import make_checkpointer
from argus.orchestration.pipeline import build_pipeline

RUNS_ROOT = "runs"
MAX_REQUEST_BYTES = 1_000_000
MAX_LOG_BYTES = 200_000
MAX_PROGRESS_EVENTS = 300
WORKSPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
MIN_OUTPUT_TOKENS = 8_192
MAX_BUSINESS_FLOW_BATCH_SIZE = 128


class APIError(Exception):
    """An expected API error with a safe user-facing message."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Job:
    workspace: str
    action: str
    command: list[str]
    started_at: float
    log_path: str
    pid: int | None = None
    returncode: int | None = None

    @property
    def status(self) -> str:
        if self.returncode is None:
            return "running"
        return "complete" if self.returncode == 0 else "failed"

    def public(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("command")
        data["status"] = self.status
        return data


class JobLauncher(Protocol):
    def launch(self, workspace: str, action: str, command: list[str]) -> Job: ...

    def get(self, workspace: str) -> Job | None: ...


class JobManager:
    """Launches one subprocess per workspace and records its terminal status."""

    def __init__(self, project_root: Path, runs_root: Path) -> None:
        self.project_root = project_root
        self.runs_root = runs_root
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def launch(self, workspace: str, action: str, command: list[str]) -> Job:
        with self._lock:
            existing = self._jobs.get(workspace)
            if existing is not None and existing.status == "running":
                raise APIError(HTTPStatus.CONFLICT, f"工作区 {workspace!r} 已有任务正在运行")

            workspace_dir = self.runs_root / workspace
            workspace_dir.mkdir(parents=True, exist_ok=True)
            log_path = workspace_dir / "web-console.log"
            log_handle = log_path.open("a", encoding="utf-8")
            log_handle.write(f"\n[argus-web] {action} started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_handle.flush()

            try:
                process = subprocess.Popen(  # noqa: S603 - command is constructed from validated values
                    command,
                    cwd=self.project_root,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except OSError as exc:
                log_handle.close()
                raise APIError(HTTPStatus.INTERNAL_SERVER_ERROR, f"无法启动 Argus：{exc}") from exc

            job = Job(
                workspace=workspace,
                action=action,
                command=command,
                started_at=time.time(),
                log_path=str(log_path),
                pid=process.pid,
            )
            self._jobs[workspace] = job
            threading.Thread(
                target=self._monitor,
                args=(process, job, log_handle),
                name=f"argus-web-{workspace}",
                daemon=True,
            ).start()
            return job

    def _monitor(self, process: subprocess.Popen[str], job: Job, log_handle: Any) -> None:
        returncode = process.wait()
        log_handle.write(f"[argus-web] process exited with code {returncode}\n")
        log_handle.close()
        with self._lock:
            job.returncode = returncode

    def get(self, workspace: str) -> Job | None:
        with self._lock:
            return self._jobs.get(workspace)


def _validate_workspace(value: Any) -> str:
    if not isinstance(value, str) or not WORKSPACE_PATTERN.fullmatch(value):
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            "工作区名称只能包含字母、数字、点、下划线和连字符，且最长 128 个字符",
        )
    return value


def _validate_repo(value: Any) -> str:
    if not isinstance(value, str) or not os.path.isabs(value):
        raise APIError(HTTPStatus.BAD_REQUEST, "仓库路径必须是绝对路径")
    resolved = os.path.realpath(value)
    if not os.path.isdir(resolved):
        raise APIError(HTTPStatus.BAD_REQUEST, f"仓库目录不存在：{resolved}")
    return resolved


def _validate_source_mode(value: Any) -> str:
    if value not in {"raw", "stripped"}:
        raise APIError(HTTPStatus.BAD_REQUEST, "源码模式必须是 raw 或 stripped")
    return str(value)


def _validate_analyzers(value: Any, available: set[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise APIError(HTTPStatus.BAD_REQUEST, "分析器必须是字符串列表")
    unknown = sorted(set(value) - available)
    if unknown:
        raise APIError(HTTPStatus.BAD_REQUEST, f"未知分析器：{', '.join(unknown)}")
    return list(dict.fromkeys(value))


def _validate_output_token_limit(value: Any) -> int | None:
    if value in {None, "", "auto"}:
        return None
    if isinstance(value, bool):
        raise APIError(HTTPStatus.BAD_REQUEST, "输出额度必须是整数")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise APIError(HTTPStatus.BAD_REQUEST, "输出额度必须是整数") from exc
    if not MIN_OUTPUT_TOKENS <= parsed <= DEFAULT_MAX_OUTPUT_TOKENS:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            f"输出额度必须在 {MIN_OUTPUT_TOKENS} 到 {DEFAULT_MAX_OUTPUT_TOKENS} 之间",
        )
    return parsed


def _validate_business_flow_batch_size(value: Any) -> int:
    if value in {None, ""}:
        return 8
    if isinstance(value, bool):
        raise APIError(HTTPStatus.BAD_REQUEST, "业务流批次必须是整数")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise APIError(HTTPStatus.BAD_REQUEST, "业务流批次必须是整数") from exc
    if not 1 <= parsed <= MAX_BUSINESS_FLOW_BATCH_SIZE:
        raise APIError(
            HTTPStatus.BAD_REQUEST,
            f"业务流批次必须在 1 到 {MAX_BUSINESS_FLOW_BATCH_SIZE} 之间",
        )
    return parsed


def _validate_focus(value: Any) -> str | None:
    if value in {None, ""}:
        return None
    if not isinstance(value, str) or "\x00" in value or len(value) > 4096:
        raise APIError(HTTPStatus.BAD_REQUEST, "聚焦路径必须是有效路径字符串")
    return value


def _validate_strict_outputs(value: Any) -> bool:
    if not isinstance(value, bool):
        raise APIError(HTTPStatus.BAD_REQUEST, "严格输出必须是布尔值")
    return value


def build_start_command(payload: dict[str, Any], available_analyzers: set[str]) -> tuple[str, list[str]]:
    """Validate a scan payload and build an argv-only CLI command."""
    if payload.get("disclosure_acknowledged") is not True:
        raise APIError(HTTPStatus.BAD_REQUEST, "请先确认你有权向配置的 LLM 披露所选源码上下文")

    repo = _validate_repo(payload.get("repo"))
    workspace = _validate_workspace(payload.get("workspace"))
    source_mode = _validate_source_mode(payload.get("source_mode", "stripped"))
    vuln = _validate_analyzers(payload.get("analyzers", ["authz"]), available_analyzers)
    enrichment = _validate_analyzers(payload.get("enrichment_analyzers", []), available_analyzers)
    output_token_limit = _validate_output_token_limit(payload.get("output_token_limit"))
    business_flow_batch_size = _validate_business_flow_batch_size(payload.get("business_flow_batch_size"))

    command = [
        sys.executable,
        "-m",
        "argus.cli",
        "start",
        "-r",
        repo,
        "-w",
        workspace,
        "--set",
        f"source_mode={source_mode}",
        "--set",
        f"analyzers.enrichment={json.dumps(enrichment)}",
        "--set",
        f"analyzers.vuln={json.dumps(vuln)}",
    ]
    if "business-flow" in enrichment:
        command.extend(["--set", f"business-flow.batch_size={business_flow_batch_size}"])
    if output_token_limit is not None:
        for analyzer in [*enrichment, *vuln]:
            command.extend(["--set", f"{analyzer}.max_tokens={output_token_limit}"])
    if payload.get("checkpoints", True) is False:
        command.append("--yolo")
    return workspace, command


def _safe_json_file(path: Path, fallback: Any) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return fallback


def _atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
        os.replace(temporary_path, path)
    except BaseException:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity")
        if severity in counts:
            counts[severity] += 1
    return counts


class ConsoleService:
    """Application service shared by the HTTP handler and unit tests."""

    def __init__(
        self,
        *,
        project_root: Path,
        runs_root: Path,
        launcher: JobLauncher,
    ) -> None:
        self.project_root = project_root
        self.runs_root = runs_root
        self.launcher = launcher

    def analyzers(self) -> list[dict[str, str]]:
        discovered = discover_analyzers()
        return [{"name": name, "phase": analyzer.phase.value} for name, analyzer in sorted(discovered.items())]

    def list_workspaces(self) -> list[dict[str, Any]]:
        if not self.runs_root.is_dir():
            return []
        workspaces = [
            self.workspace_summary(entry.name)
            for entry in self.runs_root.iterdir()
            if entry.is_dir() and WORKSPACE_PATTERN.fullmatch(entry.name)
        ]
        return sorted(workspaces, key=lambda item: float(item["updated_at"]), reverse=True)

    def workspace_summary(self, workspace: str) -> dict[str, Any]:
        workspace = _validate_workspace(workspace)
        directory = self.runs_root / workspace
        if not directory.is_dir():
            raise APIError(HTTPStatus.NOT_FOUND, f"工作区不存在：{workspace}")

        findings = self.findings(workspace)
        job = self.launcher.get(workspace)
        if job is not None and job.status == "running":
            status = "running"
        elif (directory / "report.md").is_file():
            status = "complete"
        elif (directory / "state.db").is_file() and (
            (directory / "enriched-graph.json").is_file() or (directory / "findings.json").is_file()
        ):
            status = "checkpoint"
        elif (directory / "state.db").is_file():
            status = "resumable"
        elif job is not None and job.status == "failed":
            status = "failed"
        else:
            status = "created"

        artifacts = {
            "state": (directory / "state.db").is_file(),
            "enriched": (directory / "enriched-graph.json").is_file(),
            "findings": (directory / "findings.json").is_file(),
            "report": (directory / "report.md").is_file(),
        }
        return {
            "workspace": workspace,
            "status": status,
            "updated_at": directory.stat().st_mtime,
            "finding_count": len(findings),
            "severity_counts": _severity_counts(findings),
            "artifacts": artifacts,
            "job": job.public() if job is not None else None,
        }

    def findings(self, workspace: str) -> list[dict[str, Any]]:
        workspace = _validate_workspace(workspace)
        path = self.runs_root / workspace / "findings.json"
        value = _safe_json_file(path, [])
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def all_findings(self) -> list[dict[str, Any]]:
        aggregated: list[dict[str, Any]] = []
        for workspace in self.list_workspaces():
            workspace_name = str(workspace["workspace"])
            for finding in self.findings(workspace_name):
                aggregated.append({**finding, "_workspace": workspace_name})
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            aggregated,
            key=lambda finding: (
                severity_order.get(str(finding.get("severity")), 5),
                str(finding.get("title", "")),
            ),
        )

    def review_finding(self, workspace: str, payload: dict[str, Any]) -> dict[str, Any]:
        workspace = _validate_workspace(workspace)
        finding_id = payload.get("finding_id")
        status = payload.get("status")
        if not isinstance(finding_id, str) or not finding_id:
            raise APIError(HTTPStatus.BAD_REQUEST, "finding_id 不能为空")
        if status not in {"unreviewed", "confirmed", "false_positive"}:
            raise APIError(HTTPStatus.BAD_REQUEST, "审阅状态必须是 unreviewed、confirmed 或 false_positive")

        path = self.runs_root / workspace / "findings.json"
        findings = self.findings(workspace)
        matched: dict[str, Any] | None = None
        for finding in findings:
            if finding.get("id") != finding_id:
                continue
            matched = finding
            if status == "unreviewed":
                finding.pop("review_status", None)
                finding.pop("reviewed_at", None)
            else:
                finding["review_status"] = status
                finding["reviewed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            break
        if matched is None:
            raise APIError(HTTPStatus.NOT_FOUND, "未找到指定漏洞发现")
        try:
            _atomic_write_json(path, findings)
        except OSError as exc:
            raise APIError(HTTPStatus.INTERNAL_SERVER_ERROR, f"无法保存审阅状态：{exc}") from exc
        return matched

    def report(self, workspace: str) -> str:
        workspace = _validate_workspace(workspace)
        path = self.runs_root / workspace / "report.md"
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "该工作区尚未生成报告") from exc
        except OSError as exc:
            raise APIError(HTTPStatus.INTERNAL_SERVER_ERROR, f"无法读取报告：{exc}") from exc

    def log(self, workspace: str) -> str:
        workspace = _validate_workspace(workspace)
        path = self.runs_root / workspace / "web-console.log"
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                handle.seek(max(0, size - MAX_LOG_BYTES))
                return handle.read().decode("utf-8", errors="replace")
        except FileNotFoundError:
            return ""
        except OSError as exc:
            raise APIError(HTTPStatus.INTERNAL_SERVER_ERROR, f"无法读取运行日志：{exc}") from exc

    def progress(self, workspace: str) -> dict[str, Any]:
        """Return bounded structured progress without prompts, source, or responses."""
        workspace = _validate_workspace(workspace)
        path = self.runs_root / workspace / "progress.jsonl"
        events: list[dict[str, Any]] = []
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                handle.seek(max(0, size - MAX_LOG_BYTES))
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
        except FileNotFoundError:
            lines = []
        except OSError as exc:
            raise APIError(HTTPStatus.INTERNAL_SERVER_ERROR, f"无法读取进度日志：{exc}") from exc

        for line in lines[-MAX_PROGRESS_EVENTS:]:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(value, dict):
                continue
            details = value.get("details")
            events.append(
                {
                    "timestamp": value.get("timestamp"),
                    "event": value.get("event"),
                    "level": value.get("level"),
                    "message": value.get("message"),
                    "details": details if isinstance(details, dict) else {},
                }
            )
        legacy_audit = False
        if not events:
            audit_path = self.runs_root / workspace / "audit" / "llm.jsonl"
            try:
                size = audit_path.stat().st_size
                with audit_path.open("rb") as handle:
                    handle.seek(max(0, size - (MAX_LOG_BYTES * 4)))
                    audit_lines = handle.read().decode("utf-8", errors="replace").splitlines()
            except (FileNotFoundError, OSError):
                audit_lines = []
            for line in audit_lines[-MAX_PROGRESS_EVENTS:]:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(value, dict):
                    continue
                usage = value.get("usage")
                finish_reason = value.get("finish_reason")
                max_tokens = value.get("max_tokens")
                message = (
                    f"历史模型响应被截断（额度 {max_tokens:,} tokens）"
                    if finish_reason == "length" and isinstance(max_tokens, int)
                    else "历史模型调用完成"
                )
                events.append(
                    {
                        "timestamp": value.get("timestamp"),
                        "event": "legacy_llm_request_completed",
                        "level": "warning" if finish_reason == "length" else "success",
                        "message": message,
                        "details": {
                            "attempt": value.get("attempt"),
                            "max_tokens": max_tokens,
                            "finish_reason": finish_reason,
                            "completion_tokens": (usage.get("completion_tokens") if isinstance(usage, dict) else None),
                        },
                    }
                )
            legacy_audit = bool(events)
        return {
            "workspace": workspace,
            "status": self.workspace_summary(workspace)["status"],
            "events": events,
            "legacy_audit": legacy_audit,
        }

    def settings(self) -> dict[str, Any]:
        load_llm_environment()
        base_url = os.environ.get(ENV_BASE_URL, "")
        parsed = urlparse(base_url) if base_url else None
        endpoint = parsed.netloc if parsed is not None else ""
        return {
            "llm": {
                "api_key_configured": bool(os.environ.get(ENV_API_KEY)),
                "base_url_configured": bool(base_url),
                "endpoint": endpoint,
                "model": os.environ.get(ENV_MODEL, ""),
                "default_max_tokens": DEFAULT_MAX_TOKENS,
                "heavy_max_tokens": HEAVY_MAX_TOKENS,
                "retry_ceiling": DEFAULT_MAX_OUTPUT_TOKENS,
            },
            "server": {
                "local_only": True,
                "runs_root": str(self.runs_root),
                "project_root": str(self.project_root),
            },
            "analyzers": self.analyzers(),
        }

    def runtime(self, workspace: str) -> dict[str, Any]:
        """Return a safe, editable projection of the persisted graph state."""
        workspace = _validate_workspace(workspace)
        if not (self.runs_root / workspace / "state.db").is_file():
            raise APIError(HTTPStatus.CONFLICT, "该工作区没有可读取的 checkpoint")

        discovered = discover_analyzers()
        try:
            checkpointer = make_checkpointer(workspace, runs_root=str(self.runs_root))
            app = build_pipeline(discovered, checkpointer)
            snapshot = app.get_state({"configurable": {"thread_id": workspace}})
            values = dict(snapshot.values)
        except Exception as exc:
            raise APIError(HTTPStatus.CONFLICT, f"无法读取 checkpoint：{exc}") from exc

        config = values.get("config")
        if not isinstance(config, dict):
            config = {}
        analyzer_config = config.get("analyzers")
        if not isinstance(analyzer_config, dict):
            analyzer_config = {}
        available = set(discovered)
        enrichment = [
            item for item in analyzer_config.get("enrichment", []) if isinstance(item, str) and item in available
        ]
        vuln = [item for item in analyzer_config.get("vuln", []) if isinstance(item, str) and item in available]
        configured_limits = {
            config[name].get("max_tokens")
            for name in [*enrichment, *vuln]
            if isinstance(config.get(name), dict)
            and isinstance(config[name].get("max_tokens"), int)
            and not isinstance(config[name].get("max_tokens"), bool)
            and MIN_OUTPUT_TOKENS <= config[name]["max_tokens"] <= DEFAULT_MAX_OUTPUT_TOKENS
        }
        output_token_limit = configured_limits.pop() if len(configured_limits) == 1 else None
        business_flow_config = config.get("business-flow")
        if not isinstance(business_flow_config, dict):
            business_flow_config = {}
        business_flow_batch_size = business_flow_config.get("batch_size", 8)
        if (
            not isinstance(business_flow_batch_size, int)
            or isinstance(business_flow_batch_size, bool)
            or not 1 <= business_flow_batch_size <= MAX_BUSINESS_FLOW_BATCH_SIZE
        ):
            business_flow_batch_size = 8
        focus = config.get("focus", "")
        if not isinstance(focus, str):
            focus = ""
        completed_nodes = values.get("completed_nodes", [])
        if not isinstance(completed_nodes, list):
            completed_nodes = []

        stage = None
        if snapshot.interrupts:
            detail = snapshot.interrupts[0].value
            if isinstance(detail, dict):
                stage = detail.get("stage")
                if not isinstance(stage, str):
                    stage = None
        log_tail = self.log(workspace).splitlines()[-24:]
        return {
            "workspace": workspace,
            "status": self.workspace_summary(workspace)["status"],
            "stage": stage,
            "next_nodes": list(snapshot.next),
            "completed_nodes": [item for item in completed_nodes if isinstance(item, str)],
            "config": {
                "focus": focus,
                "strict_outputs": config.get("strict_outputs") is True,
                "analyzers": vuln,
                "enrichment_analyzers": enrichment,
                "output_token_limit": output_token_limit,
                "business_flow_batch_size": business_flow_batch_size,
            },
            "log_tail": "\n".join(log_tail),
        }

    def create_scan(self, payload: dict[str, Any]) -> Job:
        available = set(discover_analyzers())
        workspace, command = build_start_command(payload, available)
        if (self.runs_root / workspace).exists():
            raise APIError(HTTPStatus.CONFLICT, f"工作区已存在，请使用新的名称：{workspace}")
        return self.launcher.launch(workspace, "start", command)

    def advance(self, workspace: str, action: str, payload: dict[str, Any]) -> Job:
        workspace = _validate_workspace(workspace)
        if not (self.runs_root / workspace / "state.db").is_file():
            raise APIError(HTTPStatus.CONFLICT, "该工作区没有可继续的 checkpoint")
        if action not in {"continue", "resume"}:
            raise APIError(HTTPStatus.BAD_REQUEST, "不支持的运行操作")

        available = set(discover_analyzers())
        persisted = self.runtime(workspace)["config"]
        focus = _validate_focus(payload.get("focus", persisted["focus"]))
        vuln = _validate_analyzers(payload.get("analyzers", persisted["analyzers"]), available)
        enrichment = _validate_analyzers(
            payload.get("enrichment_analyzers", persisted["enrichment_analyzers"]),
            available,
        )
        output_token_limit = _validate_output_token_limit(
            payload.get("output_token_limit", persisted["output_token_limit"])
        )
        business_flow_batch_size = _validate_business_flow_batch_size(
            payload.get("business_flow_batch_size", persisted["business_flow_batch_size"])
        )
        strict_outputs = _validate_strict_outputs(payload.get("strict_outputs", persisted["strict_outputs"]))

        command = [sys.executable, "-m", "argus.cli", action, "-w", workspace]
        command.extend(["--set", f"analyzers.enrichment={json.dumps(enrichment)}"])
        command.extend(["--set", f"analyzers.vuln={json.dumps(vuln)}"])
        command.extend(["--set", f"strict_outputs={json.dumps(strict_outputs)}"])
        if "business-flow" in enrichment:
            command.extend(["--set", f"business-flow.batch_size={business_flow_batch_size}"])
        if output_token_limit is not None:
            for analyzer in [*enrichment, *vuln]:
                command.extend(["--set", f"{analyzer}.max_tokens={output_token_limit}"])
        elif "output_token_limit" in payload:
            for analyzer in [*enrichment, *vuln]:
                default_limit = HEAVY_MAX_TOKENS if analyzer in {"business-flow", "invariant"} else DEFAULT_MAX_TOKENS
                command.extend(["--set", f"{analyzer}.max_tokens={default_limit}"])
        if focus is not None:
            command.extend(["--focus", focus])
        return self.launcher.launch(workspace, action, command)

    def dashboard(self) -> dict[str, Any]:
        workspaces = self.list_workspaces()
        selected = next((item for item in workspaces if item["status"] == "running"), None)
        if selected is None:
            selected = next((item for item in workspaces if item["status"] == "checkpoint"), None)
        if selected is None:
            selected = next((item for item in workspaces if item["finding_count"] > 0), None)
        if selected is None:
            selected = next((item for item in workspaces if item["status"] == "resumable"), None)
        if selected is None and workspaces:
            selected = workspaces[0]
        findings = self.findings(selected["workspace"]) if selected is not None else []
        return {
            "workspaces": workspaces,
            "selected_workspace": selected,
            "findings": findings,
            "analyzers": self.analyzers(),
            "project_root": str(self.project_root),
        }


class ArgusConsoleHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the console assets and same-origin JSON API."""

    service: ConsoleService
    ui_root: Path
    server_version = "ArgusConsole/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[argus-web] {self.address_string()} {format % args}\n")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
        try:
            self._do_get()
        except APIError as exc:
            self._send_json({"error": exc.message}, exc.status)
        except Exception:
            self._send_json({"error": "服务器处理请求时发生内部错误"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _do_get(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            self._send_json({"status": "ok", "local_only": True})
            return
        if path == "/api/dashboard":
            self._send_json(self.service.dashboard())
            return
        if path == "/api/workspaces":
            self._send_json({"workspaces": self.service.list_workspaces()})
            return
        if path == "/api/analyzers":
            self._send_json({"analyzers": self.service.analyzers()})
            return
        if path == "/api/findings":
            self._send_json({"findings": self.service.all_findings()})
            return
        if path == "/api/settings":
            self._send_json(self.service.settings())
            return

        workspace_route = self._workspace_route(path)
        if workspace_route is not None:
            workspace, resource = workspace_route
            if resource == "":
                self._send_json(self.service.workspace_summary(workspace))
            elif resource == "findings":
                self._send_json({"findings": self.service.findings(workspace)})
            elif resource == "report":
                report = self.service.report(workspace)
                download = parse_qs(parsed.query).get("download") == ["1"]
                self._send_text(
                    report,
                    "text/markdown; charset=utf-8",
                    filename=f"{workspace}-report.md" if download else None,
                )
            elif resource == "log":
                self._send_text(self.service.log(workspace), "text/plain; charset=utf-8")
            elif resource == "progress":
                self._send_json(self.service.progress(workspace))
            elif resource == "runtime":
                self._send_json(self.service.runtime(workspace))
            else:
                raise APIError(HTTPStatus.NOT_FOUND, "API 路径不存在")
            return

        self._serve_asset(path)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook
        try:
            payload = self._read_json()
            parsed = urlparse(self.path)
            if parsed.path == "/api/scans":
                job = self.service.create_scan(payload)
                self._send_json({"job": job.public()}, HTTPStatus.ACCEPTED)
                return

            workspace_route = self._workspace_route(parsed.path)
            if workspace_route is not None:
                workspace, resource = workspace_route
                if resource in {"continue", "resume"}:
                    job = self.service.advance(workspace, resource, payload)
                    self._send_json({"job": job.public()}, HTTPStatus.ACCEPTED)
                    return
                if resource == "findings/review":
                    finding = self.service.review_finding(workspace, payload)
                    self._send_json({"finding": finding})
                    return
            raise APIError(HTTPStatus.NOT_FOUND, "API 路径不存在")
        except APIError as exc:
            self._send_json({"error": exc.message}, exc.status)
        except Exception:
            self._send_json({"error": "服务器处理请求时发生内部错误"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _workspace_route(self, path: str) -> tuple[str, str] | None:
        prefix = "/api/workspaces/"
        if not path.startswith(prefix):
            return None
        remainder = path[len(prefix) :]
        workspace, separator, resource = remainder.partition("/")
        if not workspace:
            raise APIError(HTTPStatus.NOT_FOUND, "工作区路径不完整")
        return unquote(workspace), resource if separator else ""

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "0")
        except ValueError as exc:
            raise APIError(HTTPStatus.BAD_REQUEST, "无效的 Content-Length") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise APIError(HTTPStatus.BAD_REQUEST, "请求正文为空或过大")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise APIError(HTTPStatus.BAD_REQUEST, "请求正文必须是 JSON") from exc
        if not isinstance(value, dict):
            raise APIError(HTTPStatus.BAD_REQUEST, "请求正文必须是 JSON 对象")
        return value

    def _serve_asset(self, raw_path: str) -> None:
        relative = "index.html" if raw_path in {"", "/"} else unquote(raw_path).lstrip("/")
        candidate = (self.ui_root / relative).resolve()
        try:
            candidate.relative_to(self.ui_root.resolve())
        except ValueError as exc:
            raise APIError(HTTPStatus.NOT_FOUND, "静态资源不存在") from exc
        if not candidate.is_file():
            raise APIError(HTTPStatus.NOT_FOUND, "静态资源不存在")
        media_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        data = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header(
            "Content-Type", f"{media_type}; charset=utf-8" if media_type.startswith("text/") else media_type
        )
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, value: str, media_type: str, filename: str | None = None) -> None:
        data = value.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if filename is not None:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)


def make_server(
    *,
    host: str,
    port: int,
    project_root: Path,
    runs_root: Path,
    ui_root: Path | None = None,
) -> ThreadingHTTPServer:
    """Create a local console server without starting its event loop."""
    if host not in LOOPBACK_HOSTS:
        raise ValueError("Argus Console has no authentication and may only bind to a loopback host")
    assets = ui_root or Path(__file__).with_name("web_ui")
    manager = JobManager(project_root, runs_root)
    service = ConsoleService(project_root=project_root, runs_root=runs_root, launcher=manager)

    class Handler(ArgusConsoleHandler):
        pass

    Handler.service = service
    Handler.ui_root = assets
    return ThreadingHTTPServer((host, port), Handler)


def serve(args: argparse.Namespace) -> int:
    project_root = Path.cwd().resolve()
    runs_root = (project_root / args.runs_root).resolve()
    server = make_server(
        host=args.host,
        port=args.port,
        project_root=project_root,
        runs_root=runs_root,
    )
    bound_port = int(server.server_address[1])
    print(f"[argus] console available at http://{args.host}:{bound_port}")
    print("[argus] scans may disclose selected source context to the configured LLM")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[argus] console stopped")
    finally:
        server.server_close()
    return 0
