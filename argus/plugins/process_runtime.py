"""JSON-RPC/stdio process boundary for plugin execution."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import BinaryIO, cast
from uuid import UUID, uuid4

from pydantic import JsonValue, TypeAdapter, ValidationError

from argus.domain.models import StaticFindingV2
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput
from argus.llm.client import (
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_DISABLE_THINKING,
    ENV_MAX_OUTPUT_TOKENS,
    ENV_MODEL,
    ENV_TIMEOUT,
)
from argus.plugins.contracts import SecretsPermission
from argus.plugins.registry import RegisteredPlugin

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
_REFERENCE = re.compile(r"^[0-9a-f]{32}$")
_STDIO_LIMIT = 1024 * 1024
_LLM_ENVIRONMENT = {
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_DISABLE_THINKING,
    ENV_MAX_OUTPUT_TOKENS,
    ENV_MODEL,
    ENV_TIMEOUT,
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
}


class PluginProcessError(RuntimeError):
    pass


class PluginProcessTimeout(PluginProcessError):
    pass


class PluginProcessOutputLimit(PluginProcessError):
    pass


def _read_limited(
    stream: BinaryIO,
    *,
    limit: int,
    target: bytearray,
    overflow: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    while chunk := stream.read(64 * 1024):
        if len(target) + len(chunk) > limit:
            overflow.set()
            _terminate_process(process)
            return
        target.extend(chunk)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    process.kill()


def _worker_environment(
    registered: RegisteredPlugin,
    *,
    runs_root: Path,
    temp_root: Path,
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONUTF8": "1",
        "ARGUS_PLUGIN_RUNS_ROOT": str(runs_root),
        "ARGUS_PLUGIN_TEMP_ROOT": str(temp_root),
        "ARGUS_PLUGIN_SOURCE_PERMISSION": registered.spec.permissions.source.value,
        "ARGUS_PLUGIN_NETWORK_PERMISSION": registered.spec.permissions.network.value,
        "ARGUS_PLUGIN_SUBPROCESS_PERMISSION": registered.spec.permissions.subprocess.value,
        "ARGUS_PLUGIN_MEMORY_LIMIT_MB": str(registered.spec.runtime.memory_limit_mb),
        "ARGUS_PLUGIN_MAX_OUTPUT_BYTES": str(registered.spec.runtime.max_output_bytes),
        "ARGUS_PLUGIN_TIMEOUT_SECONDS": str(registered.spec.runtime.timeout_seconds),
    }
    if registered.manifest_path is not None:
        environment["ARGUS_PLUGIN_ROOT"] = str(Path(registered.manifest_path).resolve().parent)
    if registered.spec.permissions.secrets is SecretsPermission.LLM:
        environment.update({key: value for key in _LLM_ENVIRONMENT if (value := os.environ.get(key)) is not None})
    return environment


def _request(
    registered: RegisteredPlugin,
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> bytes:
    snapshot = context.snapshot
    request: dict[str, JsonValue] = {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "plugin.execute",
        "params": {
            "plugin": {
                "id": registered.spec.id,
                "version": registered.spec.version,
                "entrypoint": registered.spec.entrypoint,
            },
            "context": {
                "scan": context.scan.model_dump(mode="json"),
                "snapshot": {
                    "id": str(snapshot.id),
                    "project_id": str(snapshot.project_id),
                    "vcs_type": snapshot.vcs_type.value,
                    "commit_sha": snapshot.commit_sha,
                    "tree_hash": snapshot.tree_hash,
                    "dirty": snapshot.dirty,
                    "manifest_artifact_id": str(snapshot.manifest_artifact_id),
                    "created_at": snapshot.created_at.isoformat(),
                },
                "task": context.task.model_dump(mode="json"),
                "workspace": context.workspace,
                "attempt_id": str(context.attempt_id),
                "input_hashes": cast(JsonValue, context.input_hashes),
            },
            "inputs": {
                capability: {
                    "capability": capability,
                    "artifact": item.artifact.model_dump(mode="json"),
                }
                for capability, item in inputs.items()
            },
        },
    }
    return json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()


class ProcessPluginRunner:
    def run(
        self,
        registered: RegisteredPlugin,
        context: RuntimeContext,
        inputs: dict[str, RuntimeInput],
    ) -> list[RuntimeOutput]:
        staging_parent = context.runs_root / "_data" / "plugin-tmp"
        staging_parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(
                prefix=f"{context.task.id}.",
                dir=staging_parent,
            )
        )
        try:
            return self._run(registered, context, inputs, temporary)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def _run(
        self,
        registered: RegisteredPlugin,
        context: RuntimeContext,
        inputs: dict[str, RuntimeInput],
        temporary: Path,
    ) -> list[RuntimeOutput]:
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter/module invocation
            [sys.executable, "-I", "-m", "argus.plugins.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=temporary,
            env=_worker_environment(
                registered,
                runs_root=context.runs_root,
                temp_root=temporary,
            ),
            start_new_session=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()
        stdout_thread = threading.Thread(
            target=_read_limited,
            kwargs={
                "stream": process.stdout,
                "limit": _STDIO_LIMIT,
                "target": stdout,
                "overflow": overflow,
                "process": process,
            },
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_read_limited,
            kwargs={
                "stream": process.stderr,
                "limit": _STDIO_LIMIT,
                "target": stderr,
                "overflow": overflow,
                "process": process,
            },
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            process.stdin.write(_request(registered, context, inputs))
            process.stdin.close()
            process.wait(timeout=registered.spec.runtime.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _terminate_process(process)
            process.wait()
            raise PluginProcessTimeout(
                f"plugin {registered.spec.id!r} exceeded {registered.spec.runtime.timeout_seconds}s timeout"
            ) from exc
        finally:
            stdout_thread.join()
            stderr_thread.join()
        if overflow.is_set():
            raise PluginProcessOutputLimit(
                f"plugin {registered.spec.id!r} exceeded the {_STDIO_LIMIT}-byte stdio limit"
            )
        if process.returncode != 0:
            raise PluginProcessError(f"plugin {registered.spec.id!r} worker exited with code {process.returncode}")
        try:
            response = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginProcessError(f"plugin {registered.spec.id!r} returned an invalid JSON-RPC response") from exc
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
            raise PluginProcessError("plugin worker returned an invalid JSON-RPC envelope")
        error = response.get("error")
        if isinstance(error, dict):
            code = str(error.get("code", "PLUGIN_FAILED"))
            raise PluginProcessError(f"plugin {registered.spec.id!r} failed: {code}")
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("outputs"), list):
            raise PluginProcessError("plugin worker response has no output references")
        total = 0
        seen: set[str] = set()
        for item in result["outputs"]:
            if not isinstance(item, dict):
                raise PluginProcessError("plugin output reference must be an object")
            reference = item.get("reference")
            if not isinstance(reference, str) or _REFERENCE.fullmatch(reference) is None:
                raise PluginProcessError("plugin output reference is invalid")
            if reference in seen:
                raise PluginProcessError("plugin returned a duplicate output reference")
            seen.add(reference)
            path = (temporary / "outputs" / reference).resolve()
            if not path.is_file():
                raise PluginProcessError("plugin output reference is missing")
            total += path.stat().st_size
            if total > registered.spec.runtime.max_output_bytes:
                raise PluginProcessOutputLimit(f"plugin {registered.spec.id!r} outputs exceed their total byte limit")
        return [self._output_from_reference(registered, temporary, item) for item in result["outputs"]]

    @staticmethod
    def _output_from_reference(
        registered: RegisteredPlugin,
        temporary: Path,
        raw: object,
    ) -> RuntimeOutput:
        if not isinstance(raw, dict):
            raise PluginProcessError("plugin output reference must be an object")
        reference = raw.get("reference")
        if not isinstance(reference, str) or _REFERENCE.fullmatch(reference) is None:
            raise PluginProcessError("plugin output reference is invalid")
        path = (temporary / "outputs" / reference).resolve()
        try:
            path.relative_to((temporary / "outputs").resolve())
        except ValueError as exc:
            raise PluginProcessError("plugin output reference escapes staging") from exc
        if not path.is_file():
            raise PluginProcessError("plugin output reference is missing")
        payload = path.read_bytes()
        if len(payload) > registered.spec.runtime.max_output_bytes:
            raise PluginProcessOutputLimit(f"plugin {registered.spec.id!r} output exceeds its byte limit")
        expected_hash = raw.get("content_hash")
        if not isinstance(expected_hash, str) or hashlib.sha256(payload).hexdigest() != expected_hash:
            raise PluginProcessError("plugin output reference hash does not match")
        representation = raw.get("representation")
        json_value: JsonValue | None = None
        raw_payload: bytes | None = None
        if representation == "json":
            try:
                json_value = _JSON.validate_json(payload)
            except ValidationError as exc:
                raise PluginProcessError("plugin JSON output reference is invalid") from exc
        elif representation in {"payload", "source"}:
            raw_payload = payload
        else:
            raise PluginProcessError("plugin output representation is invalid")
        try:
            findings = tuple(StaticFindingV2.model_validate(item) for item in raw.get("static_findings", []))
        except (TypeError, ValidationError) as exc:
            raise PluginProcessError("plugin returned invalid StaticFindingV2 records") from exc
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, dict):
            raise PluginProcessError("plugin output metadata must be an object")
        return RuntimeOutput(
            capability=str(raw.get("capability", "")),
            artifact_type=str(raw.get("artifact_type", "")),
            schema_version=str(raw.get("schema_version", "")),
            media_type=str(raw.get("media_type", "")),
            payload=raw_payload,
            json_value=json_value,
            metadata=cast(dict[str, JsonValue], metadata),
            artifact_id=(UUID(str(raw["artifact_id"])) if raw.get("artifact_id") is not None else None),
            static_findings=findings,
        )
