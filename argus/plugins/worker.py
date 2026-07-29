"""Isolated plugin worker. Protocol traffic is one JSON-RPC message on stdio."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from argus.artifacts.codecs import encode_json
from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories
from argus.domain.models import Artifact, Scan, SourceSnapshot, Task
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput


class WorkerPolicyDenied(PermissionError):
    pass


class _DeniedRepositories:
    def __getattr__(self, name: str) -> NoReturn:
        raise WorkerPolicyDenied(f"plugin repository access is denied: {name}")


def _environment_path(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        raise WorkerPolicyDenied(f"worker environment is missing {name}")
    return Path(raw).resolve()


def _apply_resource_limits() -> None:
    memory_bytes = int(os.environ["ARGUS_PLUGIN_MEMORY_LIMIT_MB"]) * 1024 * 1024
    output_bytes = int(os.environ["ARGUS_PLUGIN_MAX_OUTPUT_BYTES"])
    timeout = int(os.environ["ARGUS_PLUGIN_TIMEOUT_SECONDS"])
    for name, value in (
        ("RLIMIT_AS", memory_bytes),
        ("RLIMIT_FSIZE", output_bytes),
        ("RLIMIT_CPU", max(1, timeout)),
    ):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            _soft, hard = resource.getrlimit(limit)
            resource.setrlimit(limit, (min(value, hard) if hard >= 0 else value, hard))
        except (OSError, ValueError):
            continue


def _restrict_network() -> None:
    permission = os.environ["ARGUS_PLUGIN_NETWORK_PERMISSION"]

    def denied(*_args: object, **_kwargs: object) -> NoReturn:
        raise WorkerPolicyDenied("plugin network access is denied")

    if permission == "none":
        setattr(socket, "socket", denied)
        setattr(socket, "create_connection", denied)
        setattr(socket, "getaddrinfo", denied)
        setattr(socket, "gethostbyname", denied)
        return

    parsed = urlsplit(os.environ.get("ARGUS_LLM_BASE_URL", ""))
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise WorkerPolicyDenied("LLM network permission requires a configured base URL")
    allowed_host = parsed.hostname
    allowed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    original_getaddrinfo = socket.getaddrinfo
    resolved = original_getaddrinfo(allowed_host, allowed_port, type=socket.SOCK_STREAM)
    allowed_addresses = {str(item[4][0]) for item in resolved}

    def allowed_endpoint(address: object) -> bool:
        return (
            isinstance(address, tuple)
            and len(address) >= 2
            and str(address[0]) in {allowed_host, *allowed_addresses}
            and address[1] == allowed_port
        )

    class RestrictedSocket(socket.socket):
        def connect(self, address: object) -> None:
            if not allowed_endpoint(address):
                denied()
            super().connect(cast(Any, address))

        def connect_ex(self, address: object) -> int:
            if not allowed_endpoint(address):
                denied()
            return super().connect_ex(cast(Any, address))

        def sendto(self, data: bytes, address: object) -> int:  # type: ignore[override]
            if not allowed_endpoint(address):
                denied()
            return super().sendto(data, cast(Any, address))

        def bind(self, _address: object) -> NoReturn:
            raise WorkerPolicyDenied("plugin socket bind is denied")

        def listen(self, _backlog: int = 0) -> NoReturn:
            raise WorkerPolicyDenied("plugin socket listen is denied")

    def restricted_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if str(host) != allowed_host or port not in {allowed_port, str(allowed_port)}:
            denied()
        return original_getaddrinfo(host, port, *args, **kwargs)

    setattr(socket, "socket", RestrictedSocket)
    setattr(socket, "getaddrinfo", restricted_getaddrinfo)
    setattr(
        socket,
        "gethostbyname",
        lambda host: resolved[0][4][0] if str(host) == allowed_host else denied(),
    )


def _restrict_subprocess() -> None:
    permission = os.environ["ARGUS_PLUGIN_SUBPROCESS_PERMISSION"]
    original_popen: Any = subprocess.Popen

    def denied(*_args: object, **_kwargs: object) -> NoReturn:
        raise WorkerPolicyDenied("plugin subprocess access is denied")

    def restricted(args: object, *positional: object, **kwargs: object) -> Any:
        if kwargs.get("shell"):
            raise WorkerPolicyDenied("shell execution is denied")
        command = args[0] if isinstance(args, (list, tuple)) and args else None
        if not isinstance(command, (str, bytes)) or Path(os.fsdecode(command)).name != "codegraph":
            raise WorkerPolicyDenied("restricted subprocess permission only permits codegraph")
        return original_popen(args, *positional, **kwargs)

    setattr(subprocess, "Popen", denied if permission == "none" else restricted)
    if permission == "none":
        subprocess.call = cast(Any, denied)
        subprocess.check_call = cast(Any, denied)
        subprocess.check_output = cast(Any, denied)
        subprocess.run = cast(Any, denied)
    os.system = cast(Any, denied)
    for name in dir(os):
        if name.startswith(("spawn", "exec")):
            setattr(os, name, denied)


def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    return any(resolved == root or resolved.is_relative_to(root) for root in roots)


def _install_filesystem_policy(
    snapshot_root: Path,
    temp_root: Path,
    workspace: str,
    artifact_paths: tuple[Path, ...],
) -> None:
    runs_root = _environment_path("ARGUS_PLUGIN_RUNS_ROOT")
    plugin_root_raw = os.environ.get("ARGUS_PLUGIN_ROOT")
    library_roots = tuple(Path(item).resolve() for item in sys.path if item and Path(item).exists())
    plugin_roots = (Path(plugin_root_raw).resolve(),) if plugin_root_raw else ()
    read_roots = (
        temp_root,
        *artifact_paths,
        *library_roots,
        *plugin_roots,
    )
    if os.environ["ARGUS_PLUGIN_SOURCE_PERMISSION"] == "read":
        read_roots = (*read_roots, snapshot_root)
    workspace_root = (runs_root / workspace).resolve()
    audit_root = workspace_root / "audit"
    progress_path = workspace_root / "progress.jsonl"
    write_roots = (temp_root, audit_root)

    def check_path(raw: object, *, write: bool) -> None:
        if isinstance(raw, int):
            return
        if not isinstance(raw, (str, bytes, os.PathLike)):
            raise WorkerPolicyDenied("plugin file path type is denied")
        path = Path(os.fsdecode(raw))
        if not path.is_absolute():
            path = Path.cwd() / path
        if write:
            if not _inside(path, write_roots) and path.resolve() != progress_path:
                raise WorkerPolicyDenied("plugin write is outside its temporary/audit roots")
        elif not _inside(path, read_roots) and path.resolve() not in {
            progress_path,
        }:
            raise WorkerPolicyDenied("plugin read is outside its approved roots")

    def audit(event: str, args: tuple[object, ...]) -> None:
        if event == "open" and args:
            mode = args[1] if len(args) > 1 else "r"
            flags = args[2] if len(args) > 2 else 0
            write = (isinstance(mode, str) and any(character in mode for character in "wax+")) or (
                isinstance(flags, int)
                and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            )
            check_path(args[0], write=write)
        elif event in {"os.listdir", "os.scandir", "os.chdir"} and args:
            check_path(args[0], write=False)
        elif (
            event
            in {
                "os.remove",
                "os.rmdir",
                "os.mkdir",
                "os.chmod",
                "os.chown",
                "os.truncate",
                "os.utime",
            }
            and args
        ):
            check_path(args[0], write=True)
        elif event in {"os.rename", "os.replace"} and len(args) >= 2:
            check_path(args[0], write=True)
            check_path(args[1], write=True)
        elif event == "os.link" and len(args) >= 2:
            check_path(args[0], write=False)
            check_path(args[1], write=True)
        elif event == "os.symlink" and len(args) >= 2:
            check_path(args[1], write=True)

    sys.addaudithook(audit)


def _context(params: dict[str, Any], temp_root: Path) -> tuple[RuntimeContext, dict[str, RuntimeInput]]:
    raw_context = params["context"]
    raw_snapshot = raw_context["snapshot"]
    runs_root = _environment_path("ARGUS_PLUGIN_RUNS_ROOT")
    snapshot_root = (runs_root / "_data" / "snapshots" / str(raw_snapshot["id"]) / "source").resolve()
    snapshot = SourceSnapshot.model_validate(
        {
            **raw_snapshot,
            "repository_path": "[isolated]",
            "materialized_path": str(snapshot_root),
        }
    )
    scan = Scan.model_validate(raw_context["scan"])
    task = Task.model_validate(raw_context["task"])
    workspace = str(raw_context["workspace"])
    artifact_store = ArtifactStore(runs_root)
    raw_artifacts = {
        capability: Artifact.model_validate(raw_input["artifact"]) for capability, raw_input in params["inputs"].items()
    }
    artifact_paths = tuple(
        (
            runs_root / "_data" / "artifacts" / "sha256" / artifact.content_hash[:2] / artifact.content_hash / "payload"
        ).resolve()
        for artifact in raw_artifacts.values()
    )
    _install_filesystem_policy(
        snapshot_root,
        temp_root,
        workspace,
        artifact_paths,
    )
    inputs: dict[str, RuntimeInput] = {}
    for capability, artifact in raw_artifacts.items():
        inputs[capability] = RuntimeInput(
            capability=capability,
            artifact=artifact,
            payload=artifact_store.read_bytes(
                artifact.content_hash,
                expected_size=artifact.size_bytes,
            ),
        )
    return (
        RuntimeContext(
            scan=scan,
            snapshot=snapshot,
            task=task,
            repositories=cast(Repositories, _DeniedRepositories()),
            artifact_store=artifact_store,
            runs_root=runs_root,
            workspace=workspace,
            attempt_id=UUID(str(raw_context["attempt_id"])),
            input_hashes={str(key): str(value) for key, value in raw_context["input_hashes"].items()},
            temp_dir=temp_root,
        ),
        inputs,
    )


def _stage_outputs(outputs: object, temp_root: Path) -> list[dict[str, Any]]:
    if not isinstance(outputs, list) or any(not isinstance(item, RuntimeOutput) for item in outputs):
        raise TypeError("plugin returned an invalid RuntimeOutput list")
    output_root = temp_root / "outputs"
    output_root.mkdir()
    limit = int(os.environ["ARGUS_PLUGIN_MAX_OUTPUT_BYTES"])
    total = 0
    protected_values = [
        value.encode()
        for key, value in os.environ.items()
        if (key.endswith(("_API_KEY", "_TOKEN", "_PASSWORD", "_SECRET")) and value)
    ]
    references: list[dict[str, Any]] = []
    for output in outputs:
        reference = uuid4().hex
        destination = output_root / reference
        if output.json_value is not None:
            payload = encode_json(output.json_value)
            representation = "json"
        elif output.payload is not None:
            payload = output.payload
            representation = "payload"
        elif output.source_path is not None:
            source = output.source_path.resolve()
            if not source.is_relative_to(temp_root):
                raise WorkerPolicyDenied("plugin source_path output must be inside its temporary root")
            payload = source.read_bytes()
            representation = "source"
        else:
            raise TypeError("plugin output has no representation")
        total += len(payload)
        if total > limit:
            raise WorkerPolicyDenied("plugin outputs exceed the configured byte limit")
        if any(secret in payload for secret in protected_values):
            raise WorkerPolicyDenied("plugin output contains protected secret material")
        destination.write_bytes(payload)
        output_reference = {
            "reference": reference,
            "content_hash": hashlib.sha256(payload).hexdigest(),
            "representation": representation,
            "capability": output.capability,
            "artifact_type": output.artifact_type,
            "schema_version": output.schema_version,
            "media_type": output.media_type,
            "metadata": output.metadata,
            "artifact_id": (str(output.artifact_id) if output.artifact_id is not None else None),
            "static_findings": [finding.model_dump(mode="json") for finding in output.static_findings],
        }
        encoded_reference = json.dumps(
            output_reference,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        if any(secret in encoded_reference for secret in protected_values):
            raise WorkerPolicyDenied("plugin output metadata contains protected secret material")
        references.append(output_reference)
    return references


def _execute(request: dict[str, Any]) -> dict[str, Any]:
    if (
        request.get("jsonrpc") != "2.0"
        or request.get("method") != "plugin.execute"
        or not isinstance(request.get("params"), dict)
    ):
        raise ValueError("invalid JSON-RPC request")
    params = request["params"]
    plugin = params["plugin"]
    temp_root = _environment_path("ARGUS_PLUGIN_TEMP_ROOT")
    context, inputs = _context(params, temp_root)
    plugin_root = os.environ.get("ARGUS_PLUGIN_ROOT")
    if plugin_root:
        sys.path.insert(0, plugin_root)
    module_name, object_name = str(plugin["entrypoint"]).split(":", maxsplit=1)
    with redirect_stdout(sys.stderr):
        module = importlib.import_module(module_name)
        runtime = getattr(module, object_name)
        if not callable(runtime):
            raise TypeError("plugin entrypoint is not callable")
        outputs = runtime(context, inputs)
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {"outputs": _stage_outputs(outputs, temp_root)},
    }


def main() -> int:
    original_stdout = sys.stdout
    try:
        _apply_resource_limits()
        request = json.loads(sys.stdin.buffer.read())
        _restrict_network()
        _restrict_subprocess()
        response = _execute(request)
    except BaseException as exc:
        if isinstance(exc, WorkerPolicyDenied):
            error_code = "POLICY_DENIED"
        elif isinstance(exc, MemoryError):
            error_code = "RESOURCE_LIMIT"
        elif isinstance(exc, (TypeError, ValueError)):
            error_code = "INVALID_OUTPUT"
        else:
            error_code = "PLUGIN_FAILED"
        response = {
            "jsonrpc": "2.0",
            "id": locals().get("request", {}).get("id"),
            "error": {
                "code": error_code,
                "message": "plugin execution failed",
            },
        }
    original_stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    original_stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
