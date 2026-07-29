"""Load one runtime, validate outputs, then publish immutable Artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3
from collections.abc import Sequence
from typing import cast

from pydantic import JsonValue, TypeAdapter, ValidationError

from argus.artifacts.codecs import encode_json
from argus.domain.errors import ArgusV2Error
from argus.domain.models import Artifact, StaticFindingV2
from uuid import uuid4
from argus.execution.contracts import (
    PluginRuntime,
    RuntimeContext,
    RuntimeInput,
    RuntimeOutput,
)
from argus.plugins.contracts import CapabilityDeclaration
from argus.plugins.loader import load_entrypoint
from argus.plugins.process_runtime import ProcessPluginRunner
from argus.plugins.contracts import IsolationMode
from argus.plugins.registry import PluginRegistry

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class PluginExecutionError(ArgusV2Error):
    pass


class PluginOutputError(PluginExecutionError):
    pass


class PluginRunner:
    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry
        self.process_runner = ProcessPluginRunner()

    def run(
        self,
        context: RuntimeContext,
        inputs: dict[str, RuntimeInput],
    ) -> list[RuntimeOutput]:
        registered = self.registry.require(context.task.plugin_id)
        if registered.spec.version != context.task.plugin_version:
            raise PluginExecutionError(
                f"task pins {context.task.plugin_id}@{context.task.plugin_version}, "
                f"registry has {registered.spec.version}"
            )
        if registered.spec.runtime.isolation is IsolationMode.PROCESS:
            outputs = self.process_runner.run(registered, context, inputs)
        else:
            loaded = load_entrypoint(self.registry, context.task.plugin_id)
            if not callable(loaded):
                raise PluginExecutionError(f"entrypoint for {context.task.plugin_id!r} is not callable")
            runtime = cast(PluginRuntime, loaded)
            outputs = runtime(context, inputs)
        if not isinstance(outputs, list) or any(not isinstance(item, RuntimeOutput) for item in outputs):
            raise PluginOutputError(f"plugin {context.task.plugin_id!r} returned an invalid output list")
        self._validate(
            context,
            registered.spec.produces,
            registered.spec.output_schemas,
            outputs,
        )
        return outputs

    @staticmethod
    def _validate(
        context: RuntimeContext,
        declarations: Sequence[CapabilityDeclaration],
        output_schemas: dict[str, JsonValue],
        outputs: list[RuntimeOutput],
    ) -> None:
        task = context.task
        declared = {item.capability: item for item in declarations}
        actual = [item.capability for item in outputs]
        primary = {item.capability for item in declarations if not item.supplemental}
        if primary != set(task.expected_capabilities):
            raise PluginOutputError("task expectations do not match primary Manifest outputs")
        actual_primary = [capability for capability in actual if capability in primary]
        if set(actual_primary) != primary or len(actual_primary) != len(primary):
            raise PluginOutputError(
                f"plugin primary outputs {sorted(actual_primary)} do not "
                f"match task expectation {sorted(task.expected_capabilities)}"
            )
        unknown = set(actual) - set(declared)
        if unknown:
            raise PluginOutputError(f"plugin returned undeclared capabilities {sorted(unknown)}")
        duplicate_primary = {capability for capability in primary if actual.count(capability) != 1}
        if duplicate_primary:
            raise PluginOutputError(f"plugin returned duplicate primary capabilities {sorted(duplicate_primary)}")
        artifact_ids = [output.artifact_id for output in outputs if output.artifact_id is not None]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise PluginOutputError("plugin returned duplicate Artifact IDs")
        for output in outputs:
            declaration = declared.get(output.capability)
            if declaration is None:
                raise PluginOutputError(f"undeclared output capability {output.capability!r}")
            if output.artifact_type != declaration.artifact_type or output.schema_version != declaration.schema_version:
                raise PluginOutputError(f"output schema mismatch for {output.capability!r}")
            representations = [
                output.payload is not None,
                output.source_path is not None,
                output.json_value is not None,
            ]
            if sum(representations) != 1:
                raise PluginOutputError(f"output {output.capability!r} must have exactly one payload")
            if output.cleanup_source and output.source_path is None:
                raise PluginOutputError(f"output {output.capability!r} can only clean up a source_path payload")
            if output.json_value is not None:
                try:
                    json_value = _JSON.validate_python(output.json_value)
                except ValidationError as exc:
                    raise PluginOutputError(f"output {output.capability!r} is not JSON-compatible") from exc
                schema = output_schemas.get(output.capability)
                if schema is not None:
                    _validate_json_schema(
                        json_value,
                        schema,
                        path=output.capability,
                    )
            if output.source_path is not None:
                if not output.source_path.is_file():
                    raise PluginOutputError(f"output file is missing: {output.source_path}")
                if output.media_type == "application/vnd.sqlite3":
                    try:
                        connection = sqlite3.connect(
                            f"file:{output.source_path}?mode=ro",
                            uri=True,
                        )
                        connection.execute("PRAGMA schema_version").fetchone()
                        connection.close()
                    except sqlite3.DatabaseError as exc:
                        raise PluginOutputError(
                            f"output is not a readable SQLite database: {output.source_path}"
                        ) from exc
            if output.payload is not None and output.media_type == "application/json":
                try:
                    json_value = _JSON.validate_python(json.loads(output.payload))
                except (json.JSONDecodeError, ValidationError) as exc:
                    raise PluginOutputError(f"output {output.capability!r} is not valid JSON") from exc
                schema = output_schemas.get(output.capability)
                if schema is not None:
                    _validate_json_schema(
                        json_value,
                        schema,
                        path=output.capability,
                    )
            workspace_view = output.metadata.get("workspace_view")
            if workspace_view is not None and (
                not isinstance(workspace_view, str)
                or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.-]*",
                    workspace_view,
                )
                is None
            ):
                raise PluginOutputError(f"invalid compatibility workspace filename: {workspace_view!r}")
            if output.static_findings:
                if output.artifact_type != "finding.static.v2":
                    raise PluginOutputError("StaticFindingV2 records require artifactType 'finding.static.v2'")
                if output.json_value is None:
                    raise PluginOutputError("StaticFindingV2 records require a JSON payload")
                expected_findings = [finding.model_dump(mode="json") for finding in output.static_findings]
                if output.json_value != expected_findings:
                    raise PluginOutputError("StaticFindingV2 records differ from the JSON payload")
                for finding in output.static_findings:
                    if finding.scan_id != context.scan.id or finding.snapshot_id != context.snapshot.id:
                        raise PluginOutputError("StaticFindingV2 belongs to a different Scan or SourceSnapshot")


def _validate_json_schema(
    value: JsonValue,
    schema: JsonValue,
    *,
    path: str,
) -> None:
    """Validate the strict JSON-Schema subset accepted by the M4 local runtime."""
    if isinstance(schema, bool):
        if not schema:
            raise PluginOutputError(f"{path} is rejected by its output schema")
        return
    if not isinstance(schema, dict):
        raise PluginOutputError(f"output schema for {path} must be an object or boolean")
    supported = {
        "$schema",
        "title",
        "description",
        "type",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
    }
    unsupported = set(schema) - supported
    if unsupported:
        raise PluginOutputError(f"unsupported output schema keywords for {path}: {sorted(unsupported)}")
    expected_type = schema.get("type")
    if expected_type is not None:
        names = (
            [expected_type]
            if isinstance(expected_type, str)
            else expected_type
            if isinstance(expected_type, list)
            else []
        )
        checks = {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "null": value is None,
        }
        if not names or not any(checks.get(str(name), False) for name in names):
            raise PluginOutputError(f"{path} does not match output schema type {expected_type!r}")
    choices = schema.get("enum")
    if choices is not None:
        if not isinstance(choices, list) or value not in choices:
            raise PluginOutputError(f"{path} is not in the declared enum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            raise PluginOutputError(f"{path}.required must be a string array")
        missing = [item for item in required if item not in value]
        if missing:
            raise PluginOutputError(f"{path} is missing required fields {missing}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise PluginOutputError(f"{path}.properties must be an object")
        for key, child_schema in properties.items():
            if key in value:
                _validate_json_schema(
                    value[key],
                    child_schema,
                    path=f"{path}.{key}",
                )
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise PluginOutputError(f"{path} has undeclared fields {sorted(extra)}")
    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            raise PluginOutputError(f"{path} has fewer than {minimum} items")
        if isinstance(maximum, int) and len(value) > maximum:
            raise PluginOutputError(f"{path} has more than {maximum} items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                _validate_json_schema(
                    item,
                    item_schema,
                    path=f"{path}[{index}]",
                )
    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise PluginOutputError(f"{path} is shorter than {minimum}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise PluginOutputError(f"{path} is longer than {maximum}")


def publish_outputs(
    context: RuntimeContext,
    outputs: list[RuntimeOutput],
) -> list[Artifact]:
    artifacts: list[Artifact] = []
    findings: list[StaticFindingV2] = []
    for output in outputs:
        metadata = dict(output.metadata)
        metadata["attempt_id"] = str(context.attempt_id)
        metadata["config_hash"] = context.task.config_hash
        metadata["input_hashes"] = cast(JsonValue, context.input_hashes)
        metadata["task_cache_key"] = context.task.cache_key
        if output.source_path is not None:
            try:
                blob = context.artifact_store.put_file(output.source_path)
            finally:
                if output.cleanup_source:
                    output.source_path.unlink(missing_ok=True)
        elif output.json_value is not None:
            blob = context.artifact_store.put_bytes(encode_json(output.json_value))
        else:
            blob = context.artifact_store.put_bytes(output.payload or b"")
        artifacts.append(
            Artifact(
                id=output.artifact_id or uuid4(),
                scan_id=context.scan.id,
                snapshot_id=context.snapshot.id,
                task_id=context.task.id,
                artifact_type=output.artifact_type,
                schema_version=output.schema_version,
                capabilities=[output.capability],
                producer_plugin_id=context.task.plugin_id,
                producer_plugin_version=context.task.plugin_version,
                media_type=output.media_type,
                content_hash=blob.content_hash,
                size_bytes=blob.size_bytes,
                storage_uri=blob.storage_uri,
                metadata=metadata,
            )
        )
        findings.extend(output.static_findings)
    artifact_ids = {artifact.id for artifact in artifacts}
    for finding in findings:
        if finding.graph_slice_artifact_id is not None and finding.graph_slice_artifact_id not in artifact_ids:
            raise PluginOutputError("StaticFindingV2 references a Graph Slice outside its atomic Artifact batch")
        missing_evidence = set(finding.evidence_artifact_ids) - artifact_ids
        if missing_evidence:
            raise PluginOutputError(
                "StaticFindingV2 references evidence outside its atomic "
                f"Artifact batch: {sorted(map(str, missing_evidence))}"
            )
    committed = context.repositories.artifacts.create_many(
        artifacts,
        findings=findings,
    )
    project_workspace_views(context, committed)
    return committed


def project_workspace_views(
    context: RuntimeContext,
    artifacts: Sequence[Artifact],
) -> None:
    for artifact in artifacts:
        filename = artifact.metadata.get("workspace_view")
        if filename is None:
            continue
        if (
            not isinstance(filename, str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*",
                filename,
            )
            is None
        ):
            raise PluginOutputError(f"invalid compatibility workspace filename: {filename!r}")
        destination = Path(context.runs_root) / context.workspace / filename
        context.artifact_store.materialize(
            artifact.content_hash,
            destination,
            expected_size=artifact.size_bytes,
        )
