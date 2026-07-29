"""M4 runtime adapters for V1 analyzers and deterministic legacy views."""

from __future__ import annotations

import json
import os
from enum import Enum
from pathlib import Path
import shutil
from typing import Any, cast

from pydantic import JsonValue, TypeAdapter

from argus.contracts import (
    AnalysisContext,
    ArgusState,
    Finding,
    LLMClient,
    SourceAccess,
    SourceMode,
)
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput
from argus.graph.build import build_graph
from argus.graph.codegraph import CodegraphHandle
from argus.llm.client import (
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MODEL,
    AuditedLLM,
    load_llm_environment,
)
from argus.llm.audit import AuditLevel
from argus.orchestration.registry import discover_analyzers
from argus.plugins.legacy_adapter import (
    ENRICHMENT_AGGREGATE,
    ENRICHMENT_REVIEWED,
    FINDINGS_AGGREGATE,
    FINDINGS_REVIEWED,
    GRAPH_CAPABILITY,
    REPORT_CAPABILITY,
)
from argus.reporting.report import render_report
from argus.source import strip_source

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class FileSourceAccess:
    def __init__(self, repository_path: str, mode: SourceMode) -> None:
        self.repository_path = repository_path
        self.mode = mode

    def read(
        self,
        path: str,
        start: int | None = None,
        end: int | None = None,
    ) -> str:
        absolute = path if os.path.isabs(path) else os.path.join(self.repository_path, path)
        with open(absolute, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        if self.mode is SourceMode.STRIPPED:
            text = strip_source(path, text)
        lines = text.splitlines(keepends=True)
        low = (start - 1) if start else 0
        high = end if end else len(lines)
        return "".join(lines[low:high])


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    return str(value)


def _json_value(value: object) -> JsonValue:
    normalized = json.loads(json.dumps(value, default=_json_default, ensure_ascii=False))
    return _JSON.validate_python(normalized)


def _read_json(input_artifact: RuntimeInput) -> JsonValue:
    return _JSON.validate_json(input_artifact.payload)


def _ordered_inputs(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[tuple[str, RuntimeInput]]:
    return sorted(
        inputs.items(),
        key=lambda item: (
            item[1].artifact.created_at,
            item[1].artifact.producer_plugin_id,
            item[0],
        ),
    )


def _source_mode(config: dict[str, JsonValue]) -> SourceMode:
    raw = config.get("source_mode", SourceMode.RAW.value)
    try:
        return SourceMode(str(raw))
    except ValueError as exc:
        raise ValueError(f"invalid source_mode: {raw!r}") from exc


def _audit_level(config: dict[str, JsonValue]) -> AuditLevel:
    llm = config.get("llm")
    raw = llm.get("auditLevel", AuditLevel.REDACTED.value) if isinstance(llm, dict) else AuditLevel.REDACTED.value
    try:
        return AuditLevel(str(raw))
    except ValueError as exc:
        raise ValueError(f"invalid llm.auditLevel: {raw!r}") from exc


def _graph_path(context: RuntimeContext, graph_input: RuntimeInput) -> Path:
    graph_path = context.temp_dir / "codegraph" / "codegraph.db"
    context.artifact_store.materialize(
        graph_input.artifact.content_hash,
        graph_path,
        expected_size=graph_input.artifact.size_bytes,
    )
    return graph_path


def graph_provider_runtime(
    context: RuntimeContext,
    _inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    source_copy = context.temp_dir / "source"
    shutil.copytree(
        context.snapshot.materialized_path,
        source_copy,
        symlinks=True,
    )
    for path in source_copy.rglob("*"):
        if path.is_symlink() and not path.resolve().is_relative_to(source_copy):
            raise RuntimeError(f"snapshot symlink escapes source root: {path.relative_to(source_copy)}")
    path = Path(build_graph(str(source_copy)))
    return [
        RuntimeOutput(
            capability=GRAPH_CAPABILITY,
            artifact_type="code.graph.codegraph",
            schema_version="1.0",
            media_type="application/vnd.sqlite3",
            source_path=path,
        )
    ]


def legacy_analyzer_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    name = context.task.plugin_id.removeprefix("legacy.analyzer.")
    analyzers = discover_analyzers()
    analyzer = analyzers.get(name)
    if analyzer is None:
        raise RuntimeError(f"legacy analyzer is no longer available: {name}")
    graph_input = inputs[GRAPH_CAPABILITY]
    graph_path = _graph_path(context, graph_input)
    enriched: dict[str, Any] = {}
    enrichment_input = inputs.get(ENRICHMENT_REVIEWED)
    if enrichment_input is not None:
        enrichment_value = _read_json(enrichment_input)
        if not isinstance(enrichment_value, dict):
            raise TypeError("legacy enrichment aggregate must be a JSON object")
        enriched = enrichment_value
    load_llm_environment()
    llm: LLMClient = AuditedLLM(
        api_key=os.environ.get(ENV_API_KEY, ""),
        base_url=os.environ.get(ENV_BASE_URL, ""),
        model=os.environ.get(ENV_MODEL, ""),
        workspace=context.workspace,
        runs_root=str(context.runs_root),
        audit_level=_audit_level(context.scan.config),
    )
    source: SourceAccess = FileSourceAccess(
        context.snapshot.materialized_path,
        _source_mode(context.scan.config),
    )
    analysis_context: AnalysisContext = {
        "graph": CodegraphHandle(str(graph_path)),
        "enriched": enriched,
        "source": source,
        "config": cast(dict[str, Any], context.scan.config),
        "llm": llm,
        "workspace": context.workspace,
    }
    result = analyzer.run(analysis_context)
    if analyzer.phase.value == "enrichment":
        capability = f"legacy.enrichment.{name}.v1"
        result_value: object = result.get("enrichment", {})
        artifact_type = f"legacy.enrichment.{name}"
    else:
        capability = f"legacy.findings.{name}.v1"
        result_value = result.get("findings", [])
        artifact_type = f"legacy.findings.{name}"
    return [
        RuntimeOutput(
            capability=capability,
            artifact_type=artifact_type,
            schema_version="1.0",
            media_type="application/json",
            json_value=_json_value(result_value),
        )
    ]


def legacy_enrichment_aggregate_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    merged: dict[str, JsonValue] = {}
    for capability, input_artifact in _ordered_inputs(context, inputs):
        if not capability.startswith("legacy.enrichment.") or capability in {
            ENRICHMENT_AGGREGATE,
            ENRICHMENT_REVIEWED,
        }:
            continue
        value = _read_json(input_artifact)
        if not isinstance(value, dict):
            raise TypeError(f"{capability} must contain a JSON object")
        merged.update(value)
    return [
        RuntimeOutput(
            capability=ENRICHMENT_AGGREGATE,
            artifact_type="legacy.enrichment.aggregate",
            schema_version="1.0",
            media_type="application/json",
            json_value=merged,
            metadata={"workspace_view": "enriched-graph.json"},
        )
    ]


def legacy_findings_aggregate_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    findings: list[JsonValue] = []
    mode = context.scan.config.get("analysisMode", "legacy")
    static_capabilities = set(inputs)
    for capability, input_artifact in _ordered_inputs(context, inputs):
        if mode == "compare" and (
            (capability == "legacy.findings.injection.v1" and "finding.static.injection.v2" in static_capabilities)
            or (capability == "legacy.findings.authz.v1" and "finding.static.authorization.v2" in static_capabilities)
        ):
            continue
        if capability.startswith("finding.static.") and capability.endswith(".v2"):
            value = _read_json(input_artifact)
            if not isinstance(value, list):
                raise TypeError(f"{capability} must contain a JSON array")
            findings.extend(_static_finding_compat(item) for item in value if isinstance(item, dict))
            continue
        if not capability.startswith("legacy.findings.") or capability in {
            FINDINGS_AGGREGATE,
            FINDINGS_REVIEWED,
        }:
            continue
        value = _read_json(input_artifact)
        if not isinstance(value, list):
            raise TypeError(f"{capability} must contain a JSON array")
        findings.extend(value)
    return [
        RuntimeOutput(
            capability=FINDINGS_AGGREGATE,
            artifact_type="legacy.findings.aggregate",
            schema_version="1.0",
            media_type="application/json",
            json_value=findings,
            metadata={"workspace_view": "findings.json"},
        )
    ]


def _static_finding_compat(value: dict[str, JsonValue]) -> JsonValue:
    static_confidence = str(value.get("static_confidence", "low"))
    status = str(value.get("status", "unverified"))
    source_ids = _json_string_list(value.get("source_node_ids"))
    sink_ids = _json_string_list(value.get("sink_node_ids"))
    evidence_ids = _json_string_list(value.get("evidence_artifact_ids"))
    return {
        "id": str(value.get("id", "")),
        "analyzer": f"v2:{value.get('rule_id', 'unknown')}",
        "vuln_class": str(value.get("vuln_class", "unknown")),
        "title": str(value.get("title", "Untitled static finding")),
        "severity": str(value.get("severity", "info")),
        "confidence": static_confidence,
        "static_confidence": static_confidence,
        "verification_status": status,
        "locations": (value.get("locations") if isinstance(value.get("locations"), list) else []),
        "data_flow": (
            " → ".join(
                [
                    *source_ids,
                    *sink_ids,
                ]
            )
        ),
        "rationale": str(value.get("rationale", "")),
        "evidence": ("Static evidence Artifacts: " + ", ".join(evidence_ids)),
        "remediation": str(value.get("remediation", "")),
        "fingerprint": str(value.get("fingerprint", "")),
        "root_cause_key": value.get("root_cause_key"),
    }


def _json_string_list(value: JsonValue | None) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def review_gate_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    if len(inputs) != 1 or len(context.task.expected_capabilities) != 1:
        raise RuntimeError("review gate requires exactly one input and one output")
    source = next(iter(inputs.values()))
    capability = context.task.expected_capabilities[0]
    artifact_type = capability.removesuffix(".v1")
    return [
        RuntimeOutput(
            capability=capability,
            artifact_type=artifact_type,
            schema_version="1.0",
            media_type=source.artifact.media_type,
            payload=source.payload,
            metadata={
                "reviewed_subject_artifact_id": str(source.artifact.id),
                "reviewed_subject_hash": source.artifact.content_hash,
            },
        )
    ]


def reporter_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    value = _read_json(inputs[FINDINGS_REVIEWED])
    if not isinstance(value, list):
        raise TypeError("reviewed findings must contain a JSON array")
    state = cast(
        ArgusState,
        {
            "repo_path": context.snapshot.materialized_path,
            "workspace": context.workspace,
            "config": context.scan.config,
            "source_mode": _source_mode(context.scan.config),
            "graph_db_path": str(context.temp_dir / "codegraph" / "codegraph.db"),
            "enriched_graph_path": str(context.runs_root / context.workspace / "enriched-graph.json"),
            "findings_path": str(context.runs_root / context.workspace / "findings.json"),
            "report_path": str(context.runs_root / context.workspace / "report.md"),
            "enriched": {},
            "findings": value,
            "completed_nodes": [],
        },
    )
    markdown = render_report(cast(list[Finding], value), state)
    return [
        RuntimeOutput(
            capability=REPORT_CAPABILITY,
            artifact_type="report.markdown",
            schema_version="1.0",
            media_type="text/markdown",
            payload=markdown.encode("utf-8"),
            metadata={"workspace_view": "report.md"},
        )
    ]
