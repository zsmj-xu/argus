"""Runtime orchestration for one candidate-driven detection rule."""

from __future__ import annotations

from dataclasses import dataclass
import os
from uuid import UUID, uuid4

from pydantic import JsonValue

from argus.contracts import LLMClient, SourceMode
from argus.detection.candidates import (
    BoundedGraphSliceBuilder,
    SourceContextBuilder,
)
from argus.detection.contracts import (
    CandidateProvider,
    DetectionContext,
    ExpertAssessment,
    SourceContext,
)
from argus.detection.deduplication import deduplicate_findings
from argus.detection.experts import StrictExpertEvaluator
from argus.detection.normalization import StaticFindingNormalizer
from argus.execution.contracts import (
    RuntimeContext,
    RuntimeInput,
    RuntimeOutput,
)
from argus.graph.codegraph import CodegraphHandle
from argus.llm.client import (
    DEFAULT_MAX_TOKENS,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MODEL,
    AuditedLLM,
    load_llm_environment,
)
from argus.llm.audit import AuditLevel
from argus.plugins.legacy_adapter import GRAPH_CAPABILITY
from argus.plugins.legacy_runtime import FileSourceAccess
from argus.security_ir.business_flow_adapter import SECURITY_GRAPH_CAPABILITY
from argus.security_ir.models import GraphSlice
from argus.security_ir.query import SecurityGraphQuery
from argus.security_ir.store import SecurityGraphStore


@dataclass(frozen=True)
class DetectionRuleRuntime:
    rule_name: str
    provider: CandidateProvider
    rule_instructions: str

    @property
    def candidate_capability(self) -> str:
        return f"candidate.{self.rule_name}.v1"

    @property
    def candidate_index_capability(self) -> str:
        return f"candidate.{self.rule_name}.index.v1"

    @property
    def slice_capability(self) -> str:
        return f"graph.slice.{self.rule_name}.v1"

    @property
    def slice_index_capability(self) -> str:
        return f"graph.slice.{self.rule_name}.index.v1"

    @property
    def source_capability(self) -> str:
        return f"source.context.{self.rule_name}.v1"

    @property
    def source_index_capability(self) -> str:
        return f"source.context.{self.rule_name}.index.v1"

    @property
    def assessment_capability(self) -> str:
        return f"assessment.{self.rule_name}.v1"

    @property
    def assessment_index_capability(self) -> str:
        return f"assessment.{self.rule_name}.index.v1"

    @property
    def finding_capability(self) -> str:
        return f"finding.static.{self.rule_name}.v2"


def _source_mode(config: dict[str, JsonValue]) -> SourceMode:
    raw = config.get("source_mode", SourceMode.RAW.value)
    try:
        return SourceMode(str(raw))
    except ValueError as exc:
        raise ValueError(f"invalid source_mode: {raw!r}") from exc


def _build_llm(context: RuntimeContext) -> LLMClient:
    load_llm_environment()
    return AuditedLLM(
        api_key=os.environ.get(ENV_API_KEY, ""),
        base_url=os.environ.get(ENV_BASE_URL, ""),
        model=os.environ.get(ENV_MODEL, ""),
        workspace=context.workspace,
        runs_root=str(context.runs_root),
        audit_level=_audit_level(context.scan.config),
    )


def _audit_level(config: dict[str, JsonValue]) -> AuditLevel:
    llm = config.get("llm")
    raw = llm.get("auditLevel", AuditLevel.REDACTED.value) if isinstance(llm, dict) else AuditLevel.REDACTED.value
    try:
        return AuditLevel(str(raw))
    except ValueError as exc:
        raise ValueError(f"invalid llm.auditLevel: {raw!r}") from exc


def _expert_max_tokens(config: dict[str, JsonValue]) -> int:
    detection = config.get("detection")
    value = detection.get("expertMaxTokens") if isinstance(detection, dict) else None
    if isinstance(value, int) and not isinstance(value, bool) and 1_024 <= value <= 65_536:
        return value
    return DEFAULT_MAX_TOKENS


def _detection_context(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> DetectionContext:
    graph_input = inputs[GRAPH_CAPABILITY]
    graph_path = context.temp_dir / "codegraph" / "codegraph.db"
    context.artifact_store.materialize(
        graph_input.artifact.content_hash,
        graph_path,
        expected_size=graph_input.artifact.size_bytes,
    )
    security_query: SecurityGraphQuery | None = None
    security_input = inputs.get(SECURITY_GRAPH_CAPABILITY)
    if security_input is not None:
        security_path = context.artifact_store.verified_path(
            security_input.artifact.content_hash,
            expected_size=security_input.artifact.size_bytes,
        )
        security_query = SecurityGraphQuery(SecurityGraphStore(security_path))
    source_ids = tuple(
        sorted(
            {item.artifact.id for item in inputs.values()},
            key=str,
        )
    )
    return DetectionContext(
        scan=context.scan,
        snapshot=context.snapshot,
        plugin_id=context.task.plugin_id,
        plugin_version=context.task.plugin_version,
        source_artifact_ids=source_ids,
        codegraph=CodegraphHandle(str(graph_path)),
        security_graph=security_query,
        source=FileSourceAccess(
            context.snapshot.materialized_path,
            _source_mode(context.scan.config),
        ),
        config=context.scan.config,
    )


def _record_output(
    *,
    capability: str,
    artifact_type: str,
    value: JsonValue,
    artifact_id: UUID,
    record_id: str,
) -> RuntimeOutput:
    return RuntimeOutput(
        capability=capability,
        artifact_type=artifact_type,
        schema_version="1.0",
        media_type="application/json",
        json_value=value,
        artifact_id=artifact_id,
        metadata={
            "record_id": record_id,
            "cache_scope": "scan",
        },
    )


def run_detection_rule(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
    rule: DetectionRuleRuntime,
) -> list[RuntimeOutput]:
    detection_context = _detection_context(context, inputs)
    candidates = rule.provider.generate(detection_context)
    slice_builder = BoundedGraphSliceBuilder()
    source_builder = SourceContextBuilder()
    evaluator = (
        StrictExpertEvaluator(
            _build_llm(context),
            rule_instructions=rule.rule_instructions,
            max_tokens=_expert_max_tokens(context.scan.config),
        )
        if candidates
        else None
    )
    normalizer = StaticFindingNormalizer()

    outputs: list[RuntimeOutput] = []
    candidate_index: list[JsonValue] = []
    slice_index: list[JsonValue] = []
    source_index: list[JsonValue] = []
    assessment_index: list[JsonValue] = []
    findings = []
    for candidate in candidates:
        candidate_artifact_id = uuid4()
        slice_artifact_id = uuid4()
        source_artifact_id = uuid4()
        assessment_artifact_id = uuid4()
        graph_slice: GraphSlice = slice_builder.build(
            detection_context,
            candidate,
        )
        source_context: SourceContext = source_builder.build(
            detection_context,
            candidate,
            graph_slice,
        )
        assert evaluator is not None
        assessment: ExpertAssessment = evaluator.evaluate(
            candidate,
            graph_slice,
            source_context,
        )
        candidate_index.append(
            {
                "candidate_id": candidate.id,
                "artifact_id": str(candidate_artifact_id),
                "record": candidate.model_dump(mode="json"),
            }
        )
        slice_index.append(
            {
                "candidate_id": candidate.id,
                "artifact_id": str(slice_artifact_id),
                "record": graph_slice.model_dump(mode="json"),
            }
        )
        source_index.append(
            {
                "candidate_id": candidate.id,
                "artifact_id": str(source_artifact_id),
                "record": source_context.model_dump(mode="json"),
            }
        )
        assessment_index.append(
            {
                "candidate_id": candidate.id,
                "artifact_id": str(assessment_artifact_id),
                "record": assessment.model_dump(mode="json"),
            }
        )
        outputs.extend(
            [
                _record_output(
                    capability=rule.candidate_capability,
                    artifact_type="candidate.static.v1",
                    value=candidate.model_dump(mode="json"),
                    artifact_id=candidate_artifact_id,
                    record_id=candidate.id,
                ),
                _record_output(
                    capability=rule.slice_capability,
                    artifact_type="graph.slice.v1",
                    value=graph_slice.model_dump(mode="json"),
                    artifact_id=slice_artifact_id,
                    record_id=candidate.id,
                ),
                _record_output(
                    capability=rule.source_capability,
                    artifact_type="source.context.v1",
                    value=source_context.model_dump(mode="json"),
                    artifact_id=source_artifact_id,
                    record_id=candidate.id,
                ),
                _record_output(
                    capability=rule.assessment_capability,
                    artifact_type="assessment.static.v1",
                    value=assessment.model_dump(mode="json"),
                    artifact_id=assessment_artifact_id,
                    record_id=assessment.id,
                ),
            ]
        )
        if assessment.supported:
            findings.append(
                normalizer.normalize(
                    detection_context,
                    candidate,
                    assessment,
                    graph_slice,
                    graph_slice_artifact_id=slice_artifact_id,
                    evidence_artifact_ids=[
                        candidate_artifact_id,
                        slice_artifact_id,
                        source_artifact_id,
                        assessment_artifact_id,
                    ],
                )
            )
    normalized_findings = deduplicate_findings(findings)
    outputs.extend(
        [
            RuntimeOutput(
                capability=rule.candidate_index_capability,
                artifact_type="candidate.index.v1",
                schema_version="1.0",
                media_type="application/json",
                json_value=candidate_index,
                metadata={"cache_scope": "scan"},
            ),
            RuntimeOutput(
                capability=rule.slice_index_capability,
                artifact_type="graph.slice.index.v1",
                schema_version="1.0",
                media_type="application/json",
                json_value=slice_index,
                metadata={"cache_scope": "scan"},
            ),
            RuntimeOutput(
                capability=rule.source_index_capability,
                artifact_type="source.context.index.v1",
                schema_version="1.0",
                media_type="application/json",
                json_value=source_index,
                metadata={"cache_scope": "scan"},
            ),
            RuntimeOutput(
                capability=rule.assessment_index_capability,
                artifact_type="assessment.index.v1",
                schema_version="1.0",
                media_type="application/json",
                json_value=assessment_index,
                metadata={"cache_scope": "scan"},
            ),
            RuntimeOutput(
                capability=rule.finding_capability,
                artifact_type="finding.static.v2",
                schema_version="2.0",
                media_type="application/json",
                json_value=[finding.model_dump(mode="json") for finding in normalized_findings],
                metadata={"cache_scope": "scan"},
                static_findings=tuple(normalized_findings),
            ),
        ]
    )
    return outputs
