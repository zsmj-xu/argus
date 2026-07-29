"""Strict contracts for Candidate → Slice → Expert → Finding."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Annotated, Protocol
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from argus.contracts import SourceAccess
from argus.domain.enums import StaticConfidence
from argus.domain.models import Scan, SourceSnapshot, StaticFindingV2
from argus.graph.codegraph import CodegraphHandle
from argus.security_ir.models import GraphSlice, SecurityProvenance
from argus.security_ir.query import SecurityGraphQuery

NonEmptyStr = Annotated[str, Field(min_length=1)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class DetectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class Candidate(DetectionModel):
    id: NonEmptyStr
    rule_id: NonEmptyStr
    rule_version: NonEmptyStr
    candidate_type: NonEmptyStr
    primary_node_ids: list[str] = Field(min_length=1)
    source_node_ids: list[str] = Field(default_factory=list)
    sink_node_ids: list[str] = Field(default_factory=list)
    route_ids: list[str] = Field(default_factory=list)
    identity_context_ids: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(min_length=1)
    static_score: float = Field(ge=0.0, le=1.0)
    root_cause_key: Sha256
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    provenance: SecurityProvenance

    @field_validator(
        "primary_node_ids",
        "source_node_ids",
        "sink_node_ids",
        "route_ids",
        "identity_context_ids",
        "reason_codes",
    )
    @classmethod
    def reject_duplicates(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("candidate lists must not contain duplicates")
        return values

    @field_validator("reason_codes")
    @classmethod
    def validate_reason_codes(cls, values: list[str]) -> list[str]:
        if any(_REASON_CODE.fullmatch(value) is None for value in values):
            raise ValueError("candidate reason codes must be uppercase identifiers")
        return values


class SourceExcerpt(DetectionModel):
    node_id: NonEmptyStr
    file: NonEmptyStr
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str
    content_hash: Sha256
    truncated: bool = False

    @model_validator(mode="after")
    def validate_range(self) -> SourceExcerpt:
        if self.end_line < self.start_line:
            raise ValueError("source excerpt end_line precedes start_line")
        return self


class SourceContext(DetectionModel):
    candidate_id: NonEmptyStr
    excerpts: list[SourceExcerpt]
    total_chars: int = Field(ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def validate_total(self) -> SourceContext:
        if self.total_chars != sum(len(item.text) for item in self.excerpts):
            raise ValueError("source context total_chars does not match excerpts")
        return self


class EvidenceClaim(DetectionModel):
    node_id: NonEmptyStr
    claim: NonEmptyStr
    evidence_ref: NonEmptyStr


class ExpertAssessment(DetectionModel):
    id: NonEmptyStr
    candidate_id: NonEmptyStr
    rule_id: NonEmptyStr
    rule_version: NonEmptyStr
    supported: bool
    confidence: StaticConfidence
    rationale: str
    preconditions: list[str] = Field(default_factory=list)
    evidence_claims: list[EvidenceClaim] = Field(default_factory=list)
    remediation_hints: list[str] = Field(default_factory=list)
    provenance: SecurityProvenance

    @model_validator(mode="after")
    def validate_supported_assessment(self) -> ExpertAssessment:
        if self.supported and (not self.rationale.strip() or not self.evidence_claims or not self.remediation_hints):
            raise ValueError("supported assessment requires rationale, evidence, and remediation")
        return self


@dataclass(frozen=True)
class DetectionContext:
    scan: Scan
    snapshot: SourceSnapshot
    plugin_id: str
    plugin_version: str
    source_artifact_ids: tuple[UUID, ...]
    codegraph: CodegraphHandle
    security_graph: SecurityGraphQuery | None
    source: SourceAccess
    config: dict[str, JsonValue]


class CandidateProvider(Protocol):
    def generate(self, context: DetectionContext) -> list[Candidate]: ...


class GraphSliceBuilder(Protocol):
    def build(
        self,
        context: DetectionContext,
        candidate: Candidate,
    ) -> GraphSlice: ...


class ExpertEvaluator(Protocol):
    def evaluate(
        self,
        candidate: Candidate,
        graph_slice: GraphSlice,
        source_context: SourceContext,
    ) -> ExpertAssessment: ...


class FindingNormalizer(Protocol):
    def normalize(
        self,
        context: DetectionContext,
        candidate: Candidate,
        assessment: ExpertAssessment,
        graph_slice: GraphSlice,
        *,
        graph_slice_artifact_id: UUID,
        evidence_artifact_ids: list[UUID],
    ) -> StaticFindingV2: ...
