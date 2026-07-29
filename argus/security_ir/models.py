"""Strict, extensible models for the Argus Security IR."""

from __future__ import annotations

from enum import Enum
import re
from typing import Annotated
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

NonEmptyStr = Annotated[str, Field(min_length=1)]
JsonObject = dict[str, JsonValue]

_NODE_KIND = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_-]*)+$")
_EDGE_KIND = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_-]*)*$")

CORE_NODE_KINDS = frozenset(
    {
        "code.function",
        "http.route",
        "auth.guard",
        "auth.policy",
        "identity.role",
        "tenant",
        "resource.entity",
        "data.source",
        "data.sink",
        "sanitizer",
        "business.operation",
        "business.flow",
        "state.transition",
    }
)
CORE_EDGE_KINDS = frozenset(
    {
        "handled_by",
        "calls",
        "guarded_by",
        "authorizes",
        "reads",
        "writes",
        "owns",
        "belongs_to",
        "flows_to",
        "sanitized_by",
        "transitions_to",
        "triggers",
    }
)


class SecurityConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    POSSIBLE = "POSSIBLE"


class ExtractionMethod(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM_INFERRED = "llm_inferred"
    IMPORTED = "imported"


class SecurityIRModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class SecurityCodeLocation(SecurityIRModel):
    file: NonEmptyStr
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    codegraph_node_id: str | None = None

    @model_validator(mode="after")
    def validate_range(self) -> SecurityCodeLocation:
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class SecurityProvenance(SecurityIRModel):
    snapshot_id: UUID
    producer_plugin_id: NonEmptyStr
    producer_plugin_version: NonEmptyStr
    source_artifact_ids: list[UUID] = Field(min_length=1)
    original_codegraph_node_ids: list[str] = Field(default_factory=list)
    extraction_method: ExtractionMethod
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator(
        "source_artifact_ids",
        "original_codegraph_node_ids",
        "evidence_refs",
    )
    @classmethod
    def reject_duplicates(cls, value: list[object]) -> list[object]:
        if len(value) != len(set(value)):
            raise ValueError("provenance lists must not contain duplicates")
        return value


class SecurityNode(SecurityIRModel):
    id: NonEmptyStr
    kind: NonEmptyStr
    name: NonEmptyStr
    code_locations: list[SecurityCodeLocation] = Field(default_factory=list)
    attributes: JsonObject = Field(default_factory=dict)
    provenance: SecurityProvenance
    confidence: SecurityConfidence

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, value: str) -> str:
        if value not in CORE_NODE_KINDS and _NODE_KIND.fullmatch(value) is None:
            raise ValueError("security node kind must be a core kind or namespaced extension")
        return value


class SecurityEdge(SecurityIRModel):
    id: NonEmptyStr
    kind: NonEmptyStr
    source_id: NonEmptyStr
    target_id: NonEmptyStr
    attributes: JsonObject = Field(default_factory=dict)
    provenance: SecurityProvenance
    confidence: SecurityConfidence

    @field_validator("kind")
    @classmethod
    def validate_kind(cls, value: str) -> str:
        if _EDGE_KIND.fullmatch(value) is None:
            raise ValueError("invalid security edge kind")
        if value not in CORE_EDGE_KINDS and "." not in value:
            raise ValueError("extension edge kinds must be namespaced")
        return value

    @model_validator(mode="after")
    def reject_self_reference_without_kind(self) -> SecurityEdge:
        if not self.source_id or not self.target_id:
            raise ValueError("security edge endpoints are required")
        return self


class GraphSlice(SecurityIRModel):
    seed_ids: list[str]
    nodes: list[SecurityNode]
    edges: list[SecurityEdge]
    truncated: bool = False
    max_nodes: int = Field(ge=1)
    radius: int = Field(default=1, ge=0)


class GraphPath(SecurityIRModel):
    node_ids: list[str] = Field(min_length=1)
    edge_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> GraphPath:
        if len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError("a graph path must have exactly one edge between each pair of nodes")
        return self


class PathQueryResult(SecurityIRModel):
    paths: list[GraphPath]
    truncated: bool = False
    max_depth: int = Field(ge=0)
    max_paths: int = Field(ge=1)
