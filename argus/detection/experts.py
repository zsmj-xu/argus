"""Strict, bounded LLM expert evaluation."""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
)

from argus.contracts import LLMClient
from argus.detection.contracts import (
    Candidate,
    EvidenceClaim,
    ExpertAssessment,
    SourceContext,
)
from argus.domain.enums import StaticConfidence
from argus.domain.hashing import sha256_digest
from argus.security_ir.models import (
    ExtractionMethod,
    GraphSlice,
)
from argus.security_ir.provenance import security_provenance, stable_security_id

NonEmptyStr = Annotated[str, Field(min_length=1)]


class ExpertOutputError(ValueError):
    """The expert returned output outside the strict assessment contract."""


class _RawEvidenceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: NonEmptyStr
    claim: NonEmptyStr
    evidence_ref: NonEmptyStr


class _RawAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    supported: bool
    confidence: StaticConfidence
    rationale: str
    preconditions: list[str] = Field(default_factory=list)
    evidence_claims: list[_RawEvidenceClaim] = Field(default_factory=list)
    remediation_hints: list[str] = Field(default_factory=list)


class StrictExpertEvaluator:
    def __init__(
        self,
        llm: LLMClient,
        *,
        rule_instructions: str,
        max_tokens: int = 8_192,
    ) -> None:
        self.llm = llm
        self.rule_instructions = rule_instructions
        self.max_tokens = max(1_024, min(max_tokens, 65_536))

    def evaluate(
        self,
        candidate: Candidate,
        graph_slice: GraphSlice,
        source_context: SourceContext,
    ) -> ExpertAssessment:
        payload = {
            "candidate": candidate.model_dump(mode="json"),
            "graph_slice": graph_slice.model_dump(mode="json"),
            "source_context": source_context.model_dump(mode="json"),
            "output_contract": {
                "supported": "boolean",
                "confidence": ["low", "medium", "high"],
                "rationale": "string",
                "preconditions": ["string"],
                "evidence_claims": [
                    {
                        "node_id": "must exist in graph_slice.nodes",
                        "claim": "string",
                        "evidence_ref": "source excerpt or graph reference",
                    }
                ],
                "remediation_hints": ["string"],
            },
        }
        response = self.llm.complete(
            system=(
                "You are a static-analysis expert. Judge only the supplied "
                "candidate, bounded graph slice, and bounded source excerpts. "
                "Do not assume access to the repository, tools, credentials, "
                "or network. Do not create Finding IDs or claim dynamic "
                "verification. Return one strict JSON object. " + self.rule_instructions
            ),
            prompt=json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            max_tokens=self.max_tokens,
        )
        raw = self._parse(response)
        allowed_node_ids = {node.id for node in graph_slice.nodes}
        unknown_nodes = {claim.node_id for claim in raw.evidence_claims if claim.node_id not in allowed_node_ids}
        if unknown_nodes:
            raise ExpertOutputError(
                f"expert evidence references nodes outside the Graph Slice: {sorted(unknown_nodes)}"
            )
        evidence_claims = [
            EvidenceClaim(
                node_id=claim.node_id,
                claim=claim.claim,
                evidence_ref=claim.evidence_ref,
            )
            for claim in raw.evidence_claims
        ]
        response_hash = sha256_digest(raw)
        try:
            return ExpertAssessment(
                id=stable_security_id(
                    "assessment",
                    candidate.id,
                    response_hash,
                ),
                candidate_id=candidate.id,
                rule_id=candidate.rule_id,
                rule_version=candidate.rule_version,
                supported=raw.supported,
                confidence=raw.confidence,
                rationale=raw.rationale,
                preconditions=list(dict.fromkeys(raw.preconditions)),
                evidence_claims=evidence_claims,
                remediation_hints=list(dict.fromkeys(raw.remediation_hints)),
                provenance=security_provenance(
                    snapshot_id=candidate.provenance.snapshot_id,
                    producer_plugin_id=candidate.provenance.producer_plugin_id,
                    producer_plugin_version=(candidate.provenance.producer_plugin_version),
                    source_artifact_ids=(candidate.provenance.source_artifact_ids),
                    original_codegraph_node_ids=(candidate.provenance.original_codegraph_node_ids),
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_refs=[
                        f"candidate:{candidate.id}",
                        f"graph-slice:{sha256_digest(graph_slice)}",
                        f"source-context:{sha256_digest(source_context)}",
                        f"expert-response:sha256:{response_hash}",
                    ],
                ),
            )
        except ValidationError as exc:
            raise ExpertOutputError(f"expert assessment violates the contract: {exc}") from exc

    @staticmethod
    def _parse(response: str) -> _RawAssessment:
        text = response.strip()
        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline < 0 or not text.endswith("```"):
                raise ExpertOutputError("expert returned an invalid code fence")
            text = text[first_newline + 1 : -3].strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExpertOutputError("expert returned invalid JSON") from exc
        try:
            return _RawAssessment.model_validate(value)
        except ValidationError as exc:
            raise ExpertOutputError(f"expert output violates the assessment schema: {exc}") from exc
