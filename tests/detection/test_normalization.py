from __future__ import annotations

from uuid import uuid4

from argus.detection.builtin.injection.provider import InjectionCandidateProvider
from argus.detection.candidates import BoundedGraphSliceBuilder
from argus.detection.contracts import EvidenceClaim, ExpertAssessment
from argus.detection.deduplication import deduplicate_findings
from argus.detection.normalization import StaticFindingNormalizer
from argus.domain.enums import FindingStatus, StaticConfidence
from argus.security_ir.models import ExtractionMethod
from argus.security_ir.provenance import security_provenance

from .test_candidate_pipeline import _injection_context


def _assessment(candidate, *, confidence: StaticConfidence = StaticConfidence.MEDIUM):
    return ExpertAssessment(
        id="assessment-1",
        candidate_id=candidate.id,
        rule_id=candidate.rule_id,
        rule_version=candidate.rule_version,
        supported=True,
        confidence=confidence,
        rationale="Attacker-controlled input reaches an interpolated SQL query.",
        preconditions=["The route is reachable."],
        evidence_claims=[
            EvidenceClaim(
                node_id="cg-unsafe",
                claim="The query is constructed with request input.",
                evidence_ref="source:app.py:1",
            )
        ],
        remediation_hints=["Use a parameterized query."],
        provenance=security_provenance(
            snapshot_id=candidate.provenance.snapshot_id,
            producer_plugin_id="detector.injection",
            producer_plugin_version="1.0.0",
            source_artifact_ids=candidate.provenance.source_artifact_ids,
            original_codegraph_node_ids=candidate.provenance.original_codegraph_node_ids,
            extraction_method=ExtractionMethod.LLM_INFERRED,
            evidence_refs=[f"candidate:{candidate.id}"],
        ),
    )


def test_normalizer_creates_unverified_graph_anchored_finding() -> None:
    context = _injection_context()
    candidate = InjectionCandidateProvider().generate(context)[0]
    graph_slice = BoundedGraphSliceBuilder().build(context, candidate)
    slice_id = uuid4()
    evidence_ids = [uuid4(), slice_id, uuid4()]

    finding = StaticFindingNormalizer().normalize(
        context,
        candidate,
        _assessment(candidate),
        graph_slice,
        graph_slice_artifact_id=slice_id,
        evidence_artifact_ids=evidence_ids,
    )

    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.static_confidence is StaticConfidence.MEDIUM
    assert finding.locations[0].node_id == "cg-unsafe"
    assert finding.root_cause_key == candidate.root_cause_key
    assert finding.graph_slice_artifact_id == slice_id
    assert finding.evidence_artifact_ids == evidence_ids


def test_duplicate_fingerprint_merges_evidence_and_keeps_highest_confidence() -> None:
    context = _injection_context()
    candidate = InjectionCandidateProvider().generate(context)[0]
    graph_slice = BoundedGraphSliceBuilder().build(context, candidate)
    first_evidence = uuid4()
    second_evidence = uuid4()
    first = StaticFindingNormalizer().normalize(
        context,
        candidate,
        _assessment(candidate, confidence=StaticConfidence.LOW),
        graph_slice,
        graph_slice_artifact_id=uuid4(),
        evidence_artifact_ids=[first_evidence],
    )
    second = first.model_copy(
        update={
            "id": uuid4(),
            "static_confidence": StaticConfidence.HIGH,
            "evidence_artifact_ids": [second_evidence],
            "preconditions": ["The route is reachable.", "The attacker controls id."],
            "rationale": "Independent expert evidence confirms the same root cause.",
        }
    )

    merged = deduplicate_findings([second, first])

    assert len(merged) == 1
    assert merged[0].static_confidence is StaticConfidence.HIGH
    assert set(merged[0].evidence_artifact_ids) == {
        first_evidence,
        second_evidence,
    }
    assert merged[0].root_cause_key == candidate.root_cause_key
