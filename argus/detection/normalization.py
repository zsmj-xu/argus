"""Normalize supported assessments into deterministic StaticFindingV2 records."""

from __future__ import annotations

from uuid import UUID

from argus.detection.contracts import (
    Candidate,
    DetectionContext,
    ExpertAssessment,
)
from argus.detection.fingerprints import finding_fingerprint
from argus.domain.enums import FindingStatus, Severity
from argus.domain.models import CodeLocation, StaticFindingV2
from argus.security_ir.models import GraphSlice


class FindingNormalizationError(ValueError):
    pass


class StaticFindingNormalizer:
    def normalize(
        self,
        context: DetectionContext,
        candidate: Candidate,
        assessment: ExpertAssessment,
        graph_slice: GraphSlice,
        *,
        graph_slice_artifact_id: UUID,
        evidence_artifact_ids: list[UUID],
    ) -> StaticFindingV2:
        if not assessment.supported:
            raise FindingNormalizationError("unsupported assessment cannot become a Finding")
        if assessment.candidate_id != candidate.id:
            raise FindingNormalizationError("assessment belongs to a different Candidate")
        locations = self._locations(candidate, assessment, graph_slice)
        if not locations:
            raise FindingNormalizationError("supported Candidate has no graph-anchored code location")
        title, weakness_id, vuln_class, severity = self._classification(candidate)
        return StaticFindingV2(
            fingerprint=finding_fingerprint(
                candidate=candidate,
                locations=locations,
            ),
            scan_id=context.scan.id,
            snapshot_id=context.snapshot.id,
            rule_id=candidate.rule_id,
            rule_version=candidate.rule_version,
            title=title,
            weakness_id=weakness_id,
            vuln_class=vuln_class,
            severity=severity,
            static_confidence=assessment.confidence,
            status=FindingStatus.UNVERIFIED,
            locations=locations,
            source_node_ids=candidate.source_node_ids,
            sink_node_ids=candidate.sink_node_ids,
            root_cause_key=candidate.root_cause_key,
            graph_slice_artifact_id=graph_slice_artifact_id,
            evidence_artifact_ids=list(dict.fromkeys(evidence_artifact_ids)),
            preconditions=assessment.preconditions,
            rationale=assessment.rationale,
            remediation="\n".join(assessment.remediation_hints),
        )

    @staticmethod
    def _locations(
        candidate: Candidate,
        assessment: ExpertAssessment,
        graph_slice: GraphSlice,
    ) -> list[CodeLocation]:
        preferred = list(
            dict.fromkeys(
                [
                    *(claim.node_id for claim in assessment.evidence_claims),
                    *candidate.primary_node_ids,
                    *candidate.sink_node_ids,
                ]
            )
        )
        nodes = {node.id: node for node in graph_slice.nodes}
        locations: list[CodeLocation] = []
        seen: set[tuple[str, int, str | None]] = set()
        for node_id in preferred:
            node = nodes.get(node_id)
            if node is None:
                continue
            for location in node.code_locations:
                key = (
                    location.file,
                    location.start_line,
                    location.codegraph_node_id,
                )
                if key in seen:
                    continue
                seen.add(key)
                locations.append(
                    CodeLocation(
                        file=location.file,
                        line=location.start_line,
                        node_id=(location.codegraph_node_id or node.id),
                    )
                )
        return locations

    @staticmethod
    def _classification(
        candidate: Candidate,
    ) -> tuple[str, str, str, Severity]:
        if candidate.candidate_type == "injection.sql":
            return (
                "Potential SQL injection at a reachable query sink",
                "CWE-89",
                "injection",
                Severity.HIGH,
            )
        if candidate.candidate_type == "injection.command":
            return (
                "Potential command injection at a process sink",
                "CWE-78",
                "injection",
                Severity.CRITICAL,
            )
        if candidate.candidate_type == "injection.template":
            return (
                "Potential server-side template injection",
                "CWE-1336",
                "injection",
                Severity.HIGH,
            )
        if candidate.candidate_type == "authorization.idor":
            resource = candidate.attributes.get("resource_name")
            suffix = f" for {resource}" if isinstance(resource, str) else ""
            return (
                f"Potential IDOR or ownership bypass{suffix}",
                "CWE-639",
                "authorization",
                Severity.HIGH,
            )
        raise FindingNormalizationError(f"unsupported candidate type: {candidate.candidate_type}")
