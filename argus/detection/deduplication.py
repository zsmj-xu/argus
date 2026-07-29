"""Deterministically merge duplicate StaticFindingV2 evidence."""

from __future__ import annotations

from argus.domain.enums import StaticConfidence
from argus.domain.models import StaticFindingV2

_CONFIDENCE_RANK = {
    StaticConfidence.LOW: 0,
    StaticConfidence.MEDIUM: 1,
    StaticConfidence.HIGH: 2,
}


def deduplicate_findings(
    findings: list[StaticFindingV2],
) -> list[StaticFindingV2]:
    merged: dict[str, StaticFindingV2] = {}
    for finding in sorted(
        findings,
        key=lambda item: (item.fingerprint, str(item.id)),
    ):
        current = merged.get(finding.fingerprint)
        if current is None:
            merged[finding.fingerprint] = finding
            continue
        confidence = max(
            (current.static_confidence, finding.static_confidence),
            key=lambda item: _CONFIDENCE_RANK[item],
        )
        rationales = list(dict.fromkeys(value for value in (current.rationale, finding.rationale) if value))
        merged[finding.fingerprint] = current.model_copy(
            update={
                "static_confidence": confidence,
                "locations": list(dict.fromkeys([*current.locations, *finding.locations])),
                "source_node_ids": list(
                    dict.fromkeys(
                        [
                            *current.source_node_ids,
                            *finding.source_node_ids,
                        ]
                    )
                ),
                "sink_node_ids": list(dict.fromkeys([*current.sink_node_ids, *finding.sink_node_ids])),
                "evidence_artifact_ids": list(
                    dict.fromkeys(
                        [
                            *current.evidence_artifact_ids,
                            *finding.evidence_artifact_ids,
                        ]
                    )
                ),
                "preconditions": list(
                    dict.fromkeys(
                        [
                            *current.preconditions,
                            *finding.preconditions,
                        ]
                    )
                ),
                "rationale": "\n\n".join(rationales),
            }
        )
    return [merged[key] for key in sorted(merged)]
