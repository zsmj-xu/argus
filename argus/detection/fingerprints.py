"""Title-independent Finding fingerprints and root-cause identities."""

from __future__ import annotations

from typing import cast

from argus.detection.contracts import Candidate
from argus.domain.hashing import CanonicalValue, sha256_digest
from argus.domain.models import CodeLocation


def finding_fingerprint(
    *,
    candidate: Candidate,
    locations: list[CodeLocation],
) -> str:
    """Fingerprint stable facts only; human-facing title is intentionally absent."""
    location_values: list[dict[str, str | int | None]] = [
        {
            "file": location.file,
            "line": location.line,
            "node_id": location.node_id,
        }
        for location in locations
    ]
    location_values.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]) if isinstance(item["line"], int) else 0,
            str(item["node_id"]),
        )
    )
    return sha256_digest(
        cast(
            CanonicalValue,
            {
                "rule_id": candidate.rule_id,
                "rule_version": candidate.rule_version,
                "candidate_type": candidate.candidate_type,
                "locations": location_values,
                "source_node_ids": sorted(candidate.source_node_ids),
                "sink_node_ids": sorted(candidate.sink_node_ids),
            },
        )
    )
