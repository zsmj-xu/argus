"""Deterministic identity and provenance helpers for Security IR producers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from uuid import UUID

from pydantic import JsonValue, TypeAdapter

from argus.security_ir.models import ExtractionMethod, SecurityProvenance

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


def stable_security_id(namespace: str, *parts: object) -> str:
    canonical = json.dumps(
        [namespace, *parts],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return f"sir:{namespace}:{digest[:32]}"


def security_provenance(
    *,
    snapshot_id: UUID,
    producer_plugin_id: str,
    producer_plugin_version: str,
    source_artifact_ids: Iterable[UUID],
    original_codegraph_node_ids: Iterable[str] = (),
    extraction_method: ExtractionMethod,
    evidence_refs: Iterable[str] = (),
) -> SecurityProvenance:
    return SecurityProvenance(
        snapshot_id=snapshot_id,
        producer_plugin_id=producer_plugin_id,
        producer_plugin_version=producer_plugin_version,
        source_artifact_ids=sorted(set(source_artifact_ids), key=str),
        original_codegraph_node_ids=sorted(set(original_codegraph_node_ids)),
        extraction_method=extraction_method,
        evidence_refs=sorted(set(evidence_refs)),
    )


def json_compatible(value: object) -> JsonValue:
    normalized = json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))
    return _JSON.validate_python(normalized)
