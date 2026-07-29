"""Side-channel legacy/V2 comparison that never feeds the main report."""

from __future__ import annotations

from typing import Any

from pydantic import JsonValue, TypeAdapter

from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)

_CAPABILITIES = {
    "comparison.injection": (
        "legacy.findings.injection.v1",
        "finding.static.injection.v2",
        "comparison.injection.v1",
    ),
    "comparison.authorization": (
        "legacy.findings.authz.v1",
        "finding.static.authorization.v2",
        "comparison.authorization.v1",
    ),
}


def _records(value: JsonValue) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _comparison_key(
    finding: dict[str, Any],
    *,
    family: str,
) -> str:
    locations = finding.get("locations", [])
    anchors = sorted(
        {
            str(location.get("node_id") or "") or f"{location.get('file')}:{location.get('line')}"
            for location in locations
            if isinstance(location, dict)
        }
    )
    return f"{family}:{'|'.join(anchors)}"


def finding_comparison_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    try:
        legacy_capability, v2_capability, output_capability = _CAPABILITIES[context.task.plugin_id]
    except KeyError as exc:
        raise RuntimeError(f"unsupported comparison plugin: {context.task.plugin_id}") from exc
    family = "injection" if context.task.plugin_id.endswith("injection") else "authorization"
    legacy = _records(_JSON.validate_json(inputs[legacy_capability].payload))
    v2 = _records(_JSON.validate_json(inputs[v2_capability].payload))
    legacy_by_key = {_comparison_key(item, family=family): item for item in legacy}
    v2_by_key = {_comparison_key(item, family=family): item for item in v2}
    shared = sorted(set(legacy_by_key) & set(v2_by_key))
    legacy_only = sorted(set(legacy_by_key) - set(v2_by_key))
    v2_only = sorted(set(v2_by_key) - set(legacy_by_key))
    payload: JsonValue = {
        "schema_version": "1.0",
        "rule_family": family,
        "legacy_capability": legacy_capability,
        "v2_capability": v2_capability,
        "matched": [
            {
                "key": key,
                "legacy_id": str(legacy_by_key[key].get("id", "")),
                "v2_id": str(v2_by_key[key].get("id", "")),
            }
            for key in shared
        ],
        "legacy_only": [
            {
                "key": key,
                "id": str(legacy_by_key[key].get("id", "")),
                "title": str(legacy_by_key[key].get("title", "")),
            }
            for key in legacy_only
        ],
        "v2_only": [
            {
                "key": key,
                "id": str(v2_by_key[key].get("id", "")),
                "title": str(v2_by_key[key].get("title", "")),
                "fingerprint": str(v2_by_key[key].get("fingerprint", "")),
            }
            for key in v2_only
        ],
        "counts": {
            "legacy": len(legacy),
            "v2": len(v2),
            "matched": len(shared),
            "legacy_only": len(legacy_only),
            "v2_only": len(v2_only),
        },
        "affects_main_report": False,
    }
    return [
        RuntimeOutput(
            capability=output_capability,
            artifact_type="comparison.findings.v1",
            schema_version="1.0",
            media_type="application/json",
            json_value=payload,
            metadata={"cache_scope": "scan"},
        )
    ]
