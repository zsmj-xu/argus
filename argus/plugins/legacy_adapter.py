"""Translate V1 Analyzer metadata into V2 PluginSpecs.

This is the only M3 module allowed to interpret free-form ``Analyzer.requires``.
The legacy Pipeline continues to execute analyzers unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from argus.contracts import Analyzer, Phase
from argus.domain.enums import PluginKind
from argus.domain.errors import ArgusV2Error
from argus.plugins.contracts import (
    CapabilityDeclaration,
    CapabilityRequirement,
    PluginSpec,
    NetworkPermission,
    PermissionSpec,
    SecretsPermission,
    SourcePermission,
)
from argus.plugins.registry import PluginOrigin, PluginRegistry

GRAPH_CAPABILITY = "code.graph.codegraph.v1"
SOURCE_CAPABILITY = "source.snapshot.v1"
ENRICHMENT_AGGREGATE = "legacy.enrichment.aggregate.v1"
ENRICHMENT_REVIEWED = "legacy.enrichment.reviewed.v1"
FINDINGS_AGGREGATE = "legacy.findings.aggregate.v1"
FINDINGS_REVIEWED = "legacy.findings.reviewed.v1"
REPORT_CAPABILITY = "legacy.report.markdown.v1"
BUSINESS_FLOW_SECURITY_IR_PLUGIN = "semantic.business-flow-to-security-ir"
STATIC_INJECTION_FINDINGS = "finding.static.injection.v2"
STATIC_AUTHORIZATION_FINDINGS = "finding.static.authorization.v2"

_MIGRATED_DETECTORS = {
    "injection": ("detector.injection", "comparison.injection"),
    "authz": ("detector.authorization", "comparison.authorization"),
}


class UnknownLegacyRequirementError(ArgusV2Error):
    """A V1 free-form dependency cannot be represented safely in V2."""


def _analyzer_plugin_id(name: str) -> str:
    return f"legacy.analyzer.{name}"


def _enrichment_capability(name: str) -> str:
    return f"legacy.enrichment.{name}.v1"


def _findings_capability(name: str) -> str:
    return f"legacy.findings.{name}.v1"


def adapt_analyzer(analyzer: Analyzer) -> PluginSpec:
    is_enrichment = analyzer.phase is Phase.ENRICHMENT
    # V1's only declared shared-key dependency is mapped here and nowhere in
    # the generic planner. All vulnerability analyzers consume the aggregate
    # to preserve the current Pipeline's phase barrier and shallow merge.
    mapped_requires = {
        "enriched-graph": ENRICHMENT_REVIEWED,
    }
    consumes = [CapabilityRequirement(capability=GRAPH_CAPABILITY)]
    if not is_enrichment:
        consumes.append(CapabilityRequirement(capability=ENRICHMENT_REVIEWED))
    for legacy_key in analyzer.requires:
        capability = mapped_requires.get(legacy_key)
        if capability is None:
            raise UnknownLegacyRequirementError(
                f"legacy analyzer {analyzer.name!r} has unsupported requirement {legacy_key!r}"
            )
        if all(item.capability != capability for item in consumes):
            consumes.append(CapabilityRequirement(capability=capability))
    output = _enrichment_capability(analyzer.name) if is_enrichment else _findings_capability(analyzer.name)
    return PluginSpec(
        id=_analyzer_plugin_id(analyzer.name),
        version="1.0.0",
        kind=PluginKind.LEGACY_ANALYZER,
        entrypoint="argus.plugins.legacy_runtime:legacy_analyzer_runtime",
        consumes=consumes,
        produces=[
            CapabilityDeclaration(
                capability=output,
                artifact_type=output.removesuffix(".v1"),
                schema_version="1.0",
            )
        ],
        permissions=PermissionSpec(
            source=SourcePermission.READ,
            network=NetworkPermission.LLM,
            secrets=SecretsPermission.LLM,
        ),
    )


def register_legacy_plugins(
    registry: PluginRegistry,
    analyzers: Mapping[str, Analyzer],
) -> dict[str, str]:
    """Register adapters and return V1 analyzer name -> V2 plugin ID."""
    plugin_ids: dict[str, str] = {}
    enrichment_capabilities: list[str] = []
    finding_capabilities: list[str] = []
    for name in sorted(analyzers):
        analyzer = analyzers[name]
        spec = adapt_analyzer(analyzer)
        registry.register(spec, origin=PluginOrigin.LEGACY_ADAPTER)
        plugin_ids[name] = spec.id
        output = spec.produces[0].capability
        if analyzer.phase is Phase.ENRICHMENT:
            enrichment_capabilities.append(output)
        else:
            finding_capabilities.append(output)

    registry.register(
        PluginSpec(
            id="legacy.enrichment.aggregate",
            version="1.0.0",
            kind=PluginKind.AGGREGATOR,
            entrypoint="argus.plugins.legacy_runtime:legacy_enrichment_aggregate_runtime",
            consumes=[],
            optional_consumes=[
                CapabilityRequirement(capability=item, required=False) for item in enrichment_capabilities
            ],
            produces=[
                CapabilityDeclaration(
                    capability=ENRICHMENT_AGGREGATE,
                    artifact_type="legacy.enrichment.aggregate",
                    schema_version="1.0",
                )
            ],
        ),
        origin=PluginOrigin.LEGACY_ADAPTER,
    )
    registry.register(
        PluginSpec(
            id="legacy.findings.aggregate",
            version="1.0.0",
            kind=PluginKind.AGGREGATOR,
            entrypoint="argus.plugins.legacy_runtime:legacy_findings_aggregate_runtime",
            consumes=[],
            optional_consumes=[
                *[
                    CapabilityRequirement(
                        capability=item,
                        required=False,
                    )
                    for item in finding_capabilities
                ],
                CapabilityRequirement(
                    capability=STATIC_INJECTION_FINDINGS,
                    required=False,
                ),
                CapabilityRequirement(
                    capability=STATIC_AUTHORIZATION_FINDINGS,
                    required=False,
                ),
            ],
            produces=[
                CapabilityDeclaration(
                    capability=FINDINGS_AGGREGATE,
                    artifact_type="legacy.findings.aggregate",
                    schema_version="1.0",
                )
            ],
        ),
        origin=PluginOrigin.LEGACY_ADAPTER,
    )
    return plugin_ids


def legacy_selected_plugin_ids(
    config: Mapping[str, Any],
    analyzer_plugin_ids: Mapping[str, str],
) -> list[str]:
    configured = config.get("analyzers", {})
    if not isinstance(configured, Mapping):
        configured = {}
    enrichment = configured.get("enrichment", [])
    vuln = configured.get("vuln", [])
    enrichment_names = [item for item in enrichment if isinstance(item, str)] if isinstance(enrichment, list) else []
    vuln_names = [item for item in vuln if isinstance(item, str)] if isinstance(vuln, list) else []
    raw_mode = config.get("analysisMode", "legacy")
    if raw_mode not in {"legacy", "v2", "compare"}:
        raise ArgusV2Error("analysisMode must be one of: legacy, v2, compare")
    selected = ["graph.codegraph", "legacy.enrichment.aggregate"]
    selected.extend(analyzer_plugin_ids.get(name, _analyzer_plugin_id(name)) for name in enrichment_names)
    for name in vuln_names:
        migrated = _MIGRATED_DETECTORS.get(name)
        if migrated is None or raw_mode == "legacy":
            selected.append(analyzer_plugin_ids.get(name, _analyzer_plugin_id(name)))
            continue
        detector_id, comparison_id = migrated
        selected.append(detector_id)
        if raw_mode == "compare":
            selected.extend(
                [
                    analyzer_plugin_ids.get(
                        name,
                        _analyzer_plugin_id(name),
                    ),
                    comparison_id,
                ]
            )
    if "business-flow" in enrichment_names:
        selected.append(BUSINESS_FLOW_SECURITY_IR_PLUGIN)
    selected.extend(
        [
            "review.legacy-enrichment",
            "legacy.findings.aggregate",
            "review.legacy-findings",
            "reporter.markdown",
        ]
    )
    return selected


def legacy_analyzer_order(
    config: Mapping[str, Any],
    analyzer_plugin_ids: Mapping[str, str],
) -> list[tuple[str, str]]:
    configured = config.get("analyzers", {})
    if not isinstance(configured, Mapping):
        return []
    pairs: list[tuple[str, str]] = []
    for phase in ("enrichment", "vuln"):
        names = configured.get(phase, [])
        if not isinstance(names, list):
            continue
        plugin_ids = [
            analyzer_plugin_ids.get(name, _analyzer_plugin_id(name)) for name in names if isinstance(name, str)
        ]
        pairs.extend(zip(plugin_ids, plugin_ids[1:], strict=False))
    return pairs
