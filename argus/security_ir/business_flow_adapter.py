"""Deterministically adapt normalized legacy business-flow output to Security IR."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import UUID

from pydantic import JsonValue, TypeAdapter

from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput
from argus.graph.codegraph import CodegraphHandle
from argus.security_ir.models import (
    ExtractionMethod,
    SecurityCodeLocation,
    SecurityConfidence,
    SecurityEdge,
    SecurityNode,
    SecurityProvenance,
)
from argus.security_ir.provenance import (
    json_compatible,
    security_provenance,
    stable_security_id,
)
from argus.security_ir.store import (
    SECURITY_GRAPH_SCHEMA_VERSION,
    SecurityGraphStore,
)

LEGACY_BUSINESS_FLOW_CAPABILITY = "legacy.enrichment.business-flow.v1"
CODEGRAPH_CAPABILITY = "code.graph.codegraph.v1"
SECURITY_ROUTES_CAPABILITY = "security.routes.v1"
SECURITY_BUSINESS_FLOW_CAPABILITY = "security.business-flow.v1"
SECURITY_AUTHORIZATION_CAPABILITY = "security.authorization.v1"
SECURITY_RESOURCES_CAPABILITY = "security.resources.v1"
SECURITY_GRAPH_CAPABILITY = "security.graph.v1"

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


def _objects(value: object, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    items = value.get(key, [])
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _source_location(
    source_ref: object,
    *,
    codegraph_node: dict[str, Any] | None = None,
) -> list[SecurityCodeLocation]:
    if codegraph_node is not None:
        file = _text(codegraph_node.get("file_path"))
        start = codegraph_node.get("start_line")
        end = codegraph_node.get("end_line")
        if file is not None and isinstance(start, int) and not isinstance(start, bool) and start >= 1:
            return [
                SecurityCodeLocation(
                    file=file,
                    start_line=start,
                    end_line=(end if isinstance(end, int) and not isinstance(end, bool) and end >= start else None),
                    codegraph_node_id=_text(codegraph_node.get("id")),
                )
            ]
    raw = _text(source_ref)
    if raw is None:
        return []
    file, separator, line_text = raw.rpartition(":")
    if not separator or not file:
        return []
    try:
        line = int(line_text)
    except ValueError:
        return []
    if line < 1:
        return []
    return [SecurityCodeLocation(file=file, start_line=line)]


class BusinessFlowSecurityIRBuilder:
    def __init__(
        self,
        *,
        context: RuntimeContext,
        source_artifact_ids: list[UUID],
        codegraph: CodegraphHandle,
    ) -> None:
        self.context = context
        self.source_artifact_ids = source_artifact_ids
        self.codegraph = codegraph
        self.nodes: dict[str, SecurityNode] = {}
        self.edges: dict[str, SecurityEdge] = {}
        self.legacy_ids: dict[str, str | None] = {}
        self.codegraph_ids: dict[str, str] = {}

    def build(
        self,
        enrichment: dict[str, Any],
    ) -> tuple[list[SecurityNode], list[SecurityEdge]]:
        self._base_nodes(enrichment)
        self._legacy_edges(enrichment)
        self._flow_semantics(enrichment)
        self._codegraph_calls()
        return (
            sorted(self.nodes.values(), key=lambda item: item.id),
            sorted(self.edges.values(), key=lambda item: item.id),
        )

    def _remember_legacy(self, legacy_id: str, node_id: str) -> None:
        if legacy_id not in self.legacy_ids:
            self.legacy_ids[legacy_id] = node_id
        elif self.legacy_ids[legacy_id] != node_id:
            self.legacy_ids[legacy_id] = None

    def _provenance(
        self,
        *,
        extraction_method: ExtractionMethod,
        evidence_ref: str,
        codegraph_node_ids: list[str] | None = None,
    ) -> SecurityProvenance:
        return security_provenance(
            snapshot_id=self.context.snapshot.id,
            producer_plugin_id=self.context.task.plugin_id,
            producer_plugin_version=self.context.task.plugin_version,
            source_artifact_ids=self.source_artifact_ids,
            original_codegraph_node_ids=codegraph_node_ids or [],
            extraction_method=extraction_method,
            evidence_refs=[evidence_ref],
        )

    def _add_node(
        self,
        *,
        namespace: str,
        identity: object,
        kind: str,
        name: str,
        attributes: dict[str, Any],
        locations: list[SecurityCodeLocation],
        confidence: SecurityConfidence,
        extraction_method: ExtractionMethod,
        evidence_ref: str,
        codegraph_node_ids: list[str] | None = None,
    ) -> str:
        node_id = stable_security_id(namespace, self.context.snapshot.id, identity)
        if node_id not in self.nodes:
            normalized_attributes = json_compatible(attributes)
            if not isinstance(normalized_attributes, dict):
                raise TypeError("SecurityNode attributes must be a JSON object")
            self.nodes[node_id] = SecurityNode(
                id=node_id,
                kind=kind,
                name=name,
                code_locations=locations,
                attributes=normalized_attributes,
                provenance=self._provenance(
                    extraction_method=extraction_method,
                    evidence_ref=evidence_ref,
                    codegraph_node_ids=codegraph_node_ids,
                ),
                confidence=confidence,
            )
        return node_id

    def _add_edge(
        self,
        *,
        kind: str,
        source_id: str,
        target_id: str,
        attributes: dict[str, Any],
        confidence: SecurityConfidence,
        extraction_method: ExtractionMethod,
        evidence_ref: str,
        codegraph_node_ids: list[str] | None = None,
    ) -> None:
        edge_id = stable_security_id(
            "edge",
            self.context.snapshot.id,
            kind,
            source_id,
            target_id,
            evidence_ref,
        )
        normalized_attributes = json_compatible(attributes)
        if not isinstance(normalized_attributes, dict):
            raise TypeError("SecurityEdge attributes must be a JSON object")
        self.edges.setdefault(
            edge_id,
            SecurityEdge(
                id=edge_id,
                kind=kind,
                source_id=source_id,
                target_id=target_id,
                attributes=normalized_attributes,
                provenance=self._provenance(
                    extraction_method=extraction_method,
                    evidence_ref=evidence_ref,
                    codegraph_node_ids=codegraph_node_ids,
                ),
                confidence=confidence,
            ),
        )

    def _base_nodes(self, enrichment: dict[str, Any]) -> None:
        for index, endpoint in enumerate(_objects(enrichment, "endpoints")):
            legacy_id = _text(endpoint.get("id"))
            if legacy_id is None:
                continue
            codegraph_id = _text(endpoint.get("node_id"))
            codegraph_node = self.codegraph.node(codegraph_id) if codegraph_id is not None else None
            method = _text(endpoint.get("method")) or "*"
            path = _text(endpoint.get("path")) or legacy_id
            node_id = self._add_node(
                namespace="http-route",
                identity=legacy_id,
                kind="http.route",
                name=f"{method} {path}",
                attributes=endpoint,
                locations=_source_location(
                    endpoint.get("source_ref"),
                    codegraph_node=codegraph_node,
                ),
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=f"business-flow:/endpoints/{index}",
                codegraph_node_ids=([codegraph_id] if codegraph_node is not None and codegraph_id is not None else []),
            )
            self._remember_legacy(legacy_id, node_id)

        for index, handler in enumerate(_objects(enrichment, "handlers")):
            legacy_id = _text(handler.get("id"))
            if legacy_id is None:
                continue
            codegraph_id = _text(handler.get("node_id"))
            codegraph_node = self.codegraph.node(codegraph_id) if codegraph_id is not None else None
            if codegraph_node is not None and codegraph_id is not None:
                node_id = self._add_node(
                    namespace="code-function",
                    identity=codegraph_id,
                    kind="code.function",
                    name=_text(codegraph_node.get("name")) or _text(handler.get("name")) or legacy_id,
                    attributes={
                        "legacy": handler,
                        "qualified_name": codegraph_node.get("qualified_name"),
                        "language": codegraph_node.get("language"),
                        "signature": codegraph_node.get("signature"),
                    },
                    locations=_source_location(
                        handler.get("source_ref"),
                        codegraph_node=codegraph_node,
                    ),
                    confidence=SecurityConfidence.CONFIRMED,
                    extraction_method=ExtractionMethod.DETERMINISTIC,
                    evidence_ref=f"codegraph:node:{codegraph_id}",
                    codegraph_node_ids=[codegraph_id],
                )
                self.codegraph_ids[codegraph_id] = node_id
            else:
                node_id = self._add_node(
                    namespace="code-function-unanchored",
                    identity=legacy_id,
                    kind="code.function",
                    name=_text(handler.get("name")) or legacy_id,
                    attributes={"legacy": handler, "anchored": False},
                    locations=_source_location(handler.get("source_ref")),
                    confidence=SecurityConfidence.POSSIBLE,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=f"business-flow:/handlers/{index}",
                )
            self._remember_legacy(legacy_id, node_id)

        for section, kind, namespace in (
            ("resources", "resource.entity", "resource"),
            ("operations", "business.operation", "operation"),
        ):
            for index, item in enumerate(_objects(enrichment, section)):
                legacy_id = _text(item.get("id"))
                if legacy_id is None:
                    continue
                name = _text(item.get("name")) or _text(item.get("verb")) or legacy_id
                node_id = self._add_node(
                    namespace=namespace,
                    identity=legacy_id,
                    kind=kind,
                    name=name,
                    attributes=item,
                    locations=_source_location(item.get("source_ref")),
                    confidence=SecurityConfidence.INFERRED,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=f"business-flow:/{section}/{index}",
                )
                self._remember_legacy(legacy_id, node_id)

    def _legacy_edges(self, enrichment: dict[str, Any]) -> None:
        kind_map = {
            "handled_by": "handled_by",
            "calls": "calls",
            "performs": "triggers",
            "targets": "writes",
        }
        for index, item in enumerate(_objects(enrichment, "edges")):
            source = self.legacy_ids.get(_text(item.get("from")) or "")
            target = self.legacy_ids.get(_text(item.get("to")) or "")
            kind = kind_map.get(_text(item.get("rel")) or "")
            if source is None or target is None or kind is None:
                continue
            self._add_edge(
                kind=kind,
                source_id=source,
                target_id=target,
                attributes={"legacy_relation": item},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=f"business-flow:/edges/{index}",
            )

    def _flow_semantics(self, enrichment: dict[str, Any]) -> None:
        for flow_index, flow in enumerate(_objects(enrichment, "business_flows")):
            endpoint_legacy_id = _text(flow.get("endpoint_id"))
            if endpoint_legacy_id is None:
                continue
            endpoint_id = self.legacy_ids.get(endpoint_legacy_id)
            if endpoint_id is None:
                continue
            intent = _text(flow.get("intent")) or endpoint_legacy_id
            flow_id = self._add_node(
                namespace="business-flow",
                identity=(endpoint_legacy_id, intent),
                kind="business.flow",
                name=intent,
                attributes=flow,
                locations=[],
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=f"business-flow:/business_flows/{flow_index}",
            )
            self._add_edge(
                kind="triggers",
                source_id=endpoint_id,
                target_id=flow_id,
                attributes={},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=f"business-flow:/business_flows/{flow_index}/endpoint_id",
            )
            self._related_endpoints(flow, flow_index, flow_id)
            self._authorization(flow, flow_index, flow_id)
            self._trust_boundaries(flow, flow_index, flow_id)
            self._state_access(flow, flow_index, flow_id)
            self._state_transitions(flow, flow_index, flow_id)

    def _related_endpoints(
        self,
        flow: dict[str, Any],
        flow_index: int,
        flow_id: str,
    ) -> None:
        related = flow.get("related_endpoint_ids", [])
        if not isinstance(related, list):
            return
        for index, legacy_id in enumerate(related):
            endpoint_id = self.legacy_ids.get(_text(legacy_id) or "")
            if endpoint_id is None:
                continue
            self._add_edge(
                kind="triggers",
                source_id=flow_id,
                target_id=endpoint_id,
                attributes={"relation": "related_endpoint"},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/related_endpoint_ids/{index}"),
            )

    def _authorization(
        self,
        flow: dict[str, Any],
        flow_index: int,
        flow_id: str,
    ) -> None:
        requirements = flow.get("authorization_requirements", [])
        if isinstance(requirements, list):
            for index, requirement in enumerate(requirements):
                requirement_text = _text(requirement)
                if requirement_text is None:
                    continue
                policy_id = self._add_node(
                    namespace="auth-policy",
                    identity=(flow_id, "requirement", index, requirement_text),
                    kind="auth.policy",
                    name=requirement_text,
                    attributes={"required": True},
                    locations=[],
                    confidence=SecurityConfidence.INFERRED,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_requirements/{index}"),
                )
                self._add_edge(
                    kind="authorizes",
                    source_id=policy_id,
                    target_id=flow_id,
                    attributes={"required": True},
                    confidence=SecurityConfidence.INFERRED,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_requirements/{index}"),
                )
        checks = flow.get("authorization_checks", [])
        if not isinstance(checks, list):
            return
        for index, check in enumerate(checks):
            if not isinstance(check, dict):
                continue
            requirement = _text(check.get("requirement"))
            if requirement is None:
                continue
            enforced = check.get("enforced") is True
            policy_id = self._add_node(
                namespace="auth-check-policy",
                identity=(flow_id, index, requirement),
                kind="auth.policy",
                name=requirement,
                attributes=check,
                locations=[],
                confidence=(SecurityConfidence.INFERRED if enforced else SecurityConfidence.POSSIBLE),
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_checks/{index}"),
            )
            self._add_edge(
                kind="authorizes",
                source_id=policy_id,
                target_id=flow_id,
                attributes={"enforced": enforced},
                confidence=(SecurityConfidence.INFERRED if enforced else SecurityConfidence.POSSIBLE),
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_checks/{index}"),
            )
            if not enforced:
                continue
            guard_name = _text(check.get("enforced_by")) or requirement
            guard_id = self._add_node(
                namespace="auth-guard",
                identity=(flow_id, index, guard_name),
                kind="auth.guard",
                name=guard_name,
                attributes=check,
                locations=[],
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_checks/{index}"),
            )
            self._add_edge(
                kind="guarded_by",
                source_id=flow_id,
                target_id=guard_id,
                attributes={},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_checks/{index}/enforced_by"),
            )
            self._add_edge(
                kind="authorizes",
                source_id=guard_id,
                target_id=policy_id,
                attributes={},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/authorization_checks/{index}/enforced"),
            )

    def _trust_boundaries(
        self,
        flow: dict[str, Any],
        flow_index: int,
        flow_id: str,
    ) -> None:
        boundaries = flow.get("trust_boundaries", [])
        if not isinstance(boundaries, list):
            return
        for index, boundary in enumerate(boundaries):
            if not isinstance(boundary, dict):
                continue
            field = _text(boundary.get("field"))
            source = _text(boundary.get("source"))
            if field is None or source is None:
                continue
            source_id = self._add_node(
                namespace="data-source",
                identity=(flow_id, field, source),
                kind="data.source",
                name=f"{source}:{field}",
                attributes=boundary,
                locations=[],
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/trust_boundaries/{index}"),
            )
            self._add_edge(
                kind="flows_to",
                source_id=source_id,
                target_id=flow_id,
                attributes={"validated": boundary.get("validated") is True},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/trust_boundaries/{index}"),
            )

    def _state_access(
        self,
        flow: dict[str, Any],
        flow_index: int,
        flow_id: str,
    ) -> None:
        for field, edge_kind in (("state_reads", "reads"), ("state_writes", "writes")):
            values = flow.get(field, [])
            if not isinstance(values, list):
                continue
            for index, value in enumerate(values):
                state_name = _text(value)
                if state_name is None:
                    continue
                resource_id = self._add_node(
                    namespace="state-resource",
                    identity=state_name,
                    kind="resource.entity",
                    name=state_name,
                    attributes={"state_reference": state_name},
                    locations=[],
                    confidence=SecurityConfidence.INFERRED,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=(f"business-flow:/business_flows/{flow_index}/{field}/{index}"),
                )
                self._add_edge(
                    kind=edge_kind,
                    source_id=flow_id,
                    target_id=resource_id,
                    attributes={},
                    confidence=SecurityConfidence.INFERRED,
                    extraction_method=ExtractionMethod.LLM_INFERRED,
                    evidence_ref=(f"business-flow:/business_flows/{flow_index}/{field}/{index}"),
                )

    def _state_transitions(
        self,
        flow: dict[str, Any],
        flow_index: int,
        flow_id: str,
    ) -> None:
        transitions = flow.get("state_transitions", [])
        if not isinstance(transitions, list):
            return
        for index, transition in enumerate(transitions):
            if not isinstance(transition, dict):
                continue
            source = _text(transition.get("from"))
            target = _text(transition.get("to"))
            if source is None or target is None:
                continue
            transition_id = self._add_node(
                namespace="state-transition",
                identity=(flow_id, source, target, index),
                kind="state.transition",
                name=f"{source} → {target}",
                attributes=transition,
                locations=[],
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/state_transitions/{index}"),
            )
            self._add_edge(
                kind="transitions_to",
                source_id=flow_id,
                target_id=transition_id,
                attributes={},
                confidence=SecurityConfidence.INFERRED,
                extraction_method=ExtractionMethod.LLM_INFERRED,
                evidence_ref=(f"business-flow:/business_flows/{flow_index}/state_transitions/{index}"),
            )

    def _codegraph_calls(self) -> None:
        for codegraph_id, source_id in sorted(self.codegraph_ids.items()):
            node = self.codegraph.node(codegraph_id)
            if node is None:
                continue
            edges = node.get("edges", [])
            if not isinstance(edges, list):
                continue
            for edge in edges:
                if not isinstance(edge, dict) or edge.get("kind") != "calls":
                    continue
                if edge.get("source") != codegraph_id:
                    continue
                target_codegraph_id = _text(edge.get("target"))
                target_id = self.codegraph_ids.get(target_codegraph_id) if target_codegraph_id is not None else None
                if target_id is None or target_codegraph_id is None:
                    continue
                edge_identity = _text(edge.get("id")) or (f"{codegraph_id}->{target_codegraph_id}")
                self._add_edge(
                    kind="calls",
                    source_id=source_id,
                    target_id=target_id,
                    attributes={"codegraph_edge_id": edge.get("id")},
                    confidence=SecurityConfidence.CONFIRMED,
                    extraction_method=ExtractionMethod.DETERMINISTIC,
                    evidence_ref=f"codegraph:edge:{edge_identity}",
                    codegraph_node_ids=[codegraph_id, target_codegraph_id],
                )


def _projection(
    nodes: list[SecurityNode],
    edges: list[SecurityEdge],
    *,
    node_kinds: set[str],
    edge_kinds: set[str] | None = None,
) -> JsonValue:
    selected_nodes = [node for node in nodes if node.kind in node_kinds]
    selected_ids = {node.id for node in selected_nodes}
    selected_edges = [
        edge
        for edge in edges
        if edge.source_id in selected_ids or edge.target_id in selected_ids
        if edge_kinds is None or edge.kind in edge_kinds
    ]
    return json_compatible(
        {
            "nodes": [node.model_dump(mode="json") for node in selected_nodes],
            "edges": [edge.model_dump(mode="json") for edge in selected_edges],
        }
    )


def business_flow_to_security_ir_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    business_input = inputs[LEGACY_BUSINESS_FLOW_CAPABILITY]
    graph_input = inputs[CODEGRAPH_CAPABILITY]
    value = _JSON.validate_json(business_input.payload)
    if not isinstance(value, dict):
        raise TypeError("legacy business-flow Artifact must contain a JSON object")

    graph_path = context.temp_dir / "codegraph" / "codegraph.db"
    context.artifact_store.materialize(
        graph_input.artifact.content_hash,
        graph_path,
        expected_size=graph_input.artifact.size_bytes,
    )
    builder = BusinessFlowSecurityIRBuilder(
        context=context,
        source_artifact_ids=[
            business_input.artifact.id,
            graph_input.artifact.id,
        ],
        codegraph=CodegraphHandle(str(graph_path)),
    )
    nodes, edges = builder.build(value)

    staging_root = context.temp_dir / "security-ir-staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{context.scan.id}.",
        suffix=".db",
        dir=staging_root,
    )
    os.close(descriptor)
    security_graph_path = Path(temporary_name)
    security_graph_path.unlink()
    SecurityGraphStore.create(
        security_graph_path,
        nodes=nodes,
        edges=edges,
    )
    graph_metadata: dict[str, JsonValue] = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "security_graph_schema": SECURITY_GRAPH_SCHEMA_VERSION,
    }
    return [
        RuntimeOutput(
            capability=SECURITY_ROUTES_CAPABILITY,
            artifact_type="security.routes",
            schema_version="1.0",
            media_type="application/json",
            json_value=_projection(
                nodes,
                edges,
                node_kinds={"http.route", "code.function"},
                edge_kinds={"handled_by", "calls"},
            ),
        ),
        RuntimeOutput(
            capability=SECURITY_BUSINESS_FLOW_CAPABILITY,
            artifact_type="security.business-flow",
            schema_version="1.0",
            media_type="application/json",
            json_value=_projection(
                nodes,
                edges,
                node_kinds={
                    "business.flow",
                    "business.operation",
                    "state.transition",
                    "data.source",
                },
            ),
        ),
        RuntimeOutput(
            capability=SECURITY_AUTHORIZATION_CAPABILITY,
            artifact_type="security.authorization",
            schema_version="1.0",
            media_type="application/json",
            json_value=_projection(
                nodes,
                edges,
                node_kinds={"auth.guard", "auth.policy", "identity.role"},
                edge_kinds={"guarded_by", "authorizes"},
            ),
        ),
        RuntimeOutput(
            capability=SECURITY_RESOURCES_CAPABILITY,
            artifact_type="security.resources",
            schema_version="1.0",
            media_type="application/json",
            json_value=_projection(
                nodes,
                edges,
                node_kinds={"resource.entity", "tenant"},
                edge_kinds={"reads", "writes", "owns", "belongs_to"},
            ),
        ),
        RuntimeOutput(
            capability=SECURITY_GRAPH_CAPABILITY,
            artifact_type="security.graph",
            schema_version=SECURITY_GRAPH_SCHEMA_VERSION,
            media_type="application/vnd.sqlite3",
            source_path=security_graph_path,
            metadata=graph_metadata,
            cleanup_source=True,
        ),
    ]
