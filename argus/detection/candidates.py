"""Deterministic candidate identity, bounded slices, and source context."""

from __future__ import annotations

from collections import deque
from typing import Any, cast

from pydantic import JsonValue

from argus.detection.contracts import (
    Candidate,
    DetectionContext,
    SourceContext,
    SourceExcerpt,
)
from argus.domain.hashing import CanonicalValue, sha256_digest
from argus.security_ir.models import (
    ExtractionMethod,
    GraphSlice,
    SecurityCodeLocation,
    SecurityConfidence,
    SecurityEdge,
    SecurityNode,
    SecurityProvenance,
)
from argus.security_ir.provenance import security_provenance, stable_security_id
from argus.security_ir.query import HARD_MAX_DEPTH, HARD_MAX_NODES

DEFAULT_SLICE_MAX_NODES = 60
DEFAULT_SLICE_RADIUS = 2
DEFAULT_EXCERPT_CHARS = 3_000
DEFAULT_SOURCE_TOTAL_CHARS = 12_000
DEFAULT_SOURCE_EXCERPTS = 12


def _positive_int(
    value: object,
    default: int,
    *,
    maximum: int,
) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum:
        return value
    return default


def detection_settings(context: DetectionContext) -> dict[str, JsonValue]:
    value = context.config.get("detection", {})
    return value if isinstance(value, dict) else {}


def candidate_identity(
    context: DetectionContext,
    *,
    rule_id: str,
    rule_version: str,
    candidate_type: str,
    primary_node_ids: list[str],
    source_node_ids: list[str],
    sink_node_ids: list[str],
) -> tuple[str, str]:
    identity = {
        "snapshot_id": str(context.snapshot.id),
        "rule_id": rule_id,
        "rule_version": rule_version,
        "candidate_type": candidate_type,
        "primary_node_ids": sorted(primary_node_ids),
        "source_node_ids": sorted(source_node_ids),
        "sink_node_ids": sorted(sink_node_ids),
    }
    candidate_id = stable_security_id("candidate", identity)
    root_cause_key = sha256_digest(
        cast(
            CanonicalValue,
            {
                "rule_family": rule_id.split(".", 1)[0],
                "primary_node_ids": sorted(primary_node_ids),
                "source_node_ids": sorted(source_node_ids),
                "sink_node_ids": sorted(sink_node_ids),
            },
        )
    )
    return candidate_id, root_cause_key


def candidate_provenance(
    context: DetectionContext,
    *,
    original_codegraph_node_ids: list[str],
    evidence_refs: list[str],
) -> SecurityProvenance:
    return security_provenance(
        snapshot_id=context.snapshot.id,
        producer_plugin_id=context.plugin_id,
        producer_plugin_version=context.plugin_version,
        source_artifact_ids=context.source_artifact_ids,
        original_codegraph_node_ids=original_codegraph_node_ids,
        extraction_method=ExtractionMethod.DETERMINISTIC,
        evidence_refs=evidence_refs,
    )


class BoundedGraphSliceBuilder:
    def build(
        self,
        context: DetectionContext,
        candidate: Candidate,
    ) -> GraphSlice:
        settings = detection_settings(context)
        max_nodes = _positive_int(
            settings.get("graphSliceMaxNodes"),
            DEFAULT_SLICE_MAX_NODES,
            maximum=HARD_MAX_NODES,
        )
        radius = _positive_int(
            settings.get("graphSliceRadius"),
            DEFAULT_SLICE_RADIUS,
            maximum=HARD_MAX_DEPTH,
        )
        security_seeds = [
            node_id
            for node_id in [
                *candidate.primary_node_ids,
                *candidate.source_node_ids,
                *candidate.sink_node_ids,
                *candidate.route_ids,
                *candidate.identity_context_ids,
            ]
            if node_id.startswith("sir:")
        ]
        nodes: dict[str, SecurityNode] = {}
        edges: dict[str, SecurityEdge] = {}
        truncated = False
        if context.security_graph is not None and security_seeds:
            security_slice = context.security_graph.subgraph(
                security_seeds,
                radius=radius,
                max_nodes=max_nodes,
            )
            nodes.update((node.id, node) for node in security_slice.nodes)
            edges.update((edge.id, edge) for edge in security_slice.edges)
            truncated = security_slice.truncated

        codegraph_seeds = [
            node_id
            for node_id in [
                *candidate.primary_node_ids,
                *candidate.source_node_ids,
                *candidate.sink_node_ids,
            ]
            if not node_id.startswith("sir:")
        ]
        remaining = max_nodes - len(nodes)
        if remaining > 0 and codegraph_seeds:
            code_nodes, code_edges, code_truncated = self._codegraph_slice(
                context,
                codegraph_seeds,
                radius=radius,
                max_nodes=remaining,
            )
            nodes.update((node.id, node) for node in code_nodes)
            edges.update((edge.id, edge) for edge in code_edges)
            truncated = truncated or code_truncated
        elif codegraph_seeds:
            truncated = True

        selected_ids = set(nodes)
        edges = {
            edge_id: edge
            for edge_id, edge in edges.items()
            if edge.source_id in selected_ids and edge.target_id in selected_ids
        }
        return GraphSlice(
            seed_ids=list(
                dict.fromkeys(
                    [
                        *candidate.primary_node_ids,
                        *candidate.route_ids,
                        *candidate.source_node_ids,
                        *candidate.sink_node_ids,
                    ]
                )
            ),
            nodes=sorted(nodes.values(), key=lambda item: item.id),
            edges=sorted(edges.values(), key=lambda item: item.id),
            truncated=truncated,
            max_nodes=max_nodes,
            radius=radius,
        )

    def _codegraph_slice(
        self,
        context: DetectionContext,
        seed_ids: list[str],
        *,
        radius: int,
        max_nodes: int,
    ) -> tuple[list[SecurityNode], list[SecurityEdge], bool]:
        queue: deque[tuple[str, int]] = deque((node_id, 0) for node_id in dict.fromkeys(seed_ids))
        raw_nodes: dict[str, dict[str, Any]] = {}
        raw_edges: dict[tuple[str, str], dict[str, Any]] = {}
        truncated = False
        while queue:
            node_id, depth = queue.popleft()
            if node_id in raw_nodes:
                continue
            if len(raw_nodes) >= max_nodes:
                truncated = True
                break
            node = context.codegraph.node(node_id)
            if node is None:
                continue
            raw_nodes[node_id] = node
            edge_values = node.get("edges", [])
            if isinstance(edge_values, list):
                for edge in edge_values:
                    if (
                        isinstance(edge, dict)
                        and edge.get("kind") == "calls"
                        and isinstance(edge.get("source"), str)
                        and isinstance(edge.get("target"), str)
                    ):
                        source = str(edge["source"])
                        target = str(edge["target"])
                        raw_edges[(source, target)] = edge
            if depth >= radius:
                continue
            neighbors = [
                *context.codegraph.callers(node_id),
                *context.codegraph.callees(node_id),
            ]
            for neighbor in sorted(
                neighbors,
                key=lambda item: str(item.get("id", "")),
            ):
                neighbor_id = neighbor.get("id")
                if isinstance(neighbor_id, str) and neighbor_id:
                    queue.append((neighbor_id, depth + 1))

        nodes = [self._codegraph_node(context, node_id, raw) for node_id, raw in sorted(raw_nodes.items())]
        known = set(raw_nodes)
        edges = [
            SecurityEdge(
                id=stable_security_id(
                    "slice-call",
                    context.snapshot.id,
                    source,
                    target,
                ),
                kind="calls",
                source_id=source,
                target_id=target,
                attributes={"codegraph_edge_id": (str(raw.get("id")) if raw.get("id") is not None else None)},
                provenance=candidate_provenance(
                    context,
                    original_codegraph_node_ids=[source, target],
                    evidence_refs=[f"codegraph:edge:{raw.get('id') or f'{source}->{target}'}"],
                ),
                confidence=SecurityConfidence.CONFIRMED,
            )
            for (source, target), raw in sorted(raw_edges.items())
            if source in known and target in known
        ]
        return nodes, edges, truncated

    @staticmethod
    def _codegraph_node(
        context: DetectionContext,
        node_id: str,
        raw: dict[str, Any],
    ) -> SecurityNode:
        file = raw.get("file_path")
        start = raw.get("start_line")
        end = raw.get("end_line")
        locations: list[SecurityCodeLocation] = []
        if isinstance(file, str) and file and isinstance(start, int) and not isinstance(start, bool) and start > 0:
            locations.append(
                SecurityCodeLocation(
                    file=file,
                    start_line=start,
                    end_line=(end if isinstance(end, int) and not isinstance(end, bool) and end >= start else None),
                    codegraph_node_id=node_id,
                )
            )
        kind = "code.function" if str(raw.get("kind", "")).lower() in {"function", "method"} else "code.symbol"
        return SecurityNode(
            id=node_id,
            kind=kind,
            name=str(raw.get("name") or raw.get("qualified_name") or node_id),
            code_locations=locations,
            attributes={
                key: value
                for key, value in {
                    "qualified_name": raw.get("qualified_name"),
                    "signature": raw.get("signature"),
                    "language": raw.get("language"),
                }.items()
                if isinstance(value, (str, bool, int, float)) or value is None
            },
            provenance=candidate_provenance(
                context,
                original_codegraph_node_ids=[node_id],
                evidence_refs=[f"codegraph:node:{node_id}"],
            ),
            confidence=SecurityConfidence.CONFIRMED,
        )


class SourceContextBuilder:
    def build(
        self,
        context: DetectionContext,
        candidate: Candidate,
        graph_slice: GraphSlice,
    ) -> SourceContext:
        settings = detection_settings(context)
        excerpt_limit = _positive_int(
            settings.get("sourceExcerptChars"),
            DEFAULT_EXCERPT_CHARS,
            maximum=20_000,
        )
        total_limit = _positive_int(
            settings.get("sourceTotalChars"),
            DEFAULT_SOURCE_TOTAL_CHARS,
            maximum=100_000,
        )
        count_limit = _positive_int(
            settings.get("sourceMaxExcerpts"),
            DEFAULT_SOURCE_EXCERPTS,
            maximum=50,
        )
        excerpts: list[SourceExcerpt] = []
        total = 0
        truncated = False
        seen_locations: set[tuple[str, int, int]] = set()
        for node in graph_slice.nodes:
            for location in node.code_locations:
                end_line = location.end_line or location.start_line
                key = (location.file, location.start_line, end_line)
                if key in seen_locations:
                    continue
                seen_locations.add(key)
                if len(excerpts) >= count_limit or total >= total_limit:
                    truncated = True
                    break
                try:
                    raw = context.source.read(
                        location.file,
                        location.start_line,
                        end_line,
                    )
                except (OSError, UnicodeError):
                    continue
                remaining = total_limit - total
                text = raw[: min(excerpt_limit, remaining)]
                item_truncated = len(text) < len(raw)
                excerpts.append(
                    SourceExcerpt(
                        node_id=node.id,
                        file=location.file,
                        start_line=location.start_line,
                        end_line=end_line,
                        text=text,
                        content_hash=sha256_digest(text),
                        truncated=item_truncated,
                    )
                )
                total += len(text)
                truncated = truncated or item_truncated
            if truncated and (len(excerpts) >= count_limit or total >= total_limit):
                break
        return SourceContext(
            candidate_id=candidate.id,
            excerpts=excerpts,
            total_chars=total,
            truncated=truncated or graph_slice.truncated,
        )
