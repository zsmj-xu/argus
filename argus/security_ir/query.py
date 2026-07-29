"""Resource-bounded Security Graph query API."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from enum import Enum

from argus.security_ir.models import (
    GraphPath,
    GraphSlice,
    PathQueryResult,
    SecurityEdge,
    SecurityNode,
)
from argus.security_ir.store import SecurityGraphStore

HARD_MAX_NODES = 500
HARD_MAX_DEPTH = 8
HARD_MAX_PATHS = 100
HARD_MAX_EDGES = 2_000
HARD_MAX_FILTER_VALUES = 100
DEFAULT_MAX_NODES = 100
DEFAULT_MAX_PATHS = 20


class QueryLimitError(ValueError):
    """A graph query asks for more work than the service permits."""


class Direction(str, Enum):
    INCOMING = "incoming"
    OUTGOING = "outgoing"
    BOTH = "both"


def _bounded(name: str, value: int, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise QueryLimitError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_values(
    name: str,
    values: Iterable[str] | None,
    *,
    maximum: int = HARD_MAX_FILTER_VALUES,
) -> list[str] | None:
    if values is None:
        return None
    unique = list(dict.fromkeys(values))
    if len(unique) > maximum:
        raise QueryLimitError(f"{name} may contain at most {maximum} values")
    if any(not value or len(value) > 512 for value in unique):
        raise QueryLimitError(f"{name} contains an invalid value")
    return unique


class SecurityGraphQuery:
    def __init__(self, store: SecurityGraphStore) -> None:
        self.store = store

    def get_node(self, node_id: str) -> SecurityNode | None:
        return self.store.get_node(node_id)

    def nodes_for_codegraph_id(
        self,
        codegraph_node_id: str,
        *,
        max_nodes: int = 20,
    ) -> GraphSlice:
        limit = _bounded(
            "max_nodes",
            max_nodes,
            minimum=1,
            maximum=HARD_MAX_NODES,
        )
        if not codegraph_node_id or len(codegraph_node_id) > 512:
            raise QueryLimitError("codegraph_node_id is invalid")
        nodes, truncated = self.store.find_nodes_by_codegraph_id(
            codegraph_node_id,
            limit=limit,
        )
        return GraphSlice(
            seed_ids=[],
            nodes=nodes,
            edges=[],
            truncated=truncated,
            max_nodes=limit,
            radius=0,
        )

    def find_nodes(
        self,
        *,
        kind: str | None = None,
        name: str | None = None,
        location: tuple[str, int | None] | None = None,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        limit = _bounded(
            "max_nodes",
            max_nodes,
            minimum=1,
            maximum=HARD_MAX_NODES,
        )
        file = location[0] if location is not None else None
        line = location[1] if location is not None else None
        nodes, truncated = self.store.find_nodes(
            kind=kind,
            name=name,
            file=file,
            line=line,
            limit=limit,
        )
        return GraphSlice(
            seed_ids=[],
            nodes=nodes,
            edges=[],
            truncated=truncated,
            max_nodes=limit,
            radius=0,
        )

    def neighbors(
        self,
        node_id: str,
        *,
        edge_kinds: Iterable[str] | None = None,
        direction: Direction = Direction.BOTH,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        limit = _bounded(
            "max_nodes",
            max_nodes,
            minimum=1,
            maximum=HARD_MAX_NODES,
        )
        seed = self.store.get_node(node_id)
        if seed is None:
            return GraphSlice(
                seed_ids=[node_id],
                nodes=[],
                edges=[],
                max_nodes=limit,
                radius=1,
            )
        edge_values = _bounded_values("edge_kinds", edge_kinds)
        edges, edges_truncated = self.store.neighbor_edges(
            node_id,
            edge_kinds=set(edge_values) if edge_values is not None else None,
            direction=direction.value,
            limit=min(HARD_MAX_EDGES, limit * 8),
        )
        neighbor_ids: list[str] = []
        for edge in edges:
            candidate = edge.target_id if edge.source_id == node_id else edge.source_id
            if candidate not in neighbor_ids:
                neighbor_ids.append(candidate)
        truncated = edges_truncated or len(neighbor_ids) > max(0, limit - 1)
        selected_ids = {node_id, *neighbor_ids[: max(0, limit - 1)]}
        selected_edges = [edge for edge in edges if edge.source_id in selected_ids and edge.target_id in selected_ids]
        return GraphSlice(
            seed_ids=[node_id],
            nodes=self.store.get_nodes(selected_ids),
            edges=selected_edges,
            truncated=truncated,
            max_nodes=limit,
            radius=1,
        )

    def find_paths(
        self,
        source_ids: Iterable[str],
        target_ids: Iterable[str],
        *,
        edge_kinds: Iterable[str] | None = None,
        max_depth: int = 4,
        max_paths: int = DEFAULT_MAX_PATHS,
    ) -> PathQueryResult:
        depth_limit = _bounded(
            "max_depth",
            max_depth,
            minimum=0,
            maximum=HARD_MAX_DEPTH,
        )
        path_limit = _bounded(
            "max_paths",
            max_paths,
            minimum=1,
            maximum=HARD_MAX_PATHS,
        )
        source_values = _bounded_values(
            "source_ids",
            source_ids,
            maximum=HARD_MAX_NODES,
        )
        target_values = _bounded_values(
            "target_ids",
            target_ids,
            maximum=HARD_MAX_NODES,
        )
        sources = sorted(source_values or [])
        targets = set(target_values or [])
        edge_values = _bounded_values("edge_kinds", edge_kinds)
        allowed_edges = set(edge_values) if edge_values is not None else None
        queue: deque[tuple[list[str], list[str]]] = deque(
            ([source], []) for source in sources if self.store.get_node(source) is not None
        )
        paths: list[GraphPath] = []
        expanded = 0
        truncated = False
        while queue and len(paths) < path_limit:
            node_path, edge_path = queue.popleft()
            current = node_path[-1]
            if current in targets:
                paths.append(GraphPath(node_ids=node_path, edge_ids=edge_path))
                continue
            if len(edge_path) >= depth_limit:
                continue
            edges, edge_truncated = self.store.neighbor_edges(
                current,
                edge_kinds=allowed_edges,
                direction="outgoing",
                limit=HARD_MAX_EDGES,
            )
            truncated = truncated or edge_truncated
            outgoing = sorted(
                edges,
                key=lambda edge: (edge.kind, edge.target_id, edge.id),
            )
            for edge in outgoing:
                if edge.target_id in node_path:
                    continue
                queue.append(
                    (
                        [*node_path, edge.target_id],
                        [*edge_path, edge.id],
                    )
                )
                expanded += 1
                if expanded >= HARD_MAX_EDGES:
                    truncated = True
                    queue.clear()
                    break
        if queue:
            truncated = True
        return PathQueryResult(
            paths=paths,
            truncated=truncated,
            max_depth=depth_limit,
            max_paths=path_limit,
        )

    def subgraph(
        self,
        seed_ids: Iterable[str],
        *,
        radius: int = 2,
        allowed_kinds: Iterable[str] | None = None,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        radius_limit = _bounded(
            "radius",
            radius,
            minimum=0,
            maximum=HARD_MAX_DEPTH,
        )
        node_limit = _bounded(
            "max_nodes",
            max_nodes,
            minimum=1,
            maximum=HARD_MAX_NODES,
        )
        allowed_values = _bounded_values("allowed_kinds", allowed_kinds)
        allowed = set(allowed_values) if allowed_values is not None else None
        all_seeds = (
            _bounded_values(
                "seed_ids",
                seed_ids,
                maximum=HARD_MAX_NODES,
            )
            or []
        )
        requested_seeds = all_seeds[:node_limit]
        initial = [
            node for node in self.store.get_nodes(set(requested_seeds)) if allowed is None or node.kind in allowed
        ]
        selected = {node.id for node in initial[:node_limit]}
        frontier = {node.id for node in initial[:node_limit]}
        truncated = len(all_seeds) > node_limit or len(initial) > node_limit
        selected_edges: dict[str, SecurityEdge] = {}
        for _depth in range(radius_limit):
            if not frontier or len(selected) >= node_limit:
                if frontier and len(selected) >= node_limit:
                    truncated = True
                break
            edges, edge_truncated = self.store.edges_for_nodes(
                frontier,
                incident=True,
                limit=HARD_MAX_EDGES,
            )
            truncated = truncated or edge_truncated
            candidate_ids = {
                endpoint for edge in edges for endpoint in (edge.source_id, edge.target_id) if endpoint not in selected
            }
            candidates = self.store.get_nodes(candidate_ids)
            if allowed is not None:
                candidates = [node for node in candidates if node.kind in allowed]
            slots = node_limit - len(selected)
            next_nodes = candidates[:slots]
            if len(candidates) > slots:
                truncated = True
            next_frontier = {node.id for node in next_nodes}
            selected.update(next_frontier)
            for edge in edges:
                if edge.source_id in selected and edge.target_id in selected:
                    selected_edges[edge.id] = edge
            frontier = next_frontier
        final_edges, edge_truncated = self.store.edges_for_nodes(
            selected,
            limit=HARD_MAX_EDGES,
        )
        truncated = truncated or edge_truncated
        for edge in final_edges:
            selected_edges[edge.id] = edge
        return GraphSlice(
            seed_ids=requested_seeds,
            nodes=self.store.get_nodes(selected),
            edges=sorted(selected_edges.values(), key=lambda edge: edge.id),
            truncated=truncated,
            max_nodes=node_limit,
            radius=radius_limit,
        )
