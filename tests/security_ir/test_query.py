from __future__ import annotations

from pathlib import Path

import pytest

from argus.security_ir.query import (
    HARD_MAX_DEPTH,
    HARD_MAX_NODES,
    HARD_MAX_PATHS,
    Direction,
    QueryLimitError,
    SecurityGraphQuery,
)
from argus.security_ir.models import SecurityConfidence, SecurityEdge
from argus.security_ir.store import SecurityGraphStore

from .helpers import graph_fixture, provenance


def _query(tmp_path: Path, *, count: int = 8) -> SecurityGraphQuery:
    nodes, edges = graph_fixture(count=count)
    return SecurityGraphQuery(
        SecurityGraphStore.create(
            tmp_path / "security.db",
            nodes=nodes,
            edges=edges,
        )
    )


def test_find_nodes_filters_kind_name_and_location(tmp_path: Path) -> None:
    query = _query(tmp_path)

    by_kind = query.find_nodes(kind="http.route")
    by_name = query.find_nodes(name="node 4")
    by_location = query.find_nodes(location=("src/app.py", 5))

    assert {node.kind for node in by_kind.nodes} == {"http.route"}
    assert [node.id for node in by_name.nodes] == ["node-4"]
    assert {node.id for node in by_location.nodes} == {"node-3", "node-4"}


def test_neighbors_respect_direction_and_node_limit(tmp_path: Path) -> None:
    query = _query(tmp_path)

    outgoing = query.neighbors(
        "node-3",
        direction=Direction.OUTGOING,
        max_nodes=2,
    )
    incoming = query.neighbors(
        "node-3",
        direction=Direction.INCOMING,
        max_nodes=2,
    )
    limited = query.neighbors("node-3", max_nodes=2)

    assert {node.id for node in outgoing.nodes} == {"node-3", "node-4"}
    assert {node.id for node in incoming.nodes} == {"node-2", "node-3"}
    assert limited.truncated is True
    assert len(limited.nodes) == 2


def test_outgoing_neighbors_are_not_hidden_by_many_incoming_edges(
    tmp_path: Path,
) -> None:
    nodes, _ = graph_fixture(count=23)
    edges = [
        SecurityEdge(
            id=f"incoming-{index}",
            kind="calls",
            source_id=f"node-{index}",
            target_id="node-20",
            provenance=provenance(),
            confidence=SecurityConfidence.CONFIRMED,
        )
        for index in range(20)
    ]
    edges.append(
        SecurityEdge(
            id="outgoing",
            kind="calls",
            source_id="node-20",
            target_id="node-21",
            provenance=provenance(),
            confidence=SecurityConfidence.CONFIRMED,
        )
    )
    query = SecurityGraphQuery(
        SecurityGraphStore.create(
            tmp_path / "high-degree.db",
            nodes=nodes,
            edges=edges,
        )
    )

    result = query.neighbors(
        "node-20",
        direction=Direction.OUTGOING,
        max_nodes=2,
    )

    assert {node.id for node in result.nodes} == {"node-20", "node-21"}


def test_paths_are_directed_bounded_and_deterministic(tmp_path: Path) -> None:
    query = _query(tmp_path)

    result = query.find_paths(
        ["node-0"],
        ["node-4"],
        max_depth=4,
        max_paths=3,
    )
    reverse = query.find_paths(
        ["node-4"],
        ["node-0"],
        max_depth=4,
        max_paths=3,
    )

    assert result.paths[0].node_ids == [
        "node-0",
        "node-1",
        "node-2",
        "node-3",
        "node-4",
    ]
    assert reverse.paths == []


def test_subgraph_and_all_public_limits_are_hard_bounded(tmp_path: Path) -> None:
    query = _query(tmp_path, count=12)

    graph_slice = query.subgraph(["node-5"], radius=5, max_nodes=4)

    assert len(graph_slice.nodes) == 4
    assert graph_slice.truncated is True
    with pytest.raises(QueryLimitError):
        query.subgraph(["node-0"], max_nodes=HARD_MAX_NODES + 1)
    with pytest.raises(QueryLimitError):
        query.subgraph(["node-0"], radius=HARD_MAX_DEPTH + 1)
    with pytest.raises(QueryLimitError):
        query.find_paths(
            ["node-0"],
            ["node-1"],
            max_paths=HARD_MAX_PATHS + 1,
        )
    with pytest.raises(QueryLimitError, match="seed_ids"):
        query.subgraph(
            [f"seed-{index}" for index in range(HARD_MAX_NODES + 1)],
        )
