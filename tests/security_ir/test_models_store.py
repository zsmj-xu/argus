from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest
from pydantic import ValidationError

from argus.domain.errors import SchemaValidationError
from argus.security_ir.models import SecurityConfidence, SecurityEdge, SecurityNode
from argus.security_ir.store import SecurityGraphStore

from .helpers import graph_fixture, provenance


def test_models_require_namespaced_kinds_and_complete_provenance() -> None:
    with pytest.raises(ValidationError, match="core kind or namespaced"):
        SecurityNode(
            id="route",
            kind="route",
            name="GET /orders",
            provenance=provenance(),
            confidence=SecurityConfidence.INFERRED,
        )
    with pytest.raises(ValidationError, match="extension edge kinds"):
        SecurityEdge(
            id="edge",
            kind="custom",
            source_id="a",
            target_id="b",
            provenance=provenance(),
            confidence=SecurityConfidence.INFERRED,
        )


def test_security_graph_round_trip_and_required_indexes(tmp_path: Path) -> None:
    nodes, edges = graph_fixture()
    path = tmp_path / "security-graph.db"

    store = SecurityGraphStore.create(path, nodes=nodes, edges=edges)

    assert store.get_node("node-0") == nodes[0]
    assert store.get_edge("edge-0") == edges[0]
    connection = sqlite3.connect(path)
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    finally:
        connection.close()
    assert {
        "nodes",
        "edges",
        "node_locations",
        "provenance",
        "original_codegraph_nodes",
    } <= tables
    assert {
        "ix_nodes_kind",
        "ix_edges_source",
        "ix_edges_target",
        "ix_node_locations_file_line",
        "ix_original_codegraph_node_id",
    } <= indexes
    assert "codegraph_metadata" not in tables


def test_security_graph_rejects_dangling_edges_without_replacing_target(
    tmp_path: Path,
) -> None:
    nodes, edges = graph_fixture(count=2)
    path = tmp_path / "security.db"
    SecurityGraphStore.create(path, nodes=nodes, edges=edges)
    original = path.read_bytes()
    dangling = edges[0].model_copy(update={"target_id": "missing"})

    with pytest.raises(SchemaValidationError, match="missing nodes"):
        SecurityGraphStore.create(path, nodes=nodes, edges=[dangling])

    assert path.read_bytes() == original
