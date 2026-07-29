from __future__ import annotations

from pathlib import Path
import sqlite3
from uuid import UUID, uuid4

from argus.security_ir.models import (
    ExtractionMethod,
    SecurityCodeLocation,
    SecurityConfidence,
    SecurityEdge,
    SecurityNode,
)
from argus.security_ir.provenance import security_provenance


def provenance(
    *,
    snapshot_id: UUID | None = None,
    original_ids: list[str] | None = None,
    inferred: bool = False,
):
    return security_provenance(
        snapshot_id=snapshot_id or uuid4(),
        producer_plugin_id="semantic.business-flow-to-security-ir",
        producer_plugin_version="1.0.0",
        source_artifact_ids=[uuid4(), uuid4()],
        original_codegraph_node_ids=original_ids or [],
        extraction_method=(ExtractionMethod.LLM_INFERRED if inferred else ExtractionMethod.DETERMINISTIC),
        evidence_refs=["fixture:/item/0"],
    )


def graph_fixture(
    *,
    count: int = 6,
) -> tuple[list[SecurityNode], list[SecurityEdge]]:
    snapshot_id = uuid4()
    nodes = [
        SecurityNode(
            id=f"node-{index}",
            kind="code.function" if index % 2 == 0 else "http.route",
            name=f"node {index}",
            code_locations=[
                SecurityCodeLocation(
                    file="src/app.py",
                    start_line=index + 1,
                    end_line=index + 2,
                    codegraph_node_id=f"cg-{index}",
                )
            ],
            attributes={"index": index},
            provenance=provenance(
                snapshot_id=snapshot_id,
                original_ids=[f"cg-{index}"],
            ),
            confidence=SecurityConfidence.CONFIRMED,
        )
        for index in range(count)
    ]
    edges = [
        SecurityEdge(
            id=f"edge-{index}",
            kind="calls",
            source_id=f"node-{index}",
            target_id=f"node-{index + 1}",
            attributes={"index": index},
            provenance=provenance(
                snapshot_id=snapshot_id,
                original_ids=[f"cg-{index}", f"cg-{index + 1}"],
            ),
            confidence=SecurityConfidence.CONFIRMED,
        )
        for index in range(count - 1)
    ]
    return nodes, edges


def write_codegraph(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE nodes (
                id TEXT PRIMARY KEY,
                kind TEXT,
                name TEXT,
                qualified_name TEXT,
                file_path TEXT,
                language TEXT,
                start_line INTEGER,
                end_line INTEGER,
                signature TEXT
            );
            CREATE TABLE edges (
                id TEXT PRIMARY KEY,
                source TEXT,
                target TEXT,
                kind TEXT,
                metadata TEXT,
                line INTEGER,
                col INTEGER,
                provenance TEXT
            );
            INSERT INTO nodes VALUES
                ('cg-checkout', 'function', 'checkout', 'api.checkout',
                 'api/orders.py', 'python', 40, 70, 'checkout(request)'),
                ('cg-save', 'function', 'save_order', 'db.save_order',
                 'db/orders.py', 'python', 10, 18, 'save_order(order)');
            INSERT INTO edges VALUES
                ('call-1', 'cg-checkout', 'cg-save', 'calls',
                 '{}', 55, 8, '{}');
            """
        )
        connection.commit()
    finally:
        connection.close()
