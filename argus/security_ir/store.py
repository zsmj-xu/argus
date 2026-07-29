"""Independent SQLite storage for one immutable Security Graph Artifact."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
from contextlib import closing
from typing import Literal

from pydantic import ValidationError

from argus.domain.errors import SchemaValidationError
from argus.security_ir.models import (
    SecurityCodeLocation,
    SecurityEdge,
    SecurityNode,
    SecurityProvenance,
)

SECURITY_GRAPH_SCHEMA_VERSION = "1.0"
SECURITY_GRAPH_APPLICATION_ID = 0x41524753  # "ARGS"


class SecurityGraphError(RuntimeError):
    """The Security Graph database is unreadable or violates its schema."""


def _json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


class SecurityGraphStore:
    """Read/write boundary for a single Security Graph SQLite file.

    ``create`` writes a sibling temporary database and atomically replaces the
    destination only after foreign-key and integrity checks succeed. Instances
    subsequently open the database read-only for every query.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"security graph database not found: {self.path}")
        self._validate_database()

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        nodes: list[SecurityNode],
        edges: list[SecurityEdge],
    ) -> SecurityGraphStore:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            connection = sqlite3.connect(temporary)
            try:
                cls._initialize(connection)
                cls._insert_graph(connection, nodes=nodes, edges=edges)
                foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_key_errors:
                    raise SecurityGraphError(f"security graph has dangling references: {foreign_key_errors[:3]}")
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise SecurityGraphError(f"security graph integrity check failed: {integrity}")
                connection.commit()
            finally:
                connection.close()
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return cls(destination)

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            f"""
            PRAGMA foreign_keys = ON;
            PRAGMA application_id = {SECURITY_GRAPH_APPLICATION_ID};
            PRAGMA user_version = 1;

            CREATE TABLE graph_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE nodes (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                attributes_json TEXT NOT NULL,
                confidence TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE edges (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                source_id TEXT NOT NULL REFERENCES nodes(id),
                target_id TEXT NOT NULL REFERENCES nodes(id),
                attributes_json TEXT NOT NULL,
                confidence TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE node_locations (
                node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                file TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER,
                codegraph_node_id TEXT,
                PRIMARY KEY (node_id, ordinal)
            ) WITHOUT ROWID;

            CREATE TABLE provenance (
                owner_type TEXT NOT NULL CHECK(owner_type IN ('node', 'edge')),
                owner_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                producer_plugin_id TEXT NOT NULL,
                producer_plugin_version TEXT NOT NULL,
                source_artifact_ids_json TEXT NOT NULL,
                original_codegraph_node_ids_json TEXT NOT NULL,
                extraction_method TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                PRIMARY KEY (owner_type, owner_id)
            ) WITHOUT ROWID;

            CREATE TABLE original_codegraph_nodes (
                owner_type TEXT NOT NULL CHECK(owner_type IN ('node', 'edge')),
                owner_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                PRIMARY KEY (owner_type, owner_id, node_id)
            ) WITHOUT ROWID;

            CREATE INDEX ix_nodes_kind ON nodes(kind);
            CREATE INDEX ix_nodes_name ON nodes(name);
            CREATE INDEX ix_edges_kind ON edges(kind);
            CREATE INDEX ix_edges_source ON edges(source_id);
            CREATE INDEX ix_edges_target ON edges(target_id);
            CREATE INDEX ix_node_locations_file_line
                ON node_locations(file, start_line, end_line);
            CREATE INDEX ix_node_locations_codegraph_node
                ON node_locations(codegraph_node_id);
            CREATE INDEX ix_original_codegraph_node_id
                ON original_codegraph_nodes(node_id);
            """
        )
        connection.execute(
            "INSERT INTO graph_metadata(key, value) VALUES (?, ?)",
            ("schema_version", SECURITY_GRAPH_SCHEMA_VERSION),
        )

    @classmethod
    def _insert_graph(
        cls,
        connection: sqlite3.Connection,
        *,
        nodes: list[SecurityNode],
        edges: list[SecurityEdge],
    ) -> None:
        node_ids = [node.id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise SchemaValidationError("security graph contains duplicate node IDs")
        edge_ids = [edge.id for edge in edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise SchemaValidationError("security graph contains duplicate edge IDs")
        known_nodes = set(node_ids)
        for edge in edges:
            missing = {edge.source_id, edge.target_id} - known_nodes
            if missing:
                raise SchemaValidationError(f"security edge {edge.id!r} references missing nodes: {sorted(missing)}")

        for node in sorted(nodes, key=lambda item: item.id):
            connection.execute(
                """
                INSERT INTO nodes(id, kind, name, attributes_json, confidence)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    node.id,
                    node.kind,
                    node.name,
                    _json(node.attributes),
                    node.confidence.value,
                ),
            )
            for ordinal, location in enumerate(node.code_locations):
                connection.execute(
                    """
                    INSERT INTO node_locations(
                        node_id, ordinal, file, start_line, end_line,
                        codegraph_node_id
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node.id,
                        ordinal,
                        location.file,
                        location.start_line,
                        location.end_line,
                        location.codegraph_node_id,
                    ),
                )
            cls._insert_provenance(
                connection,
                owner_type="node",
                owner_id=node.id,
                provenance=node.provenance,
            )

        for edge in sorted(edges, key=lambda item: item.id):
            connection.execute(
                """
                INSERT INTO edges(
                    id, kind, source_id, target_id, attributes_json, confidence
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.id,
                    edge.kind,
                    edge.source_id,
                    edge.target_id,
                    _json(edge.attributes),
                    edge.confidence.value,
                ),
            )
            cls._insert_provenance(
                connection,
                owner_type="edge",
                owner_id=edge.id,
                provenance=edge.provenance,
            )

    @staticmethod
    def _insert_provenance(
        connection: sqlite3.Connection,
        *,
        owner_type: Literal["node", "edge"],
        owner_id: str,
        provenance: SecurityProvenance,
    ) -> None:
        connection.execute(
            """
            INSERT INTO provenance(
                owner_type, owner_id, snapshot_id, producer_plugin_id,
                producer_plugin_version, source_artifact_ids_json,
                original_codegraph_node_ids_json, extraction_method,
                evidence_refs_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_type,
                owner_id,
                str(provenance.snapshot_id),
                provenance.producer_plugin_id,
                provenance.producer_plugin_version,
                _json([str(item) for item in provenance.source_artifact_ids]),
                _json(provenance.original_codegraph_node_ids),
                provenance.extraction_method.value,
                _json(provenance.evidence_refs),
            ),
        )
        connection.executemany(
            """
            INSERT INTO original_codegraph_nodes(owner_type, owner_id, node_id)
            VALUES (?, ?, ?)
            """,
            [(owner_type, owner_id, node_id) for node_id in provenance.original_codegraph_node_ids],
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return connection

    def _validate_database(self) -> None:
        try:
            with closing(self._connect()) as connection:
                application_id = connection.execute("PRAGMA application_id").fetchone()
                if application_id is None or application_id[0] != SECURITY_GRAPH_APPLICATION_ID:
                    raise SecurityGraphError("SQLite file is not an Argus Security Graph")
                schema = connection.execute("SELECT value FROM graph_metadata WHERE key = 'schema_version'").fetchone()
                if schema is None or schema[0] != SECURITY_GRAPH_SCHEMA_VERSION:
                    raise SecurityGraphError(f"unsupported Security Graph schema: {schema[0] if schema else None}")
        except sqlite3.DatabaseError as exc:
            raise SecurityGraphError(f"invalid Security Graph database: {exc}") from exc

    def get_node(self, node_id: str) -> SecurityNode | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM nodes WHERE id = ?",
                (node_id,),
            ).fetchone()
            if row is None:
                return None
            return self._node_from_row(connection, row)

    def get_edge(self, edge_id: str) -> SecurityEdge | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM edges WHERE id = ?",
                (edge_id,),
            ).fetchone()
            if row is None:
                return None
            return self._edge_from_row(connection, row)

    def find_nodes(
        self,
        *,
        kind: str | None = None,
        name: str | None = None,
        file: str | None = None,
        line: int | None = None,
        limit: int,
    ) -> tuple[list[SecurityNode], bool]:
        conditions: list[str] = []
        parameters: list[object] = []
        joins = ""
        if kind is not None:
            conditions.append("n.kind = ?")
            parameters.append(kind)
        if name is not None:
            conditions.append("lower(n.name) LIKE ? ESCAPE '\\'")
            escaped = name.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            parameters.append(f"%{escaped}%")
        if file is not None or line is not None:
            joins = " JOIN node_locations l ON l.node_id = n.id"
        if file is not None:
            conditions.append("l.file = ?")
            parameters.append(file)
        if line is not None:
            conditions.append("l.start_line <= ? AND COALESCE(l.end_line, l.start_line) >= ?")
            parameters.extend([line, line])
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        statement = f"SELECT DISTINCT n.* FROM nodes n{joins}{where} ORDER BY n.kind, n.name, n.id LIMIT ?"
        parameters.append(limit + 1)
        with closing(self._connect()) as connection:
            rows = connection.execute(statement, parameters).fetchall()
            truncated = len(rows) > limit
            return (
                [self._node_from_row(connection, row) for row in rows[:limit]],
                truncated,
            )

    def edges_for_nodes(
        self,
        node_ids: set[str],
        *,
        edge_kinds: set[str] | None = None,
        incident: bool = False,
        limit: int,
    ) -> tuple[list[SecurityEdge], bool]:
        if not node_ids:
            return [], False
        ordered_ids = sorted(node_ids)
        placeholders = ",".join("?" for _ in ordered_ids)
        endpoint_clause = (
            f"(source_id IN ({placeholders}) OR target_id IN ({placeholders}))"
            if incident
            else f"(source_id IN ({placeholders}) AND target_id IN ({placeholders}))"
        )
        parameters: list[object] = [*ordered_ids, *ordered_ids]
        kind_clause = ""
        if edge_kinds:
            ordered_kinds = sorted(edge_kinds)
            kind_placeholders = ",".join("?" for _ in ordered_kinds)
            kind_clause = f" AND kind IN ({kind_placeholders})"
            parameters.extend(ordered_kinds)
        parameters.append(limit + 1)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM edges
                WHERE {endpoint_clause}{kind_clause}
                ORDER BY kind, source_id, target_id, id
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            truncated = len(rows) > limit
            return (
                [self._edge_from_row(connection, row) for row in rows[:limit]],
                truncated,
            )

    def neighbor_edges(
        self,
        node_id: str,
        *,
        direction: Literal["incoming", "outgoing", "both"],
        edge_kinds: set[str] | None = None,
        limit: int,
    ) -> tuple[list[SecurityEdge], bool]:
        endpoint_clause = {
            "incoming": "target_id = ?",
            "outgoing": "source_id = ?",
            "both": "(source_id = ? OR target_id = ?)",
        }[direction]
        parameters: list[object] = [node_id, node_id] if direction == "both" else [node_id]
        kind_clause = ""
        if edge_kinds:
            ordered_kinds = sorted(edge_kinds)
            placeholders = ",".join("?" for _ in ordered_kinds)
            kind_clause = f" AND kind IN ({placeholders})"
            parameters.extend(ordered_kinds)
        parameters.append(limit + 1)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM edges
                WHERE {endpoint_clause}{kind_clause}
                ORDER BY kind, source_id, target_id, id
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            truncated = len(rows) > limit
            return (
                [self._edge_from_row(connection, row) for row in rows[:limit]],
                truncated,
            )

    def get_nodes(self, node_ids: set[str]) -> list[SecurityNode]:
        if not node_ids:
            return []
        ordered = sorted(node_ids)
        placeholders = ",".join("?" for _ in ordered)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"SELECT * FROM nodes WHERE id IN ({placeholders}) ORDER BY kind, name, id",
                ordered,
            ).fetchall()
            return [self._node_from_row(connection, row) for row in rows]

    def find_nodes_by_codegraph_id(
        self,
        codegraph_node_id: str,
        *,
        limit: int,
    ) -> tuple[list[SecurityNode], bool]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT n.*
                FROM original_codegraph_nodes o
                JOIN nodes n ON n.id = o.owner_id
                WHERE o.owner_type = 'node' AND o.node_id = ?
                ORDER BY n.kind, n.name, n.id
                LIMIT ?
                """,
                (codegraph_node_id, limit + 1),
            ).fetchall()
            return (
                [self._node_from_row(connection, row) for row in rows[:limit]],
                len(rows) > limit,
            )

    def _node_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> SecurityNode:
        locations = connection.execute(
            """
            SELECT file, start_line, end_line, codegraph_node_id
            FROM node_locations WHERE node_id = ? ORDER BY ordinal
            """,
            (row["id"],),
        ).fetchall()
        try:
            return SecurityNode(
                id=row["id"],
                kind=row["kind"],
                name=row["name"],
                code_locations=[
                    SecurityCodeLocation(
                        file=item["file"],
                        start_line=item["start_line"],
                        end_line=item["end_line"],
                        codegraph_node_id=item["codegraph_node_id"],
                    )
                    for item in locations
                ],
                attributes=json.loads(row["attributes_json"]),
                confidence=row["confidence"],
                provenance=self._provenance(connection, "node", row["id"]),
            )
        except (json.JSONDecodeError, ValidationError) as exc:
            raise SecurityGraphError(f"invalid persisted SecurityNode {row['id']!r}") from exc

    def _edge_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> SecurityEdge:
        try:
            return SecurityEdge(
                id=row["id"],
                kind=row["kind"],
                source_id=row["source_id"],
                target_id=row["target_id"],
                attributes=json.loads(row["attributes_json"]),
                confidence=row["confidence"],
                provenance=self._provenance(connection, "edge", row["id"]),
            )
        except (json.JSONDecodeError, ValidationError) as exc:
            raise SecurityGraphError(f"invalid persisted SecurityEdge {row['id']!r}") from exc

    @staticmethod
    def _provenance(
        connection: sqlite3.Connection,
        owner_type: Literal["node", "edge"],
        owner_id: str,
    ) -> SecurityProvenance:
        row = connection.execute(
            "SELECT * FROM provenance WHERE owner_type = ? AND owner_id = ?",
            (owner_type, owner_id),
        ).fetchone()
        if row is None:
            raise SecurityGraphError(f"missing provenance for {owner_type} {owner_id!r}")
        try:
            return SecurityProvenance(
                snapshot_id=row["snapshot_id"],
                producer_plugin_id=row["producer_plugin_id"],
                producer_plugin_version=row["producer_plugin_version"],
                source_artifact_ids=json.loads(row["source_artifact_ids_json"]),
                original_codegraph_node_ids=json.loads(row["original_codegraph_node_ids_json"]),
                extraction_method=row["extraction_method"],
                evidence_refs=json.loads(row["evidence_refs_json"]),
            )
        except (json.JSONDecodeError, ValidationError) as exc:
            raise SecurityGraphError(f"invalid provenance for {owner_type} {owner_id!r}") from exc
