"""Control-plane data service for persisted Security Graph Artifacts."""

from __future__ import annotations

from uuid import UUID

from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories
from argus.domain.errors import NotFoundError, SchemaValidationError
from argus.security_ir.business_flow_adapter import SECURITY_GRAPH_CAPABILITY
from argus.security_ir.models import GraphSlice, SecurityNode
from argus.security_ir.query import (
    DEFAULT_MAX_NODES,
    Direction,
    SecurityGraphQuery,
)
from argus.security_ir.store import SecurityGraphStore


class SecurityGraphService:
    def __init__(
        self,
        repositories: Repositories,
        artifact_store: ArtifactStore,
    ) -> None:
        self.repositories = repositories
        self.artifact_store = artifact_store

    def query_for_scan(self, scan_id: UUID) -> SecurityGraphQuery:
        scan = self.repositories.scans.get(scan_id)
        artifact = self.repositories.artifacts.find_latest_by_capability(
            scan_id=scan_id,
            capability=SECURITY_GRAPH_CAPABILITY,
        )
        if artifact is None:
            raise NotFoundError(f"Security Graph Artifact not found for scan: {scan_id}")
        if artifact.snapshot_id != scan.snapshot_id:
            raise SchemaValidationError("Security Graph Artifact does not belong to the scan snapshot")
        if artifact.media_type != "application/vnd.sqlite3":
            raise SchemaValidationError(f"Security Graph Artifact has invalid media type: {artifact.media_type}")
        path = self.artifact_store.verified_path(
            artifact.content_hash,
            expected_size=artifact.size_bytes,
        )
        return SecurityGraphQuery(SecurityGraphStore(path))

    def find_nodes(
        self,
        scan_id: UUID,
        *,
        kind: str | None = None,
        name: str | None = None,
        file: str | None = None,
        line: int | None = None,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        location = (file, line) if file is not None else None
        return self.query_for_scan(scan_id).find_nodes(
            kind=kind,
            name=name,
            location=location,
            max_nodes=max_nodes,
        )

    def get_node(self, scan_id: UUID, node_id: str) -> SecurityNode:
        node = self.query_for_scan(scan_id).get_node(node_id)
        if node is None:
            raise NotFoundError(f"Security IR node not found: {node_id}")
        return node

    def graph_slice(
        self,
        scan_id: UUID,
        *,
        seed_ids: list[str],
        radius: int = 2,
        allowed_kinds: list[str] | None = None,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        return self.query_for_scan(scan_id).subgraph(
            seed_ids,
            radius=radius,
            allowed_kinds=allowed_kinds,
            max_nodes=max_nodes,
        )

    def neighbors(
        self,
        scan_id: UUID,
        node_id: str,
        *,
        edge_kinds: list[str] | None = None,
        direction: Direction = Direction.BOTH,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        return self.query_for_scan(scan_id).neighbors(
            node_id,
            edge_kinds=edge_kinds,
            direction=direction,
            max_nodes=max_nodes,
        )
