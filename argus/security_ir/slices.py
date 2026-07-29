"""Finding-oriented Graph Slice construction."""

from __future__ import annotations

from uuid import UUID

from argus.control.repositories import FindingRepository
from argus.domain.errors import NotFoundError
from argus.security_ir.models import GraphSlice
from argus.security_ir.query import DEFAULT_MAX_NODES, SecurityGraphQuery


class FindingSliceService:
    def __init__(
        self,
        query: SecurityGraphQuery,
        findings: FindingRepository,
    ) -> None:
        self.query = query
        self.findings = findings

    def slice_for_finding(
        self,
        finding_id: UUID,
        *,
        radius: int = 2,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> GraphSlice:
        finding = self.findings.get(finding_id)
        seed_ids = list(dict.fromkeys([*finding.source_node_ids, *finding.sink_node_ids]))
        if not seed_ids:
            raise NotFoundError(f"finding has no Security IR source/sink anchors: {finding_id}")
        return self.query.subgraph(
            seed_ids,
            radius=radius,
            max_nodes=max_nodes,
        )
