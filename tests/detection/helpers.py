from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from argus.contracts import SourceMode
from argus.detection.candidates import candidate_identity, candidate_provenance
from argus.detection.contracts import Candidate, DetectionContext
from argus.domain.enums import ScanEngine, VcsType
from argus.domain.models import Scan, SourceSnapshot

SHA = "a" * 64


class FakeGraph:
    def __init__(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        self.nodes = {str(node["id"]): dict(node) for node in nodes}
        self.edges = edges or []

    def query(self, search: str) -> list[dict[str, Any]]:
        term = search.lower()
        return [
            node
            for node in self.nodes.values()
            if term in str(node.get("name", "")).lower() or term in str(node.get("qualified_name", "")).lower()
        ]

    def node(self, node_id: str) -> dict[str, Any] | None:
        raw = self.nodes.get(node_id)
        if raw is None:
            return None
        node = dict(raw)
        node["edges"] = [edge for edge in self.edges if edge["source"] == node_id or edge["target"] == node_id]
        return node

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        return [
            self.nodes[str(edge["source"])]
            for edge in self.edges
            if edge["kind"] == "calls" and edge["target"] == symbol
        ]

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        return [
            self.nodes[str(edge["target"])]
            for edge in self.edges
            if edge["kind"] == "calls" and edge["source"] == symbol
        ]

    def explore(self, query: str) -> str:
        raise AssertionError(f"candidate detection must not explore the whole graph: {query}")


class FakeSource:
    mode = SourceMode.RAW

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def read(
        self,
        path: str,
        start: int | None = None,
        end: int | None = None,
    ) -> str:
        lines = self.files[path].splitlines(keepends=True)
        if start is None:
            return "".join(lines)
        return "".join(lines[start - 1 : end])


def make_context(
    *,
    graph: FakeGraph,
    source: FakeSource | None = None,
    security_graph: Any = None,
    config: dict[str, Any] | None = None,
    snapshot_id: UUID | None = None,
) -> DetectionContext:
    project_id = uuid4()
    resolved_snapshot_id = snapshot_id or uuid4()
    snapshot = SourceSnapshot(
        id=resolved_snapshot_id,
        project_id=project_id,
        repository_path="/repo",
        vcs_type=VcsType.DIRECTORY,
        tree_hash=SHA,
        dirty=False,
        materialized_path="/snapshot",
        manifest_artifact_id=uuid4(),
    )
    scan = Scan(
        project_id=project_id,
        snapshot_id=snapshot.id,
        config=config or {},
        config_hash=SHA,
        engine=ScanEngine.V2,
    )
    return DetectionContext(
        scan=scan,
        snapshot=snapshot,
        plugin_id="detector.test",
        plugin_version="1.0.0",
        source_artifact_ids=(uuid4(),),
        codegraph=graph,  # type: ignore[arg-type]
        security_graph=security_graph,
        source=source or FakeSource({}),
        config=scan.config,
    )


def make_candidate(context: DetectionContext, *, node_id: str = "cg-handler") -> Candidate:
    candidate_id, root_cause_key = candidate_identity(
        context,
        rule_id="injection.sink-reachability",
        rule_version="1.0.0",
        candidate_type="injection.sql",
        primary_node_ids=[node_id],
        source_node_ids=[],
        sink_node_ids=["cg-execute"],
    )
    return Candidate(
        id=candidate_id,
        rule_id="injection.sink-reachability",
        rule_version="1.0.0",
        candidate_type="injection.sql",
        primary_node_ids=[node_id],
        sink_node_ids=["cg-execute"],
        reason_codes=["SINK_SQL"],
        static_score=0.8,
        root_cause_key=root_cause_key,
        provenance=candidate_provenance(
            context,
            original_codegraph_node_ids=[node_id, "cg-execute"],
            evidence_refs=[f"codegraph:node:{node_id}"],
        ),
    )
