from __future__ import annotations

from pathlib import Path
import sqlite3
from uuid import uuid4

from argus.artifacts.store import ArtifactStore
from argus.control.db import Database, upgrade_database
from argus.control.repositories import Repositories
from argus.domain.enums import (
    FindingStatus,
    ScanEngine,
    Severity,
    StaticConfidence,
    VcsType,
)
from argus.domain.models import (
    Artifact,
    CodeLocation,
    Project,
    Scan,
    SourceSnapshot,
    StaticFindingV2,
    Task,
)
from argus.security_ir.business_flow_adapter import SECURITY_GRAPH_CAPABILITY
from argus.security_ir.service import SecurityGraphService
from argus.security_ir.slices import FindingSliceService
from argus.security_ir.store import SecurityGraphStore

from .helpers import graph_fixture

SHA_A = "a" * 64
SHA_B = "b" * 64


def test_service_resolves_verified_graph_artifact_and_finding_slice(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "control.db"
    upgrade_database(database_path)
    database = Database(database_path)
    repositories = Repositories(database)
    runs_root = tmp_path / "runs"
    artifact_store = ArtifactStore(runs_root)
    project = repositories.projects.create(Project(name="fixture", repository_path=str(tmp_path / "repo")))
    snapshot_id = uuid4()
    scan = repositories.scans.create(
        Scan(
            project_id=project.id,
            snapshot_id=snapshot_id,
            config={},
            config_hash=SHA_A,
            engine=ScanEngine.V2,
        )
    )
    snapshot = repositories.snapshots.create(
        SourceSnapshot(
            id=snapshot_id,
            project_id=project.id,
            repository_path=project.repository_path,
            vcs_type=VcsType.DIRECTORY,
            tree_hash=SHA_B,
            dirty=False,
            materialized_path=str(tmp_path / "snapshot"),
            manifest_artifact_id=uuid4(),
        )
    )
    graph_task = repositories.tasks.create(
        Task(
            scan_id=scan.id,
            plugin_id="graph.codegraph",
            plugin_version="1.0.0",
            kind="graph_provider",
            expected_capabilities=["code.graph.codegraph.v1"],
            config_hash=SHA_A,
            cache_key=SHA_A,
        )
    )
    task = repositories.tasks.create(
        Task(
            scan_id=scan.id,
            plugin_id="semantic.business-flow-to-security-ir",
            plugin_version="1.0.0",
            kind="semantic_adapter",
            expected_capabilities=[SECURITY_GRAPH_CAPABILITY],
            config_hash=SHA_A,
            cache_key=SHA_B,
        )
    )
    nodes, edges = graph_fixture()
    graph_path = tmp_path / "security.db"
    SecurityGraphStore.create(graph_path, nodes=nodes, edges=edges)
    blob = artifact_store.put_file(graph_path)
    codegraph_path = tmp_path / "codegraph.db"
    codegraph_connection = sqlite3.connect(codegraph_path)
    try:
        codegraph_connection.execute("CREATE TABLE nodes(id TEXT PRIMARY KEY, kind TEXT)")
        codegraph_connection.commit()
    finally:
        codegraph_connection.close()
    codegraph_blob = artifact_store.put_file(codegraph_path)
    codegraph_artifact = repositories.artifacts.create(
        Artifact(
            scan_id=scan.id,
            snapshot_id=snapshot.id,
            task_id=graph_task.id,
            artifact_type="code.graph.codegraph",
            schema_version="1.0",
            capabilities=["code.graph.codegraph.v1"],
            producer_plugin_id=graph_task.plugin_id,
            producer_plugin_version=graph_task.plugin_version,
            media_type="application/vnd.sqlite3",
            content_hash=codegraph_blob.content_hash,
            size_bytes=codegraph_blob.size_bytes,
            storage_uri=codegraph_blob.storage_uri,
        )
    )
    graph_artifact = repositories.artifacts.create(
        Artifact(
            scan_id=scan.id,
            snapshot_id=snapshot.id,
            task_id=task.id,
            artifact_type="security.graph",
            schema_version="1.0",
            capabilities=[SECURITY_GRAPH_CAPABILITY],
            producer_plugin_id=task.plugin_id,
            producer_plugin_version=task.plugin_version,
            media_type="application/vnd.sqlite3",
            content_hash=blob.content_hash,
            size_bytes=blob.size_bytes,
            storage_uri=blob.storage_uri,
        )
    )

    service = SecurityGraphService(repositories, artifact_store)
    result = service.find_nodes(scan.id, kind="code.function", max_nodes=10)

    assert {node.id for node in result.nodes} == {"node-0", "node-2", "node-4"}
    assert (
        repositories.artifacts.find_latest_by_capability(
            scan_id=scan.id,
            capability=SECURITY_GRAPH_CAPABILITY,
        )
        == graph_artifact
    )
    assert codegraph_artifact.id != graph_artifact.id
    assert codegraph_artifact.content_hash != graph_artifact.content_hash
    assert (
        repositories.artifacts.find_latest_by_capability(
            scan_id=scan.id,
            capability="code.graph.codegraph.v1",
        )
        == codegraph_artifact
    )

    finding = repositories.findings.upsert(
        StaticFindingV2(
            fingerprint="c" * 64,
            scan_id=scan.id,
            snapshot_id=snapshot.id,
            rule_id="fixture.path",
            rule_version="1.0.0",
            title="Fixture path",
            weakness_id="CWE-000",
            vuln_class="fixture",
            severity=Severity.INFO,
            static_confidence=StaticConfidence.LOW,
            status=FindingStatus.CANDIDATE,
            locations=[
                CodeLocation(
                    file="src/app.py",
                    line=1,
                    node_id="cg-0",
                )
            ],
            source_node_ids=["node-0"],
            sink_node_ids=["node-3"],
            rationale="fixture",
            remediation="fixture",
        )
    )
    graph_slice = FindingSliceService(
        service.query_for_scan(scan.id),
        repositories.findings,
    ).slice_for_finding(finding.id, radius=2, max_nodes=10)

    assert {"node-0", "node-3"} <= set(graph_slice.seed_ids)
    assert {"node-0", "node-1", "node-2", "node-3"} <= {node.id for node in graph_slice.nodes}
    database.close()
