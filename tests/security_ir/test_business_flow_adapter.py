from __future__ import annotations

import json
from pathlib import Path
from typing import cast
from uuid import uuid4

from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories
from argus.domain.enums import ScanEngine, VcsType
from argus.domain.models import Artifact, Scan, SourceSnapshot, Task
from argus.execution.contracts import RuntimeContext, RuntimeInput
from argus.security_ir.business_flow_adapter import (
    CODEGRAPH_CAPABILITY,
    LEGACY_BUSINESS_FLOW_CAPABILITY,
    SECURITY_GRAPH_CAPABILITY,
    business_flow_to_security_ir_runtime,
)
from argus.security_ir.models import (
    ExtractionMethod,
    SecurityConfidence,
)
from argus.security_ir.store import SecurityGraphStore

from .helpers import write_codegraph

SHA_A = "a" * 64
SHA_B = "b" * 64


def _business_flow() -> dict[str, object]:
    return {
        "endpoints": [
            {
                "id": "ep-checkout",
                "method": "POST",
                "path": "/checkout",
                "auth_required": True,
                "source_ref": "api/orders.py:40",
                "node_id": "cg-checkout",
            }
        ],
        "handlers": [
            {
                "id": "h-checkout",
                "name": "checkout",
                "source_ref": "api/orders.py:40",
                "node_id": "cg-checkout",
            },
            {
                "id": "h-save",
                "name": "save_order",
                "source_ref": "db/orders.py:10",
                "node_id": "cg-save",
            },
        ],
        "resources": [
            {
                "id": "r-order",
                "name": "Order",
                "owner_field": "user_id",
                "source_ref": "models/order.py:5",
            }
        ],
        "operations": [
            {
                "id": "op-create",
                "verb": "create",
                "target_resource": "Order",
                "source_ref": "api/orders.py:52",
            }
        ],
        "edges": [
            {
                "from": "ep-checkout",
                "rel": "handled_by",
                "to": "h-checkout",
            },
            {
                "from": "h-checkout",
                "rel": "performs",
                "to": "op-create",
            },
            {
                "from": "op-create",
                "rel": "targets",
                "to": "r-order",
            },
        ],
        "business_flows": [
            {
                "endpoint_id": "ep-checkout",
                "intent": "create an order",
                "related_endpoint_ids": [],
                "authorization_requirements": ["order belongs to current user"],
                "authorization_checks": [
                    {
                        "requirement": "order belongs to current user",
                        "enforced": False,
                        "enforced_by": None,
                        "note": "missing ownership check",
                    }
                ],
                "trust_boundaries": [
                    {
                        "field": "amount",
                        "source": "request_body",
                        "validated": False,
                        "note": "not recalculated",
                    }
                ],
                "state_reads": ["cart.items"],
                "state_writes": ["order.status"],
                "state_transitions": [
                    {
                        "from": "cart",
                        "to": "created",
                        "note": "single transition",
                    }
                ],
            }
        ],
    }


def _runtime(
    tmp_path: Path,
) -> tuple[RuntimeContext, dict[str, RuntimeInput], Path]:
    snapshot_id = uuid4()
    repository = tmp_path / "snapshot" / "source"
    repository.mkdir(parents=True)
    raw_graph = tmp_path / "raw-codegraph.db"
    write_codegraph(raw_graph)
    artifact_store = ArtifactStore(tmp_path / "runs")
    graph_blob = artifact_store.put_file(raw_graph)
    business_payload = json.dumps(
        _business_flow(),
        ensure_ascii=False,
        sort_keys=True,
    ).encode()
    business_blob = artifact_store.put_bytes(business_payload)
    scan = Scan(
        snapshot_id=snapshot_id,
        project_id=uuid4(),
        config={},
        config_hash=SHA_A,
        engine=ScanEngine.V2,
    )
    snapshot = SourceSnapshot(
        id=snapshot_id,
        project_id=scan.project_id,
        repository_path=str(tmp_path / "repo"),
        vcs_type=VcsType.DIRECTORY,
        tree_hash=SHA_B,
        dirty=False,
        materialized_path=str(repository),
        manifest_artifact_id=uuid4(),
    )
    task = Task(
        scan_id=scan.id,
        plugin_id="semantic.business-flow-to-security-ir",
        plugin_version="1.0.0",
        kind="semantic_adapter",
        required_capabilities=[
            LEGACY_BUSINESS_FLOW_CAPABILITY,
            CODEGRAPH_CAPABILITY,
        ],
        expected_capabilities=[
            "security.routes.v1",
            "security.business-flow.v1",
            "security.authorization.v1",
            "security.resources.v1",
            SECURITY_GRAPH_CAPABILITY,
        ],
        config_hash=SHA_A,
        cache_key=SHA_B,
    )
    graph_artifact = Artifact(
        scan_id=scan.id,
        snapshot_id=snapshot.id,
        task_id=uuid4(),
        artifact_type="code.graph.codegraph",
        schema_version="1.0",
        capabilities=[CODEGRAPH_CAPABILITY],
        producer_plugin_id="graph.codegraph",
        producer_plugin_version="1.0.0",
        media_type="application/vnd.sqlite3",
        content_hash=graph_blob.content_hash,
        size_bytes=graph_blob.size_bytes,
        storage_uri=graph_blob.storage_uri,
    )
    business_artifact = Artifact(
        scan_id=scan.id,
        snapshot_id=snapshot.id,
        task_id=uuid4(),
        artifact_type="legacy.enrichment.business-flow",
        schema_version="1.0",
        capabilities=[LEGACY_BUSINESS_FLOW_CAPABILITY],
        producer_plugin_id="legacy.analyzer.business-flow",
        producer_plugin_version="1.0.0",
        media_type="application/json",
        content_hash=business_blob.content_hash,
        size_bytes=business_blob.size_bytes,
        storage_uri=business_blob.storage_uri,
    )
    context = RuntimeContext(
        scan=scan,
        snapshot=snapshot,
        task=task,
        repositories=cast(Repositories, object()),
        artifact_store=artifact_store,
        runs_root=tmp_path / "runs",
        workspace="fixture",
        attempt_id=uuid4(),
        input_hashes={
            CODEGRAPH_CAPABILITY: graph_blob.content_hash,
            LEGACY_BUSINESS_FLOW_CAPABILITY: business_blob.content_hash,
        },
        temp_dir=tmp_path / "runtime-tmp",
    )
    return (
        context,
        {
            CODEGRAPH_CAPABILITY: RuntimeInput(
                capability=CODEGRAPH_CAPABILITY,
                artifact=graph_artifact,
                payload=raw_graph.read_bytes(),
            ),
            LEGACY_BUSINESS_FLOW_CAPABILITY: RuntimeInput(
                capability=LEGACY_BUSINESS_FLOW_CAPABILITY,
                artifact=business_artifact,
                payload=business_payload,
            ),
        },
        raw_graph,
    )


def test_business_flow_conversion_is_stable_traceable_and_layered(
    tmp_path: Path,
) -> None:
    context, inputs, raw_graph = _runtime(tmp_path)

    first = business_flow_to_security_ir_runtime(context, inputs)
    second = business_flow_to_security_ir_runtime(context, inputs)
    first_graph = next(output for output in first if output.capability == SECURITY_GRAPH_CAPABILITY)
    second_graph = next(output for output in second if output.capability == SECURITY_GRAPH_CAPABILITY)
    assert first_graph.source_path is not None
    assert second_graph.source_path is not None
    first_store = SecurityGraphStore(first_graph.source_path)
    second_store = SecurityGraphStore(second_graph.source_path)
    first_nodes, _ = first_store.find_nodes(limit=500)
    second_nodes, _ = second_store.find_nodes(limit=500)
    first_edges, _ = first_store.edges_for_nodes(
        {node.id for node in first_nodes},
        limit=2_000,
    )
    second_edges, _ = second_store.edges_for_nodes(
        {node.id for node in second_nodes},
        limit=2_000,
    )

    assert first_graph.source_path != raw_graph
    assert [node.model_dump(mode="json") for node in first_nodes] == [
        node.model_dump(mode="json") for node in second_nodes
    ]
    assert [edge.model_dump(mode="json") for edge in first_edges] == [
        edge.model_dump(mode="json") for edge in second_edges
    ]
    assert {node.kind for node in first_nodes} >= {
        "http.route",
        "code.function",
        "auth.policy",
        "resource.entity",
        "data.source",
        "business.flow",
        "state.transition",
    }
    code_nodes = [node for node in first_nodes if node.kind == "code.function"]
    assert {node.confidence for node in code_nodes} == {SecurityConfidence.CONFIRMED}
    calls = [edge for edge in first_edges if edge.kind == "calls"]
    assert len(calls) == 1
    assert calls[0].confidence is SecurityConfidence.CONFIRMED
    assert calls[0].provenance.extraction_method is ExtractionMethod.DETERMINISTIC
    handled_by = [edge for edge in first_edges if edge.kind == "handled_by"]
    assert handled_by[0].confidence is SecurityConfidence.INFERRED
    assert handled_by[0].provenance.extraction_method is ExtractionMethod.LLM_INFERRED
    expected_sources = {
        inputs[CODEGRAPH_CAPABILITY].artifact.id,
        inputs[LEGACY_BUSINESS_FLOW_CAPABILITY].artifact.id,
    }
    for item in [*first_nodes, *first_edges]:
        assert item.provenance.snapshot_id == context.snapshot.id
        assert item.provenance.producer_plugin_id == context.task.plugin_id
        assert set(item.provenance.source_artifact_ids) == expected_sources

    assert len(first) == 5
    assert all(output.json_value is not None for output in first if output.capability != SECURITY_GRAPH_CAPABILITY)
    first_graph.source_path.unlink()
    second_graph.source_path.unlink()
