from __future__ import annotations

from uuid import uuid4

from argus.detection.builtin.authorization.provider import AuthorizationCandidateProvider
from argus.security_ir.models import (
    ExtractionMethod,
    SecurityCodeLocation,
    SecurityConfidence,
    SecurityEdge,
    SecurityNode,
)
from argus.security_ir.provenance import security_provenance
from argus.security_ir.query import SecurityGraphQuery
from argus.security_ir.store import SecurityGraphStore

from .helpers import FakeGraph, make_context


def _authorization_query(tmp_path, *, guarded: bool) -> SecurityGraphQuery:
    snapshot_id = uuid4()
    artifact_id = uuid4()

    def provenance(original_id: str):
        return security_provenance(
            snapshot_id=snapshot_id,
            producer_plugin_id="semantic.business-flow-to-security-ir",
            producer_plugin_version="1.0.0",
            source_artifact_ids=[artifact_id],
            original_codegraph_node_ids=[original_id],
            extraction_method=ExtractionMethod.DETERMINISTIC,
            evidence_refs=[f"fixture:{original_id}"],
        )

    nodes = [
        SecurityNode(
            id="sir:flow:get-order",
            kind="business.flow",
            name="Get order",
            code_locations=[
                SecurityCodeLocation(
                    file="api/orders.py",
                    start_line=10,
                    codegraph_node_id="cg-get-order",
                )
            ],
            provenance=provenance("cg-get-order"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
        SecurityNode(
            id="sir:resource:order",
            kind="resource.entity",
            name="Order",
            provenance=provenance("cg-order"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
        SecurityNode(
            id="sir:route:get-order",
            kind="http.route",
            name="GET /orders/{order_id}",
            attributes={"path": "/orders/{order_id}"},
            provenance=provenance("cg-route"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
        SecurityNode(
            id="sir:source:order-id",
            kind="data.source",
            name="order_id",
            attributes={"origin": "path"},
            provenance=provenance("cg-route"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
    ]
    edges = [
        SecurityEdge(
            id="sir:edge:reads",
            kind="reads",
            source_id="sir:flow:get-order",
            target_id="sir:resource:order",
            provenance=provenance("cg-get-order"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
        SecurityEdge(
            id="sir:edge:route",
            kind="triggers",
            source_id="sir:route:get-order",
            target_id="sir:flow:get-order",
            provenance=provenance("cg-route"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
        SecurityEdge(
            id="sir:edge:source",
            kind="flows_to",
            source_id="sir:source:order-id",
            target_id="sir:flow:get-order",
            provenance=provenance("cg-route"),
            confidence=SecurityConfidence.CONFIRMED,
        ),
    ]
    if guarded:
        nodes.append(
            SecurityNode(
                id="sir:guard:owner",
                kind="auth.guard",
                name="Order ownership guard",
                attributes={"expression": "order.owner_id == current_user.id"},
                provenance=provenance("cg-owner-check"),
                confidence=SecurityConfidence.CONFIRMED,
            )
        )
        edges.append(
            SecurityEdge(
                id="sir:edge:guard",
                kind="guarded_by",
                source_id="sir:flow:get-order",
                target_id="sir:guard:owner",
                provenance=provenance("cg-owner-check"),
                confidence=SecurityConfidence.CONFIRMED,
            )
        )
    store = SecurityGraphStore.create(
        tmp_path / ("guarded.db" if guarded else "unguarded.db"),
        nodes=nodes,
        edges=edges,
    )
    return SecurityGraphQuery(store)


def test_authorization_candidate_requires_external_id_and_missing_matching_guard(tmp_path) -> None:
    query = _authorization_query(tmp_path, guarded=False)
    context = make_context(
        graph=FakeGraph([]),
        security_graph=query,
        snapshot_id=query.get_node("sir:flow:get-order").provenance.snapshot_id,  # type: ignore[union-attr]
    )

    first = AuthorizationCandidateProvider().generate(context)
    second = AuthorizationCandidateProvider().generate(context)

    assert first == second
    assert len(first) == 1
    assert first[0].candidate_type == "authorization.idor"
    assert first[0].sink_node_ids == ["sir:resource:order"]
    assert first[0].route_ids == ["sir:route:get-order"]
    assert "MISSING_OWNERSHIP_OR_TENANT_GUARD" in first[0].reason_codes


def test_authorization_candidate_is_suppressed_by_matching_owner_guard(tmp_path) -> None:
    query = _authorization_query(tmp_path, guarded=True)
    flow = query.get_node("sir:flow:get-order")
    assert flow is not None
    context = make_context(
        graph=FakeGraph([]),
        security_graph=query,
        snapshot_id=flow.provenance.snapshot_id,
    )

    assert AuthorizationCandidateProvider().generate(context) == []
