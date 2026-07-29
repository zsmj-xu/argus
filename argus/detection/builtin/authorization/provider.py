"""Deterministic Authorization/IDOR candidate generation from Security IR."""

from __future__ import annotations

from pydantic import JsonValue

from argus.detection.candidates import (
    candidate_identity,
    candidate_provenance,
)
from argus.detection.contracts import Candidate, DetectionContext
from argus.security_ir.models import SecurityNode

RULE_ID = "authorization.idor"
RULE_VERSION = "1.0.0"


class AuthorizationCandidateProvider:
    def generate(self, context: DetectionContext) -> list[Candidate]:
        if context.security_graph is None:
            return []
        flows = context.security_graph.find_nodes(
            kind="business.flow",
            max_nodes=500,
        )
        candidates: list[Candidate] = []
        for flow in flows.nodes:
            neighborhood = context.security_graph.neighbors(
                flow.id,
                max_nodes=100,
            )
            resources = [
                node
                for node in neighborhood.nodes
                if node.kind == "resource.entity"
                and any(
                    edge.source_id == flow.id and edge.target_id == node.id and edge.kind in {"reads", "writes"}
                    for edge in neighborhood.edges
                )
            ]
            if not resources:
                continue
            routes = [node for node in neighborhood.nodes if node.kind == "http.route"]
            sources = [node for node in neighborhood.nodes if node.kind == "data.source"]
            identities = [
                node for node in neighborhood.nodes if node.kind in {"auth.guard", "auth.policy", "identity.role"}
            ]
            protected_resources = {
                resource.id
                for resource in resources
                if self._has_matching_guard(
                    resource.name,
                    identities,
                )
            }
            if len(protected_resources) == len(resources):
                continue
            external = bool(sources) or any(self._route_has_identifier(route.attributes) for route in routes)
            if not external:
                continue
            for resource in sorted(resources, key=lambda item: item.id):
                if resource.id in protected_resources:
                    continue
                source_ids = sorted(node.id for node in sources)
                route_ids = sorted(node.id for node in routes)
                identity_ids = sorted(node.id for node in identities)
                candidate_id, root_cause_key = candidate_identity(
                    context,
                    rule_id=RULE_ID,
                    rule_version=RULE_VERSION,
                    candidate_type="authorization.idor",
                    primary_node_ids=[flow.id],
                    source_node_ids=source_ids,
                    sink_node_ids=[resource.id],
                )
                reason_codes = [
                    "RESOURCE_ACCESS",
                    "EXTERNAL_RESOURCE_IDENTIFIER",
                    "MISSING_OWNERSHIP_OR_TENANT_GUARD",
                ]
                possible_policies = [
                    node.id
                    for node in identities
                    if node.kind == "auth.policy" and node.attributes.get("enforced") is False
                ]
                if possible_policies:
                    reason_codes.append("DECLARED_BUT_UNENFORCED_POLICY")
                original_ids = sorted(
                    {
                        original_id
                        for node in [
                            flow,
                            resource,
                            *routes,
                            *sources,
                            *identities,
                        ]
                        for original_id in (node.provenance.original_codegraph_node_ids)
                    }
                )
                candidates.append(
                    Candidate(
                        id=candidate_id,
                        rule_id=RULE_ID,
                        rule_version=RULE_VERSION,
                        candidate_type="authorization.idor",
                        primary_node_ids=[flow.id],
                        source_node_ids=source_ids,
                        sink_node_ids=[resource.id],
                        route_ids=route_ids,
                        identity_context_ids=identity_ids,
                        reason_codes=reason_codes,
                        static_score=(0.9 if possible_policies else 0.78),
                        root_cause_key=root_cause_key,
                        attributes={
                            "flow_name": flow.name,
                            "resource_name": resource.name,
                            "access_edges": [
                                edge.id
                                for edge in neighborhood.edges
                                if edge.source_id == flow.id
                                and edge.target_id == resource.id
                                and edge.kind in {"reads", "writes"}
                            ],
                            "enumeration_truncated": (flows.truncated or neighborhood.truncated),
                        },
                        provenance=candidate_provenance(
                            context,
                            original_codegraph_node_ids=original_ids,
                            evidence_refs=[
                                f"security-ir:node:{flow.id}",
                                f"security-ir:node:{resource.id}",
                            ],
                        ),
                    )
                )
        return sorted(candidates, key=lambda item: item.id)

    @staticmethod
    def _has_matching_guard(
        resource_name: str,
        identities: list[SecurityNode],
    ) -> bool:
        keywords = {
            "owner",
            "ownership",
            "belongs",
            "tenant",
            "current user",
            "user_id",
            "所属",
            "归属",
            "租户",
            "当前用户",
            resource_name.lower(),
        }
        for node in identities:
            kind = node.kind
            attributes = node.attributes
            if kind not in {"auth.guard", "auth.policy"} or not isinstance(
                attributes,
                dict,
            ):
                continue
            enforced = kind == "auth.guard" or attributes.get("enforced") is True
            if not enforced:
                continue
            text = " ".join(str(value) for value in attributes.values()).lower()
            if any(keyword and keyword in text for keyword in keywords):
                return True
        return False

    @staticmethod
    def _route_has_identifier(
        attributes: dict[str, JsonValue],
    ) -> bool:
        path = attributes.get("path")
        if not isinstance(path, str):
            legacy = attributes.get("legacy")
            path = legacy.get("path") if isinstance(legacy, dict) else None
        return isinstance(path, str) and ("{" in path or ":" in path or "<" in path)
