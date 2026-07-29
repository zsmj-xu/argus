"""Deterministic, sink-first Injection candidate generation."""

from __future__ import annotations

import re
from typing import Any

from argus.detection.candidates import (
    candidate_identity,
    candidate_provenance,
)
from argus.detection.contracts import Candidate, DetectionContext

RULE_ID = "injection.sink-reachability"
RULE_VERSION = "1.0.0"

_SINK_TERMS: tuple[tuple[str, str, str], ...] = (
    ("execute", "sql", "SINK_SQL"),
    ("executemany", "sql", "SINK_SQL"),
    ("raw_query", "sql", "SINK_SQL"),
    ("nativeQuery", "sql", "SINK_SQL"),
    ("system", "command", "SINK_COMMAND"),
    ("popen", "command", "SINK_COMMAND"),
    ("check_output", "command", "SINK_COMMAND"),
    ("render_template_string", "template", "SINK_TEMPLATE"),
    ("from_string", "template", "SINK_TEMPLATE"),
)
_CONCATENATION = re.compile(
    r"(?:\+|\.format\s*\(|f[\"']|%\s*\(|\$\{)",
    re.IGNORECASE,
)
_SQL_PARAMETER = re.compile(
    r"(?:\?|%s|:[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_CLIENT_INPUT = re.compile(
    r"(?:request\.|params\b|query\b|body\b|form\b|argv\b|input\s*\()",
    re.IGNORECASE,
)


class InjectionCandidateProvider:
    def generate(self, context: DetectionContext) -> list[Candidate]:
        raw_candidates: dict[
            tuple[str, str, str],
            tuple[dict[str, Any], dict[str, Any], str, str],
        ] = {}
        for term, sink_type, reason in _SINK_TERMS:
            for sink in context.codegraph.query(term):
                sink_id = sink.get("id")
                if not isinstance(sink_id, str) or not sink_id:
                    continue
                details = context.codegraph.node(sink_id) or sink
                callers = context.codegraph.callers(sink_id)
                anchors = callers or [details]
                for anchor in anchors:
                    anchor_id = anchor.get("id")
                    if not isinstance(anchor_id, str) or not anchor_id:
                        continue
                    anchor_details = context.codegraph.node(anchor_id) or anchor
                    source = self._source(context, anchor_details)
                    if self._obviously_safe(sink_type, source):
                        continue
                    key = (anchor_id, sink_id, sink_type)
                    raw_candidates[key] = (
                        anchor_details,
                        details,
                        reason,
                        source,
                    )

        candidates: list[Candidate] = []
        for (
            anchor_id,
            sink_id,
            sink_type,
        ), (
            anchor,
            sink,
            reason,
            source,
        ) in sorted(raw_candidates.items()):
            semantic = self._semantic_context(context, anchor_id)
            reason_codes = [reason]
            score = 0.55
            if _CONCATENATION.search(source):
                reason_codes.append("DYNAMIC_STRING_CONSTRUCTION")
                score += 0.2
            if _CLIENT_INPUT.search(source) or semantic["source_ids"]:
                reason_codes.append("EXTERNAL_INPUT_REACHABLE")
                score += 0.15
            if semantic["route_ids"]:
                reason_codes.append("ROUTE_REACHABLE")
                score += 0.05
            candidate_id, root_cause_key = candidate_identity(
                context,
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                candidate_type=f"injection.{sink_type}",
                primary_node_ids=[anchor_id],
                source_node_ids=semantic["source_ids"],
                sink_node_ids=[sink_id],
            )
            original_ids = sorted(
                {
                    anchor_id,
                    sink_id,
                    *semantic["original_codegraph_ids"],
                }
            )
            candidates.append(
                Candidate(
                    id=candidate_id,
                    rule_id=RULE_ID,
                    rule_version=RULE_VERSION,
                    candidate_type=f"injection.{sink_type}",
                    primary_node_ids=[anchor_id],
                    source_node_ids=semantic["source_ids"],
                    sink_node_ids=[sink_id],
                    route_ids=semantic["route_ids"],
                    identity_context_ids=semantic["identity_ids"],
                    reason_codes=reason_codes,
                    static_score=min(score, 0.99),
                    root_cause_key=root_cause_key,
                    attributes={
                        "anchor_name": str(anchor.get("qualified_name") or anchor.get("name") or anchor_id),
                        "sink_name": str(sink.get("qualified_name") or sink.get("name") or sink_id),
                        "sink_type": sink_type,
                    },
                    provenance=candidate_provenance(
                        context,
                        original_codegraph_node_ids=original_ids,
                        evidence_refs=[
                            f"codegraph:node:{anchor_id}",
                            f"codegraph:node:{sink_id}",
                        ],
                    ),
                )
            )
        return candidates

    @staticmethod
    def _source(
        context: DetectionContext,
        node: dict[str, Any],
    ) -> str:
        file = node.get("file_path")
        if not isinstance(file, str) or not file:
            return ""
        start = node.get("start_line")
        end = node.get("end_line")
        try:
            return context.source.read(
                file,
                start if isinstance(start, int) else None,
                end if isinstance(end, int) else None,
            )[:8_000]
        except (OSError, UnicodeError):
            return ""

    @staticmethod
    def _obviously_safe(sink_type: str, source: str) -> bool:
        compact = " ".join(source.split())
        if sink_type == "sql":
            execute = re.search(
                r"execute(?:many)?\s*\((?P<args>.*?)\)",
                compact,
                re.IGNORECASE,
            )
            if execute is not None:
                args = execute.group("args")
                if "," in args and _SQL_PARAMETER.search(args):
                    return True
        if sink_type == "command":
            command = re.search(
                r"(?:run|Popen|check_output)\s*\((?P<args>.*?)\)",
                compact,
                re.IGNORECASE,
            )
            if (
                command is not None
                and command.group("args").lstrip().startswith(("[", "("))
                and "shell=True" not in compact
            ):
                return True
        return False

    @staticmethod
    def _semantic_context(
        context: DetectionContext,
        codegraph_node_id: str,
    ) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {
            "source_ids": [],
            "route_ids": [],
            "identity_ids": [],
            "original_codegraph_ids": [],
        }
        if context.security_graph is None:
            return result
        mapped = context.security_graph.nodes_for_codegraph_id(
            codegraph_node_id,
            max_nodes=20,
        )
        if not mapped.nodes:
            return result
        graph_slice = context.security_graph.subgraph(
            [node.id for node in mapped.nodes],
            radius=2,
            max_nodes=60,
        )
        for node in graph_slice.nodes:
            if node.kind == "data.source":
                result["source_ids"].append(node.id)
            elif node.kind == "http.route":
                result["route_ids"].append(node.id)
            elif node.kind in {"auth.guard", "auth.policy", "identity.role"}:
                result["identity_ids"].append(node.id)
            result["original_codegraph_ids"].extend(node.provenance.original_codegraph_node_ids)
        return {key: sorted(set(values)) for key, values in result.items()}
