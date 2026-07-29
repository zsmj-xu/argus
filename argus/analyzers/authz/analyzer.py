"""Static authorization vulnerability analyzer.

The analyzer adapts Shannon's authorization review intent to Argus's white-box inputs: it reads
codegraph nodes and edges, graph-anchored source excerpts, and optional enriched-graph semantics.
LLM output is treated as untrusted data and converted into the frozen Finding contract only after
all locations have been validated against real codegraph node ids.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

from argus.analyzers.base import AnalyzerBase
from argus.contracts import (
    AnalysisContext,
    AnalyzerResult,
    CodeLocation,
    Confidence,
    Finding,
    GraphHandle,
    Phase,
    Severity,
)
from argus.llm.client import DEFAULT_MAX_TOKENS

logger = logging.getLogger(__name__)

_CALLABLE_KINDS = frozenset({"function", "method"})
_DEFAULT_BATCH_SIZE = 40
_DEFAULT_SOURCE_CHARS = 3000

_SEVERITIES: dict[str, Severity] = {member.value: member for member in Severity}
_CONFIDENCES: dict[str, Confidence] = {member.value: member for member in Confidence}
_CONFIDENCES["med"] = Confidence.MEDIUM


class AuthzAnalyzer(AnalyzerBase):
    """Find horizontal, vertical, tenant, and workflow authorization failures."""

    name = "authz"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        candidates = self._collect_candidates(ctx)
        if not candidates:
            logger.info("Authorization analysis skipped: codegraph has no callable nodes in scope")
            return self._empty_result()

        system = self._load_prompt()
        findings: list[Finding] = []
        seen_ids: set[str] = set()
        batch_size = self._positive_int(
            self._authz_config(ctx["config"]).get("batch_size"),
            _DEFAULT_BATCH_SIZE,
        )
        batches = [candidates[offset : offset + batch_size] for offset in range(0, len(candidates), batch_size)]
        for batch_index, batch in enumerate(batches, start=1):
            response = ctx["llm"].complete(
                system=system,
                prompt=self._build_user_prompt(ctx, batch, batch_index=batch_index, batch_count=len(batches)),
                max_tokens=self._max_tokens(ctx["config"]),
            )
            payload = self._parse_response(response)
            if payload is None:
                continue

            raw_findings = payload.get("findings")
            if not isinstance(raw_findings, list):
                logger.warning("Authorization analyzer response JSON must contain a findings list")
                continue

            for finding_index, raw_finding in enumerate(raw_findings):
                if not isinstance(raw_finding, dict):
                    logger.warning(
                        "Discarding authz finding batch %d item %d: finding must be a JSON object",
                        batch_index,
                        finding_index,
                    )
                    continue
                finding = self._convert_finding(
                    cast(dict[str, Any], raw_finding),
                    ctx["graph"],
                    finding_index,
                )
                if finding is not None and finding["id"] not in seen_ids:
                    seen_ids.add(finding["id"])
                    findings.append(finding)

        return {"analyzer": self.name, "findings": findings, "enrichment": {}}

    def _empty_result(self) -> AnalyzerResult:
        return {"analyzer": self.name, "findings": [], "enrichment": {}}

    def _collect_candidates(self, ctx: AnalysisContext) -> list[dict[str, Any]]:
        """Collect graph callable nodes, their call context, and bounded source excerpts."""
        config = ctx["config"]
        focus = config.get("focus")
        avoid = config.get("avoid")
        source_chars = self._positive_int(
            self._authz_config(config).get("source_chars"),
            _DEFAULT_SOURCE_CHARS,
        )

        candidates: list[dict[str, Any]] = []
        for node in ctx["graph"].query(""):
            if str(node.get("kind", "")).lower() not in _CALLABLE_KINDS:
                continue

            file_path = str(node.get("file_path", ""))
            if not self._in_scope(file_path, focus=focus, avoid=avoid):
                continue

            node_id = node.get("id")
            if not isinstance(node_id, str) or not node_id:
                continue

            details = ctx["graph"].node(node_id) or node
            candidate = self._graph_summary(details)
            candidate["callers"] = [self._neighbor_summary(item) for item in ctx["graph"].callers(node_id)]
            candidate["callees"] = [self._neighbor_summary(item) for item in ctx["graph"].callees(node_id)]
            candidate["source_excerpt"] = self._source_excerpt(ctx, details, source_chars)
            candidates.append(candidate)

        return candidates

    def _build_user_prompt(
        self,
        ctx: AnalysisContext,
        candidates: list[dict[str, Any]],
        *,
        batch_index: int,
        batch_count: int,
    ) -> str:
        input_payload = {
            "workspace": ctx["workspace"],
            "config": ctx["config"],
            "enriched_graph": ctx["enriched"],
            "scan_batch": {"index": batch_index, "count": batch_count},
            "codegraph_candidates": candidates,
        }
        return (
            "Analyze the following static Argus facts for authorization vulnerabilities. "
            "Treat codegraph node ids as the only valid location anchors.\n\n"
            + json.dumps(input_payload, ensure_ascii=False, indent=2, default=str)
        )

    def _parse_response(self, response: str) -> dict[str, Any] | None:
        text = response.strip()
        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1 :]
            if text.endswith("```"):
                text = text[:-3].rstrip()

        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end <= start:
                logger.warning("Authorization analyzer returned invalid JSON")
                return None
            try:
                decoded = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                logger.warning("Authorization analyzer returned invalid JSON")
                return None

        if not isinstance(decoded, dict):
            logger.warning("Authorization analyzer JSON response must be an object")
            return None
        return cast(dict[str, Any], decoded)

    def _convert_finding(
        self,
        raw: dict[str, Any],
        graph: GraphHandle,
        index: int,
    ) -> Finding | None:
        title = self._required_string(raw.get("title"))
        rationale = self._required_string(raw.get("rationale"))
        evidence = self._required_string(raw.get("evidence"))
        remediation = self._required_string(raw.get("remediation"))
        severity = self._severity(raw.get("severity"))
        confidence = self._confidence(raw.get("confidence"))
        if (
            title is None
            or rationale is None
            or evidence is None
            or remediation is None
            or severity is None
            or confidence is None
        ):
            logger.warning("Discarding authz finding %d: missing or invalid required fields", index)
            return None

        raw_locations = raw.get("locations")
        if not isinstance(raw_locations, list) or not raw_locations:
            logger.warning("Discarding authz finding %d: locations must be a non-empty list", index)
            return None

        locations: list[CodeLocation] = []
        for raw_location in raw_locations:
            if not isinstance(raw_location, dict):
                logger.warning("Discarding authz finding %d: location must be a JSON object", index)
                return None
            location = self._validated_location(cast(dict[str, Any], raw_location), graph, index)
            if location is None:
                return None
            locations.append(location)

        data_flow_value = raw.get("data_flow", "")
        data_flow = data_flow_value if isinstance(data_flow_value, str) else str(data_flow_value)
        return self._make_finding(
            vuln_class="authz",
            title=title,
            severity=severity,
            confidence=confidence,
            locations=locations,
            data_flow=data_flow,
            rationale=rationale,
            evidence=evidence,
            remediation=remediation,
        )

    def _validated_location(
        self,
        raw: dict[str, Any],
        graph: GraphHandle,
        finding_index: int,
    ) -> CodeLocation | None:
        node_id = raw.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            logger.warning("Discarding authz finding %d: location has no node_id", finding_index)
            return None

        node = graph.node(node_id)
        if node is None:
            logger.warning(
                "Discarding authz finding %d: unknown codegraph node_id %r",
                finding_index,
                node_id,
            )
            return None

        graph_file = node.get("file_path")
        raw_file = raw.get("file")
        file_path = graph_file if isinstance(graph_file, str) and graph_file else raw_file
        if not isinstance(file_path, str) or not file_path:
            logger.warning("Discarding authz finding %d: node %r has no file path", finding_index, node_id)
            return None

        raw_line = raw.get("line")
        start_line = node.get("start_line")
        end_line = node.get("end_line")
        line = raw_line if isinstance(raw_line, int) and raw_line > 0 else start_line
        if not isinstance(line, int) or line <= 0:
            logger.warning("Discarding authz finding %d: node %r has no valid line", finding_index, node_id)
            return None
        if isinstance(start_line, int) and isinstance(end_line, int) and not start_line <= line <= end_line:
            logger.warning(
                "Authz finding %d line %d is outside node %r range; anchoring to line %d",
                finding_index,
                line,
                node_id,
                start_line,
            )
            line = start_line
        elif isinstance(start_line, int) and not isinstance(end_line, int) and line != start_line:
            logger.warning(
                "Authz finding %d line %d has no bounded node range for %r; anchoring to line %d",
                finding_index,
                line,
                node_id,
                start_line,
            )
            line = start_line

        return {"file": file_path, "line": line, "node_id": node_id}

    def _source_excerpt(self, ctx: AnalysisContext, node: dict[str, Any], limit: int) -> str:
        file_path = node.get("file_path")
        if not isinstance(file_path, str) or not file_path:
            return ""
        start_line = node.get("start_line")
        end_line = node.get("end_line")
        start = start_line if isinstance(start_line, int) else None
        end = end_line if isinstance(end_line, int) else None
        try:
            return ctx["source"].read(file_path, start, end)[:limit]
        except (OSError, UnicodeError):
            logger.debug("Unable to read source excerpt for %s", file_path, exc_info=True)
            return ""

    @staticmethod
    def _graph_summary(node: dict[str, Any]) -> dict[str, Any]:
        keys = (
            "id",
            "kind",
            "name",
            "qualified_name",
            "file_path",
            "start_line",
            "end_line",
            "signature",
            "decorators",
            "edges",
        )
        return {key: node[key] for key in keys if key in node and node[key] is not None}

    @staticmethod
    def _neighbor_summary(node: dict[str, Any]) -> dict[str, Any]:
        return {
            key: node[key]
            for key in ("id", "kind", "name", "qualified_name", "file_path", "start_line")
            if key in node and node[key] is not None
        }

    @staticmethod
    def _required_string(value: Any) -> str | None:
        return value.strip() if isinstance(value, str) and value.strip() else None

    @staticmethod
    def _severity(value: Any) -> Severity | None:
        if isinstance(value, Severity):
            return value
        if not isinstance(value, str):
            return None
        return _SEVERITIES.get(value.strip().lower())

    @staticmethod
    def _confidence(value: Any) -> Confidence | None:
        if isinstance(value, Confidence):
            return value
        if not isinstance(value, str):
            return None
        return _CONFIDENCES.get(value.strip().lower())

    @staticmethod
    def _authz_config(config: dict[str, Any]) -> dict[str, Any]:
        value = config.get("authz", {})
        return cast(dict[str, Any], value) if isinstance(value, dict) else {}

    @staticmethod
    def _positive_int(value: Any, default: int) -> int:
        return value if isinstance(value, int) and value > 0 else default

    @staticmethod
    def _max_tokens(config: dict[str, Any]) -> int:
        return AuthzAnalyzer._positive_int(
            AuthzAnalyzer._authz_config(config).get("max_tokens"),
            DEFAULT_MAX_TOKENS,
        )

    @staticmethod
    def _in_scope(file_path: str, *, focus: Any, avoid: Any) -> bool:
        focus_values = AuthzAnalyzer._scope_values(focus)
        avoid_values = AuthzAnalyzer._scope_values(avoid)
        if focus_values and not any(value in file_path for value in focus_values):
            return False
        return not any(value in file_path for value in avoid_values)

    @staticmethod
    def _scope_values(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, list):
            return [item for item in value if isinstance(item, str) and item]
        return []


ANALYZER = AuthzAnalyzer()
