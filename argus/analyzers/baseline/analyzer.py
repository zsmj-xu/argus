"""Fail-closed source-only analyzer for the no-graph evaluation arm."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from argus.analyzers.base import AnalyzerBase
from argus.contracts import Confidence, GraphHandle, Phase, Severity, SourceMode
from argus.source import strip_source

if TYPE_CHECKING:
    from argus.contracts import AnalysisContext, AnalyzerResult, Finding


class BaselineIsolationError(RuntimeError):
    """Raised before analysis when the no-graph isolation contract is violated."""


class NoGraphHandle:
    """GraphHandle that makes every accidental graph access observable and fatal."""

    def query(self, search: str) -> list[dict[str, Any]]:
        del search
        raise BaselineIsolationError("baseline graph access disabled")

    def node(self, node_id: str) -> dict[str, Any] | None:
        del node_id
        raise BaselineIsolationError("baseline graph access disabled")

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        raise BaselineIsolationError("baseline graph access disabled")

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        del symbol
        raise BaselineIsolationError("baseline graph access disabled")

    def explore(self, query: str) -> str:
        del query
        raise BaselineIsolationError("baseline graph access disabled")


class BaselineAnalyzer(AnalyzerBase):
    """Analyze stripped source without exposing graph or enrichment to the model."""

    name = "baseline"
    phase = Phase.VULN_ANALYSIS
    requires: list[str] = []

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        files, node_ids = self._validate_isolation(ctx)

        sources: list[dict[str, str]] = []
        line_counts: dict[str, int] = {}
        for path in files:
            stripped = strip_source(path, ctx["source"].read(path))
            sources.append({"path": path, "source": stripped})
            line_counts[path] = len(stripped.splitlines())

        prompt = json.dumps({"files": sources}, ensure_ascii=False, indent=2)
        response = ctx["llm"].complete(system=self._load_prompt(), prompt=prompt)
        findings = self._parse_findings(response, files, node_ids, line_counts)
        return {"analyzer": self.name, "findings": findings, "enrichment": {}}

    @staticmethod
    def _validate_isolation(ctx: AnalysisContext) -> tuple[list[str], dict[str, str]]:
        if type(ctx["graph"]) is not NoGraphHandle:
            raise BaselineIsolationError("baseline requires NoGraphHandle")
        if ctx["enriched"] != {}:
            raise BaselineIsolationError("baseline enrichment must be empty")
        if ctx["source"].mode is not SourceMode.STRIPPED:
            raise BaselineIsolationError("baseline requires source_mode=stripped")

        baseline = ctx["config"].get("baseline")
        if not isinstance(baseline, dict):
            raise BaselineIsolationError("baseline config is required")
        raw_files = baseline.get("files")
        raw_node_ids = baseline.get("node_ids")
        if not isinstance(raw_files, list) or not raw_files:
            raise BaselineIsolationError("baseline.files must be a non-empty list")
        if not isinstance(raw_node_ids, dict):
            raise BaselineIsolationError("baseline.node_ids must be a mapping")

        files: list[str] = []
        node_ids: dict[str, str] = {}
        for raw_path in raw_files:
            path = _safe_relative_path(raw_path)
            if path in files:
                continue
            node_id = raw_node_ids.get(path)
            if not isinstance(node_id, str) or not node_id.strip():
                raise BaselineIsolationError(f"baseline node id missing for {path!r}")
            files.append(path)
            node_ids[path] = node_id
        return files, node_ids

    def _parse_findings(
        self,
        response: str,
        files: list[str],
        node_ids: dict[str, str],
        line_counts: dict[str, int],
    ) -> list[Finding]:
        payload = _json_payload(response)
        raw_findings = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(raw_findings, list):
            return []

        allowed = set(files)
        findings: list[Finding] = []
        for raw in raw_findings:
            if not isinstance(raw, dict):
                continue
            locations = raw.get("locations")
            if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
                continue
            raw_location = locations[0]
            raw_file = raw_location.get("file")
            raw_line = raw_location.get("line")
            if not isinstance(raw_file, str):
                continue
            try:
                file = _safe_relative_path(raw_file)
            except BaselineIsolationError:
                continue
            if file not in allowed or not _valid_line(raw_line, line_counts[file]):
                continue

            title = _required_text(raw.get("title"))
            rationale = _required_text(raw.get("rationale"))
            evidence = _required_text(raw.get("evidence"))
            remediation = _required_text(raw.get("remediation"))
            severity = _severity(raw.get("severity"))
            confidence = _confidence(raw.get("confidence"))
            if (
                title is None
                or rationale is None
                or evidence is None
                or remediation is None
                or severity is None
                or confidence is None
                or not isinstance(raw_line, int)
            ):
                continue
            data_flow = raw.get("data_flow")
            if not isinstance(data_flow, str):
                data_flow = ""

            findings.append(
                self._make_finding(
                    vuln_class="business-logic",
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    locations=[{"file": file, "line": raw_line, "node_id": node_ids[file]}],
                    data_flow=data_flow,
                    rationale=rationale,
                    evidence=evidence,
                    remediation=remediation,
                )
            )
        return findings


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BaselineIsolationError("baseline file path must be a non-empty string")
    normalized = value.strip().replace("\\", "/")
    if os.path.isabs(normalized) or any(part == ".." for part in normalized.split("/")):
        raise BaselineIsolationError(f"unsafe baseline file path: {value!r}")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized:
        raise BaselineIsolationError("baseline file path must be relative")
    return normalized


def _json_payload(response: str) -> Any:
    text = response.strip()
    if text.startswith("```"):
        first_newline = text.find("\n")
        last_fence = text.rfind("```")
        if first_newline >= 0 and last_fence > first_newline:
            text = text[first_newline + 1 : last_fence].strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def _required_text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _severity(value: Any) -> Severity | None:
    try:
        return value if isinstance(value, Severity) else Severity(str(value).lower())
    except ValueError:
        return None


def _confidence(value: Any) -> Confidence | None:
    try:
        return value if isinstance(value, Confidence) else Confidence(str(value).lower())
    except ValueError:
        return None


def _valid_line(value: Any, line_count: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= line_count


ANALYZER = BaselineAnalyzer()

assert isinstance(ANALYZER, BaselineAnalyzer)
assert isinstance(NoGraphHandle(), GraphHandle)
