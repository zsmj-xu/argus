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
        files, anchors = self._validate_isolation(ctx)
        settings = ctx["config"].get(self.name, {})
        max_tokens = settings.get("max_tokens", 8192) if isinstance(settings, dict) else 8192
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            max_tokens = 8192
        batch_size = settings.get("batch_size", len(files)) if isinstance(settings, dict) else len(files)
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            batch_size = len(files) or 1

        findings: list[Finding] = []
        seen_ids: set[str] = set()
        for offset in range(0, len(files), batch_size):
            batch_files = files[offset : offset + batch_size]
            sources: list[dict[str, str]] = []
            line_counts: dict[str, int] = {}
            for path in batch_files:
                stripped = strip_source(path, ctx["source"].read(path))
                sources.append({"path": path, "source": stripped})
                line_counts[path] = len(stripped.splitlines())

            prompt = json.dumps({"files": sources}, ensure_ascii=False, indent=2)
            response = ctx["llm"].complete(system=self._load_prompt(), prompt=prompt, max_tokens=max_tokens)
            batch_findings = self._parse_findings(response, batch_files, anchors, line_counts)
            for finding in batch_findings:
                if finding["id"] not in seen_ids:
                    seen_ids.add(finding["id"])
                    findings.append(finding)
        return {"analyzer": self.name, "findings": findings, "enrichment": {}}

    @staticmethod
    def _validate_isolation(ctx: AnalysisContext) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
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
        raw_anchors = baseline.get("anchors")
        if not isinstance(raw_files, list) or not raw_files:
            raise BaselineIsolationError("baseline.files must be a non-empty list")
        if not isinstance(raw_anchors, dict):
            raise BaselineIsolationError("baseline.anchors must be a mapping")

        files: list[str] = []
        anchors: dict[str, list[dict[str, Any]]] = {}
        for raw_path in raw_files:
            path = _safe_relative_path(raw_path)
            if path in files:
                continue
            raw_file_anchors = raw_anchors.get(path)
            if not isinstance(raw_file_anchors, list):
                raise BaselineIsolationError(f"baseline anchors missing for {path!r}")
            file_anchors = [anchor for item in raw_file_anchors if (anchor := _valid_anchor(item)) is not None]
            if not file_anchors:
                raise BaselineIsolationError(f"baseline has no valid anchors for {path!r}")
            files.append(path)
            anchors[path] = file_anchors
        return files, anchors

    def _parse_findings(
        self,
        response: str,
        files: list[str],
        anchors: dict[str, list[dict[str, Any]]],
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
            if not isinstance(raw_line, int):
                continue
            node_id = _anchor_for_line(anchors[file], raw_line)
            if node_id is None:
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
                    locations=[{"file": file, "line": raw_line, "node_id": node_id}],
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


def _valid_anchor(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    node_id = value.get("node_id")
    start = value.get("start_line")
    end = value.get("end_line")
    kind = value.get("kind")
    if (
        not isinstance(node_id, str)
        or not node_id
        or not isinstance(start, int)
        or isinstance(start, bool)
        or start <= 0
        or not isinstance(end, int)
        or isinstance(end, bool)
        or end < start
        or not isinstance(kind, str)
    ):
        return None
    return {"node_id": node_id, "start_line": start, "end_line": end, "kind": kind.lower()}


def _anchor_for_line(anchors: list[dict[str, Any]], line: int) -> str | None:
    containing = [anchor for anchor in anchors if anchor["start_line"] <= line <= anchor["end_line"]]
    if not containing:
        return None
    containing.sort(
        key=lambda anchor: (
            0 if anchor["kind"] in {"function", "method"} else 1,
            anchor["end_line"] - anchor["start_line"],
            anchor["node_id"],
        )
    )
    return str(containing[0]["node_id"])


ANALYZER = BaselineAnalyzer()

assert isinstance(ANALYZER, BaselineAnalyzer)
assert isinstance(NoGraphHandle(), GraphHandle)
