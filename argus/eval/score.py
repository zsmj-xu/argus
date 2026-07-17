"""Match Argus findings to ground truth and calculate recall/precision."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, TypedDict

from argus.contracts import CodeLocation, Finding

_LINE_TOLERANCE = 10
_INVARIANT_KINDS = {"ownership", "authentication", "role", "replay", "trust_boundary"}
_INVARIANT_ALIASES: dict[str, tuple[tuple[str, ...], ...]] = {
    "ownership": (
        ("ownership",),
        ("owner",),
        ("bola",),
        ("idor",),
        ("cross", "user"),
        ("cross", "tenant"),
    ),
    "authentication": (
        ("authentication",),
        ("unauthenticated",),
        ("missing", "auth"),
        ("no", "auth"),
    ),
    "role": (("role",), ("admin",), ("privilege",), ("bfla",)),
    "replay": (("replay",), ("replayed",), ("idempotency",), ("duplicate",), ("repeated",)),
    "trust_boundary": (
        ("trust", "boundary"),
        ("client", "controlled"),
        ("user", "supplied"),
        ("mass", "assignment"),
        ("tamper",),
    ),
}


class MatchedFinding(TypedDict):
    ground_truth_id: str
    finding_index: int
    finding_id: str


class ScoreResult(TypedDict):
    recall: float
    precision: float
    tp: int
    fp: int
    fn: int
    matched: list[MatchedFinding]


@dataclass(frozen=True)
class _GroundTruth:
    id: str
    vuln_class: str
    class_is_invariant: bool
    file: str
    line: int | None
    handler: str | None


@dataclass(frozen=True)
class _Candidate:
    finding_index: int
    ground_truth_index: int
    quality: int


def score(findings: list[Finding], ground_truth: dict[str, Any]) -> ScoreResult:
    """Score findings against in-scope ground truth using one-to-one matching.

    Matches require a compatible vulnerability class plus a source anchor. Source
    anchors use the same file and a line within ten lines, or the ground-truth
    handler name when a numeric ground-truth line is unavailable. Imported T15
    ground truth uses invariant kinds, so the generic ``business-logic`` finding
    class is compatible with those five kinds.
    """
    expected = _ground_truth_entries(ground_truth)
    candidates = _candidates(findings, expected)
    matched_by_gt = _maximum_matching(len(findings), candidates)

    matched: list[MatchedFinding] = []
    for ground_truth_index, item in enumerate(expected):
        finding_index = matched_by_gt.get(ground_truth_index)
        if finding_index is None:
            continue
        matched.append(
            {
                "ground_truth_id": item.id,
                "finding_index": finding_index,
                "finding_id": findings[finding_index]["id"],
            }
        )

    tp = len(matched)
    fp = len(findings) - tp
    fn = len(expected) - tp
    return {
        "recall": tp / len(expected) if expected else 0.0,
        "precision": tp / len(findings) if findings else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "matched": matched,
    }


def _ground_truth_entries(payload: dict[str, Any]) -> list[_GroundTruth]:
    raw_entries = payload.get("vulnerabilities", payload.get("vulns", []))
    if not isinstance(raw_entries, list):
        raise ValueError("ground truth vulnerabilities must be a list")

    entries: list[_GroundTruth] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise ValueError(f"ground truth entry {index} must be an object")
        if raw.get("in_scope", True) is False:
            continue

        ground_truth_id = raw.get("id")
        if not isinstance(ground_truth_id, str) or not ground_truth_id:
            raise ValueError(f"ground truth entry {index} has no id")

        explicit_class = raw.get("vuln_class")
        invariant_kind = raw.get("invariant_kind")
        if isinstance(explicit_class, str) and explicit_class:
            vuln_class = explicit_class
            class_is_invariant = False
        elif isinstance(invariant_kind, str) and invariant_kind:
            vuln_class = invariant_kind
            class_is_invariant = True
        else:
            raise ValueError(f"ground truth entry {ground_truth_id!r} has no vulnerability class")

        file, line = _ground_truth_location(raw)
        if not file:
            raise ValueError(f"ground truth entry {ground_truth_id!r} has no source file")

        handler = raw.get("handler")
        entries.append(
            _GroundTruth(
                id=ground_truth_id,
                vuln_class=vuln_class,
                class_is_invariant=class_is_invariant,
                file=file,
                line=line,
                handler=handler if isinstance(handler, str) and handler else None,
            )
        )
    return entries


def _ground_truth_location(raw: dict[str, Any]) -> tuple[str, int | None]:
    location = raw.get("location")
    file = raw.get("file")
    line = raw.get("line")

    if isinstance(location, dict):
        file = location.get("file", file)
        line = location.get("line", line)
    elif isinstance(location, str):
        file, location_line = _split_file_line(location)
        if line is None:
            line = location_line

    normalized_file = _normalize_path(file) if isinstance(file, str) else ""
    normalized_line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
    if normalized_line is None and normalized_file:
        source = raw.get("source")
        if isinstance(source, str):
            normalized_line = _line_from_source(source, normalized_file)
    return normalized_file, normalized_line


def _split_file_line(value: str) -> tuple[str, int | None]:
    match = re.fullmatch(r"(.+?):(\d+)", value.strip())
    if match is None:
        return value, None
    return match.group(1), int(match.group(2))


def _line_from_source(source: str, file: str) -> int | None:
    candidates = (file, os.path.basename(file))
    for candidate in candidates:
        match = re.search(rf"(?<![\w/]){re.escape(candidate)}:(\d+)", source)
        if match is not None:
            return int(match.group(1))
    return None


def _candidates(findings: list[Finding], expected: list[_GroundTruth]) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for finding_index, finding in enumerate(findings):
        finding_id = finding.get("id")
        finding_class = finding.get("vuln_class")
        if not isinstance(finding_id, str) or not finding_id or not isinstance(finding_class, str):
            continue
        for ground_truth_index, item in enumerate(expected):
            if not _compatible_class(finding_class, item):
                continue
            if not _compatible_invariant_semantics(finding, item):
                continue
            quality = _anchor_quality(finding, item)
            if quality is not None:
                candidates.append(_Candidate(finding_index, ground_truth_index, quality))
    return candidates


def _compatible_class(finding_class: str, ground_truth: _GroundTruth) -> bool:
    actual = _normalize_class(finding_class)
    expected = _normalize_class(ground_truth.vuln_class)
    if actual == expected:
        return True
    if ground_truth.class_is_invariant and expected in _INVARIANT_KINDS:
        if actual == "business_logic":
            return True
        if actual == "authz" and expected in {"ownership", "role"}:
            return True
        if actual == "auth" and expected == "authentication":
            return True
    return False


def _anchor_quality(finding: Finding, ground_truth: _GroundTruth) -> int | None:
    raw_locations = finding.get("locations")
    if not isinstance(raw_locations, list):
        return None
    best: int | None = None
    same_file_locations: list[CodeLocation] = []
    for location in raw_locations:
        if not isinstance(location, dict):
            continue
        file = location.get("file")
        line = location.get("line")
        node_id = location.get("node_id")
        if (
            isinstance(file, str)
            and isinstance(line, int)
            and not isinstance(line, bool)
            and isinstance(node_id, str)
            and _same_file(file, ground_truth.file)
        ):
            same_file_locations.append({"file": file, "line": line, "node_id": node_id})
    if not same_file_locations:
        return None

    if ground_truth.line is None and ground_truth.handler:
        return _handler_match_quality(finding, same_file_locations, ground_truth.handler)

    for location in same_file_locations:
        if ground_truth.line is not None:
            distance = abs(location["line"] - ground_truth.line)
            if distance <= _LINE_TOLERANCE:
                best = max(best or 0, 300 - distance)
            continue
        best = max(best or 0, 100)
    return best


def _compatible_invariant_semantics(finding: Finding, ground_truth: _GroundTruth) -> bool:
    if not ground_truth.class_is_invariant:
        return True
    if _normalize_class(finding["vuln_class"]) != "business_logic":
        return True

    expected = _normalize_class(ground_truth.vuln_class)
    aliases = _INVARIANT_ALIASES.get(expected, ())
    finding_tokens = _tokens(_finding_text(finding))
    return any(_contains_sequence(finding_tokens, alias) for alias in aliases)


def _handler_match_quality(
    finding: Finding,
    same_file_locations: list[CodeLocation],
    handler: str,
) -> int | None:
    expected = _tokens(handler)
    if not expected:
        return None

    structured_symbols = [
        symbol for location in same_file_locations if (symbol := _node_symbol(location["node_id"])) is not None
    ]
    if structured_symbols:
        return 250 if any(_symbol_matches_handler(symbol, handler) for symbol in structured_symbols) else None

    finding_tokens = _tokens(_finding_text(finding))
    return 200 if _contains_sequence(finding_tokens, expected) else None


def _node_symbol(node_id: str) -> str | None:
    symbol: str | None = None
    if "|" in node_id:
        symbol = node_id.rsplit("|", 1)[-1]
    elif "::" in node_id:
        symbol = node_id.rsplit("::", 1)[-1]
    elif node_id.startswith(("function:", "method:")):
        symbol = node_id.rsplit(":", 1)[-1]
    if symbol is None or not re.search(r"[A-Za-z]", symbol):
        return None
    return symbol


def _symbol_matches_handler(symbol: str, handler: str) -> bool:
    symbol_parts = _symbol_parts(symbol)
    handler_parts = _symbol_parts(handler)
    return (
        bool(handler_parts)
        and len(symbol_parts) >= len(handler_parts)
        and symbol_parts[-len(handler_parts) :] == handler_parts
    )


def _symbol_parts(value: str) -> tuple[tuple[str, ...], ...]:
    return tuple(tokens for part in re.split(r"[.:]+", value) if (tokens := _tokens(part)))


def _finding_text(finding: Finding) -> str:
    parts: list[str] = []
    for key in ("title", "data_flow", "rationale", "evidence"):
        value = finding.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


def _contains_sequence(tokens: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    width = len(expected)
    return width > 0 and any(tokens[index : index + width] == expected for index in range(len(tokens) - width + 1))


def _maximum_matching(finding_count: int, candidates: list[_Candidate]) -> dict[int, int]:
    adjacency: dict[int, list[_Candidate]] = {index: [] for index in range(finding_count)}
    for candidate in candidates:
        adjacency[candidate.finding_index].append(candidate)
    for edges in adjacency.values():
        edges.sort(key=lambda edge: (-edge.quality, edge.ground_truth_index))

    matched_by_gt: dict[int, int] = {}

    def assign(finding_index: int, visited_gt: set[int]) -> bool:
        for edge in adjacency[finding_index]:
            ground_truth_index = edge.ground_truth_index
            if ground_truth_index in visited_gt:
                continue
            visited_gt.add(ground_truth_index)
            previous = matched_by_gt.get(ground_truth_index)
            if previous is None or assign(previous, visited_gt):
                matched_by_gt[ground_truth_index] = finding_index
                return True
        return False

    order = sorted(
        range(finding_count),
        key=lambda index: (
            len(adjacency[index]),
            -(adjacency[index][0].quality if adjacency[index] else -1),
            index,
        ),
    )
    for finding_index in order:
        assign(finding_index, set())
    return matched_by_gt


def _normalize_class(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _normalize_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return re.sub(r"/+", "/", normalized).rstrip("/")


def _same_file(left: str, right: str) -> bool:
    normalized_left = _normalize_path(left)
    normalized_right = _normalize_path(right)
    return (
        normalized_left == normalized_right
        or normalized_left.endswith(f"/{normalized_right}")
        or normalized_right.endswith(f"/{normalized_left}")
    )


def _tokens(value: str | None) -> tuple[str, ...]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value or "")
    return tuple(re.findall(r"[a-z0-9]+", separated.lower()))
