"""Experimental business-invariant enrichment analyzer."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any

from argus.analyzers.base import AnalyzerBase
from argus.contracts import Phase
from argus.llm.client import HEAVY_MAX_TOKENS

if TYPE_CHECKING:
    from argus.contracts import AnalysisContext, AnalyzerResult

logger = logging.getLogger(__name__)

_HANDLER_KINDS = frozenset({"function", "method"})
_INVARIANT_KINDS = frozenset({"ownership", "authentication", "role", "replay", "trust_boundary"})
_CONFIDENCES = frozenset({"high", "medium", "low"})
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)

_SYSTEM = (
    "You are a senior application-security engineer. Extract only business invariants "
    "from the supplied static codegraph and source context. Return strict JSON."
)


class InvariantAnalyzer(AnalyzerBase):
    """Build a normalized per-handler invariant checklist; never emits Findings."""

    name = "invariant"
    phase = Phase.ENRICHMENT
    requires: list[str] = []

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:
        if _disabled(ctx):
            return {"analyzer": self.name, "findings": [], "enrichment": {"invariants": []}}

        handlers = _collect_handlers(ctx["graph"].query(""))
        skeleton = json.dumps(_compact_nodes(handlers), ensure_ascii=False, indent=2)
        source_context = _build_source_context(handlers, ctx["source"])
        prompt_template = self._load_prompt()
        # Use token replacement instead of str.format: prompt.txt intentionally contains
        # a literal JSON example with braces that must not be interpreted as placeholders.
        prompt = prompt_template.replace("{skeleton}", skeleton).replace("{source}", source_context)
        settings = ctx["config"].get(self.name, {})
        max_tokens = settings.get("max_tokens", HEAVY_MAX_TOKENS) if isinstance(settings, dict) else HEAVY_MAX_TOKENS
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            max_tokens = HEAVY_MAX_TOKENS
        strict_outputs = ctx["config"].get("strict_outputs") is True

        try:
            raw = ctx["llm"].complete(system=_SYSTEM, prompt=prompt, max_tokens=max_tokens)
        except Exception as exc:  # pragma: no cover - defensive around provider failures
            if strict_outputs:
                raise
            logger.warning("Invariant LLM call failed: %s", exc)
            raw = ""

        parsed = _parse_json_object(raw)
        if strict_outputs and parsed is None:
            raise RuntimeError("invariant analyzer returned invalid JSON")
        invariants = _normalize_invariants(parsed, handlers)
        return {
            "analyzer": self.name,
            "findings": [],
            "enrichment": {"invariants": invariants},
        }


def _disabled(ctx: AnalysisContext) -> bool:
    """Honor an explicit experimental disable switch; pipeline selection is the normal gate."""
    setting = ctx["config"].get("invariant")
    return isinstance(setting, dict) and setting.get("enabled") is False


def _collect_handlers(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep every real function/method node; never truncate the per-handler checklist."""
    handlers: list[dict[str, Any]] = []
    for node in nodes:
        if node.get("kind") not in _HANDLER_KINDS:
            continue
        if not isinstance(node.get("id"), str) or not node["id"]:
            continue
        if not isinstance(node.get("name"), str) or not node["name"]:
            continue
        handlers.append(node)
    return handlers


def _compact_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": node.get("id"),
            "name": node.get("name"),
            "qualified_name": node.get("qualified_name"),
            "file_path": node.get("file_path"),
            "kind": node.get("kind"),
            "start_line": node.get("start_line"),
            "end_line": node.get("end_line"),
            "signature": node.get("signature"),
        }
        for node in nodes
    ]


def _build_source_context(nodes: list[dict[str, Any]], source: Any) -> str:
    blocks: list[str] = []
    for node in nodes:
        path = node.get("file_path")
        if not isinstance(path, str) or not path:
            continue
        start = node.get("start_line") if isinstance(node.get("start_line"), int) else None
        end = node.get("end_line") if isinstance(node.get("end_line"), int) else None
        try:
            snippet = source.read(path, start, end)
        except (OSError, ValueError, TypeError):
            continue
        blocks.append(f"# {node.get('name')} [{node.get('id')}] @ {path}:{start}\n{snippet}")
    return "\n\n".join(blocks) if blocks else "(no source context available)"


def _parse_json_object(text: str) -> dict[str, Any] | None:
    if not text or not text.strip():
        return None
    candidates: list[str] = []
    match = _FENCE_RE.search(text)
    if match:
        candidates.append(match.group(1))
    candidates.append(text)
    for candidate in candidates:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end < start:
            continue
        try:
            parsed = json.loads(candidate[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _normalize_invariants(parsed: dict[str, Any] | None, handlers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if parsed is None or not isinstance(parsed.get("invariants"), list):
        return []

    by_id = {node["id"]: node for node in handlers if isinstance(node.get("id"), str)}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for node in handlers:
        name = node.get("name")
        if isinstance(name, str):
            by_name.setdefault(name, []).append(node)

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in parsed["invariants"]:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        statement = item.get("statement")
        if kind not in _INVARIANT_KINDS or not isinstance(statement, str) or not statement.strip():
            continue

        handler = _resolve_handler(item, by_id, by_name)
        if handler is None:
            continue

        node_id = handler["id"]
        inferred_from = _anchored_source_ref(item, handler)
        stable_id = _stable_id(item.get("id"), kind, node_id, statement)
        if stable_id in seen_ids:
            continue
        seen_ids.add(stable_id)
        confidence = item.get("confidence") if item.get("confidence") in _CONFIDENCES else "low"
        enforced_by = item.get("enforced_by")
        if not isinstance(enforced_by, str) or not enforced_by.strip():
            enforced_by = None
        resource = item.get("resource") if isinstance(item.get("resource"), str) else None

        normalized.append(
            {
                "id": stable_id,
                "kind": kind,
                "statement": statement.strip(),
                "handler": handler["name"],
                "handler_node_id": node_id,
                "resource": resource,
                "inferred_from": inferred_from,
                "confidence": confidence,
                "enforced_by": enforced_by,
            }
        )
    return normalized


def _resolve_handler(
    item: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    by_name: dict[str, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    for key in ("handler_node_id", "node_id"):
        candidate = item.get(key)
        if isinstance(candidate, str) and candidate in by_id:
            return by_id[candidate]

    name = item.get("handler")
    if not isinstance(name, str) or not name.strip():
        return None
    candidates = by_name.get(name.strip(), [])
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) <= 1:
        return None
    hint = _hint_file(item.get("inferred_from"))
    if hint is None:
        hint = _hint_file(item.get("source_ref"))
    matches = [node for node in candidates if node.get("file_path") == hint]
    return matches[0] if len(matches) == 1 else None


def _hint_file(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.rsplit(":", 1)[0]
    if isinstance(value, dict):
        file_value = value.get("file")
        if isinstance(file_value, str):
            return file_value
    return None


def _anchored_source_ref(item: dict[str, Any], handler: dict[str, Any]) -> str:
    raw_path = handler.get("file_path")
    raw_start = handler.get("start_line")
    raw_end = handler.get("end_line")
    path = raw_path if isinstance(raw_path, str) else ""
    start = raw_start if isinstance(raw_start, int) else 1
    end = raw_end if isinstance(raw_end, int) else start
    requested = _requested_line(item.get("inferred_from"))
    line = requested if requested is not None else start
    line = max(start, min(line, max(start, end)))
    return f"{path}:{line}"


def _requested_line(value: Any) -> int | None:
    if isinstance(value, str):
        raw = value.rsplit(":", 1)[-1]
        try:
            line = int(raw)
        except ValueError:
            return None
        return line if line > 0 else None
    if isinstance(value, dict):
        line_value = value.get("line")
        if isinstance(line_value, int) and line_value > 0:
            return line_value
    return None


def _stable_id(raw_id: Any, kind: str, node_id: str, statement: str) -> str:
    if isinstance(raw_id, str) and raw_id.strip():
        return raw_id.strip()
    digest = hashlib.sha1(f"{kind}|{node_id}|{statement}".encode("utf-8")).hexdigest()[:12]
    return f"invariant:{kind}:{digest}"


ANALYZER = InvariantAnalyzer()
