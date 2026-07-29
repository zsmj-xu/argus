from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from argus.detection.builtin.injection.provider import InjectionCandidateProvider
from argus.detection.candidates import BoundedGraphSliceBuilder, SourceContextBuilder
from argus.detection.experts import ExpertOutputError, StrictExpertEvaluator
from argus.detection.fingerprints import finding_fingerprint
from argus.detection.runtime import DetectionRuleRuntime, run_detection_rule
from argus.domain.enums import StaticConfidence
from argus.domain.models import CodeLocation

from .helpers import FakeGraph, FakeSource, make_candidate, make_context


class StubLLM:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls = 0

    def complete(self, *, system: str, prompt: str, max_tokens: int = 32768) -> str:
        self.calls += 1
        assert "Do not create Finding IDs" in system
        assert "candidate" in json.loads(prompt)
        assert max_tokens >= 1024
        return self.response if isinstance(self.response, str) else json.dumps(self.response)


def _injection_context():
    nodes = [
        {
            "id": "cg-unsafe",
            "kind": "function",
            "name": "unsafe_lookup",
            "qualified_name": "api.unsafe_lookup",
            "file_path": "app.py",
            "language": "python",
            "start_line": 1,
            "end_line": 2,
        },
        {
            "id": "cg-safe",
            "kind": "function",
            "name": "safe_lookup",
            "qualified_name": "api.safe_lookup",
            "file_path": "app.py",
            "language": "python",
            "start_line": 3,
            "end_line": 4,
        },
        {
            "id": "cg-execute",
            "kind": "method",
            "name": "execute",
            "qualified_name": "cursor.execute",
            "file_path": "db.py",
            "language": "python",
            "start_line": 1,
            "end_line": 1,
        },
    ]
    edges = [
        {"id": "call-unsafe", "source": "cg-unsafe", "target": "cg-execute", "kind": "calls"},
        {"id": "call-safe", "source": "cg-safe", "target": "cg-execute", "kind": "calls"},
    ]
    source = FakeSource(
        {
            "app.py": (
                "def unsafe_lookup(request):\n"
                "    cursor.execute(f\"select * from users where id={request.params['id']}\")\n"
                "def safe_lookup(request):\n"
                "    cursor.execute(\"select * from users where id=?\", (request.params['id'],))\n"
            ),
            "db.py": "def execute(query, params=None): pass\n",
        }
    )
    return make_context(graph=FakeGraph(nodes, edges), source=source)


def test_injection_candidates_are_sink_first_deterministic_and_exclude_safe_calls() -> None:
    context = _injection_context()
    provider = InjectionCandidateProvider()

    first = provider.generate(context)
    second = provider.generate(context)

    assert first == second
    assert [item.primary_node_ids for item in first] == [["cg-unsafe"]]
    assert first[0].sink_node_ids == ["cg-execute"]
    assert first[0].reason_codes == [
        "SINK_SQL",
        "DYNAMIC_STRING_CONSTRUCTION",
        "EXTERNAL_INPUT_REACHABLE",
    ]


def test_no_sink_produces_no_candidate() -> None:
    context = make_context(
        graph=FakeGraph(
            [
                {
                    "id": "cg-handler",
                    "kind": "function",
                    "name": "handler",
                    "file_path": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                }
            ]
        ),
        source=FakeSource({"app.py": "def handler(): return 1\n"}),
    )
    assert InjectionCandidateProvider().generate(context) == []


def test_graph_slice_and_source_context_obey_hard_configured_bounds() -> None:
    nodes = [
        {
            "id": f"cg-{index}",
            "kind": "function",
            "name": f"function_{index}",
            "file_path": "chain.py",
            "start_line": index + 1,
            "end_line": index + 1,
        }
        for index in range(10)
    ]
    nodes.append(
        {
            "id": "cg-execute",
            "kind": "method",
            "name": "execute",
            "file_path": "chain.py",
            "start_line": 11,
            "end_line": 11,
        }
    )
    edges = [
        {"id": f"edge-{index}", "source": f"cg-{index}", "target": f"cg-{index + 1}", "kind": "calls"}
        for index in range(9)
    ]
    context = make_context(
        graph=FakeGraph(nodes, edges),
        source=FakeSource({"chain.py": "".join(f"line {index}\n" for index in range(20))}),
        config={
            "detection": {
                "graphSliceMaxNodes": 3,
                "graphSliceRadius": 8,
                "sourceMaxExcerpts": 2,
                "sourceExcerptChars": 5,
                "sourceTotalChars": 7,
            }
        },
    )
    candidate = make_candidate(context, node_id="cg-0").model_copy(update={"sink_node_ids": ["cg-9"]})

    graph_slice = BoundedGraphSliceBuilder().build(context, candidate)
    source_context = SourceContextBuilder().build(context, candidate, graph_slice)

    assert len(graph_slice.nodes) == 3
    assert graph_slice.truncated is True
    assert len(source_context.excerpts) <= 2
    assert source_context.total_chars <= 7
    assert source_context.truncated is True


def test_expert_rejects_invalid_json_and_out_of_slice_evidence() -> None:
    context = _injection_context()
    candidate = InjectionCandidateProvider().generate(context)[0]
    graph_slice = BoundedGraphSliceBuilder().build(context, candidate)
    source_context = SourceContextBuilder().build(context, candidate, graph_slice)

    with pytest.raises(ExpertOutputError, match="invalid JSON"):
        StrictExpertEvaluator(StubLLM("not-json"), rule_instructions="judge").evaluate(
            candidate, graph_slice, source_context
        )

    response = {
        "supported": True,
        "confidence": "high",
        "rationale": "External data reaches the SQL sink.",
        "evidence_claims": [
            {
                "node_id": "not-in-slice",
                "claim": "invented",
                "evidence_ref": "none",
            }
        ],
        "remediation_hints": ["Use parameters."],
    }
    with pytest.raises(ExpertOutputError, match="outside the Graph Slice"):
        StrictExpertEvaluator(StubLLM(response), rule_instructions="judge").evaluate(
            candidate, graph_slice, source_context
        )


def test_fingerprint_uses_stable_facts_not_human_title() -> None:
    context = _injection_context()
    candidate = InjectionCandidateProvider().generate(context)[0]
    locations = [CodeLocation(file="app.py", line=1, node_id="cg-unsafe")]

    baseline = finding_fingerprint(candidate=candidate, locations=locations)
    renamed_display_title = "A completely different human-facing title"

    assert renamed_display_title not in baseline
    assert finding_fingerprint(candidate=candidate, locations=locations) == baseline


def test_runtime_does_not_build_llm_when_provider_has_no_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _injection_context()

    class EmptyProvider:
        def generate(self, _context):
            return []

    def fail_build_llm(_context):
        raise AssertionError("LLM must not be built without a Candidate")

    monkeypatch.setattr("argus.detection.runtime._detection_context", lambda *_: context)
    monkeypatch.setattr("argus.detection.runtime._build_llm", fail_build_llm)
    runtime_context = SimpleNamespace(scan=context.scan)
    outputs = run_detection_rule(
        runtime_context,  # type: ignore[arg-type]
        {},
        DetectionRuleRuntime(
            rule_name="injection",
            provider=EmptyProvider(),
            rule_instructions="judge",
        ),
    )

    assert len(outputs) == 5
    finding_output = next(item for item in outputs if item.capability == "finding.static.injection.v2")
    assert finding_output.json_value == []
    assert finding_output.static_findings == ()


def test_runtime_persists_each_stage_as_linked_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _injection_context()
    response = {
        "supported": True,
        "confidence": "high",
        "rationale": "Request input reaches an interpolated SQL query.",
        "preconditions": ["The endpoint is reachable."],
        "evidence_claims": [
            {
                "node_id": "cg-unsafe",
                "claim": "The query embeds request input.",
                "evidence_ref": "source:app.py:1",
            }
        ],
        "remediation_hints": ["Use a parameterized query."],
    }
    llm = StubLLM(response)
    monkeypatch.setattr("argus.detection.runtime._detection_context", lambda *_: context)
    monkeypatch.setattr("argus.detection.runtime._build_llm", lambda *_: llm)

    outputs = run_detection_rule(
        SimpleNamespace(scan=context.scan),  # type: ignore[arg-type]
        {},
        DetectionRuleRuntime(
            rule_name="injection",
            provider=InjectionCandidateProvider(),
            rule_instructions="judge",
        ),
    )

    assert len(outputs) == 9
    assert {output.capability for output in outputs if output.artifact_id is not None} == {
        "candidate.injection.v1",
        "graph.slice.injection.v1",
        "source.context.injection.v1",
        "assessment.injection.v1",
    }
    finding_output = next(output for output in outputs if output.capability == "finding.static.injection.v2")
    assert len(finding_output.static_findings) == 1
    finding = finding_output.static_findings[0]
    record_artifact_ids = {output.artifact_id for output in outputs if output.artifact_id is not None}
    assert finding.graph_slice_artifact_id in record_artifact_ids
    assert set(finding.evidence_artifact_ids) == record_artifact_ids
    assert finding.status.value == "unverified"
    assert llm.calls == 1


def test_valid_expert_assessment_has_no_finding_identity_and_is_llm_inferred() -> None:
    context = _injection_context()
    candidate = InjectionCandidateProvider().generate(context)[0]
    graph_slice = BoundedGraphSliceBuilder().build(context, candidate)
    source_context = SourceContextBuilder().build(context, candidate, graph_slice)
    node_id = graph_slice.nodes[0].id
    llm = StubLLM(
        {
            "supported": True,
            "confidence": "medium",
            "rationale": "The bounded evidence supports unsafe flow.",
            "preconditions": ["Attacker controls id."],
            "evidence_claims": [
                {
                    "node_id": node_id,
                    "claim": "Unsafe query construction.",
                    "evidence_ref": "source:app.py",
                }
            ],
            "remediation_hints": ["Use a parameterized query."],
        }
    )

    assessment = StrictExpertEvaluator(llm, rule_instructions="judge").evaluate(
        candidate,
        graph_slice,
        source_context,
    )

    assert assessment.confidence is StaticConfidence.MEDIUM
    assert "finding_id" not in type(assessment).model_fields
    assert assessment.provenance.extraction_method.value == "llm_inferred"
    assert llm.calls == 1
