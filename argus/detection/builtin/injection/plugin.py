"""Injection Candidate → Slice → Expert plugin entrypoint."""

from argus.detection.builtin.injection.provider import (
    InjectionCandidateProvider,
)
from argus.detection.runtime import DetectionRuleRuntime, run_detection_rule
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput

RULE = DetectionRuleRuntime(
    rule_name="injection",
    provider=InjectionCandidateProvider(),
    rule_instructions=(
        "For injection, decide whether external or attacker-controlled data "
        "can reach the named SQL, command, or template sink through unsafe "
        "string construction, and whether the shown parameterization or "
        "sanitizer is actually effective."
    ),
)


def injection_detection_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    return run_detection_rule(context, inputs, RULE)
