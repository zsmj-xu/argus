"""Authorization Candidate → Slice → Expert plugin entrypoint."""

from argus.detection.builtin.authorization.provider import (
    AuthorizationCandidateProvider,
)
from argus.detection.runtime import DetectionRuleRuntime, run_detection_rule
from argus.execution.contracts import RuntimeContext, RuntimeInput, RuntimeOutput

RULE = DetectionRuleRuntime(
    rule_name="authorization",
    provider=AuthorizationCandidateProvider(),
    rule_instructions=(
        "For authorization/IDOR, decide whether the shown actor can select or "
        "modify the resource without a matching ownership, tenant, role, or "
        "policy check. Account only for framework protection visible in the "
        "supplied slice or source context."
    ),
)


def authorization_detection_runtime(
    context: RuntimeContext,
    inputs: dict[str, RuntimeInput],
) -> list[RuntimeOutput]:
    return run_detection_rule(context, inputs, RULE)
