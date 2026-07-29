"""Default-deny M8 risk policy; returns decisions but executes nothing."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from argus.verification.models import (
    EnvironmentProfile,
    PolicyDecision,
    PolicyResult,
    ResetCapability,
    RiskClass,
    VerificationPlan,
)


class VerificationPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    allow_safe_read: bool = False
    allow_reversible_write: bool = False


class VerificationPolicy:
    def evaluate(
        self,
        plan: VerificationPlan,
        environment: EnvironmentProfile,
        config: VerificationPolicyConfig,
    ) -> PolicyResult:
        if plan.environment_id != environment.id:
            return PolicyResult(decision=PolicyDecision.DENY, reason="plan and environment binding differ")
        if plan.risk_class is RiskClass.R0_STATIC:
            return PolicyResult(decision=PolicyDecision.ALLOW_AUTOMATIC, reason="R0 contains no network actions")
        if not config.enabled:
            return PolicyResult(decision=PolicyDecision.DENY, reason="verification.enabled is false")
        if not environment.enabled:
            return PolicyResult(decision=PolicyDecision.DENY, reason="verification environment is disabled")
        if plan.risk_class is RiskClass.R1_SAFE_READ:
            if not config.allow_safe_read:
                return PolicyResult(decision=PolicyDecision.DENY, reason="safe-read verification is not enabled")
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="R1 safe-read plans require project opt-in and human approval",
            )
        if plan.risk_class is RiskClass.R2_REVERSIBLE_WRITE:
            if not config.allow_reversible_write:
                return PolicyResult(decision=PolicyDecision.DENY, reason="reversible-write verification is not enabled")
            if environment.reset_capability is not ResetCapability.AUTOMATED:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="R2 requires an automatically resettable environment",
                )
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="R2 requires per-plan human approval",
            )
        if plan.risk_class is RiskClass.R3_HIGH_IMPACT:
            return PolicyResult(decision=PolicyDecision.DENY, reason="R3 is denied by default")
        return PolicyResult(decision=PolicyDecision.DENY, reason="R4 is permanently prohibited")
