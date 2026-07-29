"""Deterministic, offline VerificationPlan compilation and hashing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from uuid import UUID

from argus.domain.hashing import CanonicalValue, sha256_digest
from argus.domain.models import utc_now
from argus.verification.models import (
    AbortCondition,
    EnvironmentProfile,
    ExpectedObservation,
    ExpectedSideEffect,
    IdentityProfile,
    RequestBudget,
    RiskClass,
    RollbackStrategy,
    VerificationAction,
    VerificationPlan,
    VerificationPlanStatus,
    VerificationRequirement,
)


class MissingVerificationInputs(ValueError):
    """A plan cannot be compiled while its requirement is incomplete."""


@dataclass(frozen=True)
class PlanDraft:
    finding_id: UUID
    snapshot_id: UUID
    environment: EnvironmentProfile
    identities: list[IdentityProfile]
    actions: list[VerificationAction]
    request_budget: RequestBudget
    expected_observations: list[ExpectedObservation]
    expected_side_effects: list[ExpectedSideEffect]
    rollback_strategy: RollbackStrategy
    health_checks: list[str]
    abort_conditions: list[AbortCondition]
    risk_class: RiskClass


def plan_hash_payload(plan: VerificationPlan | PlanDraft) -> dict[str, object]:
    """Return every substantive plan field and no lifecycle metadata."""

    environment_id = plan.environment_id if isinstance(plan, VerificationPlan) else plan.environment.id
    identity_handles = (
        plan.identity_handles if isinstance(plan, VerificationPlan) else [item.handle for item in plan.identities]
    )
    return {
        "finding_id": plan.finding_id,
        "snapshot_id": plan.snapshot_id,
        "environment_id": environment_id,
        "identity_handles": identity_handles,
        "actions": plan.actions,
        "request_budget": plan.request_budget,
        "expected_observations": plan.expected_observations,
        "expected_side_effects": plan.expected_side_effects,
        "rollback_strategy": plan.rollback_strategy,
        "health_checks": plan.health_checks,
        "abort_conditions": plan.abort_conditions,
        "risk_class": plan.risk_class,
    }


def compute_plan_hash(plan: VerificationPlan | PlanDraft) -> str:
    return sha256_digest(cast(CanonicalValue, plan_hash_payload(plan)))


class VerificationPlanCompiler:
    """Compile a declarative plan; this class has no execution capability."""

    def compile(
        self,
        requirement: VerificationRequirement,
        draft: PlanDraft,
    ) -> VerificationPlan:
        if requirement.finding_id != draft.finding_id:
            raise ValueError("requirement and plan draft finding IDs differ")
        if requirement.missing_fields:
            raise MissingVerificationInputs("verification inputs are missing: " + ", ".join(requirement.missing_fields))
        if not draft.environment.enabled:
            raise MissingVerificationInputs("verification environment is disabled")
        if draft.environment.source_snapshot_binding not in {None, draft.snapshot_id}:
            raise MissingVerificationInputs("verification environment is bound to another snapshot")
        by_role = {identity.role for identity in draft.identities if identity.enabled}
        missing_roles = set(requirement.required_identity_roles) - by_role
        if missing_roles:
            raise MissingVerificationInputs(f"required identity roles are missing: {sorted(missing_roles)}")
        if any(not identity.enabled for identity in draft.identities):
            raise MissingVerificationInputs("verification plan references a disabled identity")
        if any(identity.project_id != draft.environment.project_id for identity in draft.identities):
            raise ValueError("environment and identities must belong to the same project")

        now = utc_now()
        plan = VerificationPlan(
            finding_id=draft.finding_id,
            snapshot_id=draft.snapshot_id,
            environment_id=draft.environment.id,
            identity_handles=[item.handle for item in draft.identities],
            actions=draft.actions,
            request_budget=draft.request_budget,
            expected_observations=draft.expected_observations,
            expected_side_effects=draft.expected_side_effects,
            rollback_strategy=draft.rollback_strategy,
            health_checks=draft.health_checks,
            abort_conditions=draft.abort_conditions,
            risk_class=draft.risk_class,
            plan_hash="0" * 64,
            status=VerificationPlanStatus.READY,
            created_at=now,
            updated_at=now,
        )
        return plan.model_copy(update={"plan_hash": compute_plan_hash(plan)})

    def revise(self, current: VerificationPlan, **changes: object) -> VerificationPlan:
        forbidden = {"id", "finding_id", "snapshot_id", "plan_hash", "status", "created_at"}
        if forbidden & set(changes):
            raise ValueError(f"plan revision cannot change immutable fields: {sorted(forbidden & set(changes))}")
        now = utc_now()
        revised = current.model_copy(
            update={
                **changes,
                "id": UUID(
                    int=uuid_int_from_hash(
                        sha256_digest(
                            cast(
                                CanonicalValue,
                                {
                                    "current": current.plan_hash,
                                    "changes": changes,
                                },
                            )
                        )
                    )
                ),
                "plan_hash": "0" * 64,
                "status": VerificationPlanStatus.READY,
                "created_at": now,
                "updated_at": now,
            }
        )
        validated = VerificationPlan.model_validate(revised.model_dump(mode="python"))
        return validated.model_copy(update={"plan_hash": compute_plan_hash(validated)})


def uuid_int_from_hash(value: str) -> int:
    """Derive a deterministic UUID-sized integer for an immutable revision."""

    return int(value[:32], 16)
