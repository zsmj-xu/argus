from __future__ import annotations

from pathlib import Path

import pytest

from argus.control.repositories import Repositories
from argus.verification.models import (
    PolicyDecision,
    RequestBudget,
    ResetCapability,
    RiskClass,
    VerificationPlan,
)
from argus.verification.planning import (
    MissingVerificationInputs,
    VerificationPlanCompiler,
)
from argus.verification.policy import VerificationPolicy, VerificationPolicyConfig
from argus.verification.requirements import RequirementResolver, VerifierDeclaration

from .helpers import plan_draft, seed_verification


def _ready_requirement(database, scan, environment, identities):
    finding = Repositories(database).findings.list(scan_id=scan.id)[0]
    requirement = RequirementResolver().resolve(
        finding,
        VerifierDeclaration(
            verifier_id="authorization_differential_read",
            supported_vuln_classes=["authorization"],
            required_environment_capabilities=["readonly_http"],
            required_identity_roles=["owner", "peer"],
            required_test_data=["resource_id"],
        ),
        environments=[environment],
        identities=identities,
        test_data_keys={"resource_id"},
    )
    return finding, requirement


def test_plan_hash_covers_substantive_fields_and_missing_inputs_block_compile(
    tmp_path: Path,
) -> None:
    database, _repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        finding, requirement = _ready_requirement(database, scan, environment, identities)
        draft = plan_draft(scan, environment, identities, finding_id=finding.id)
        compiler = VerificationPlanCompiler()
        plan = compiler.compile(requirement, draft)
        same = compiler.compile(requirement, draft)
        changed = compiler.revise(
            plan,
            request_budget=RequestBudget(
                max_requests=3,
                max_response_bytes=128_000,
                timeout_seconds=10,
            ),
        )

        assert plan.plan_hash == same.plan_hash
        assert plan.plan_hash != changed.plan_hash
        assert plan.id != changed.id

        with pytest.raises(MissingVerificationInputs, match="test_data"):
            compiler.compile(
                requirement.model_copy(update={"missing_fields": ["test_data:resource_id"]}),
                draft,
            )
    finally:
        database.close()


def test_default_policy_matrix_is_deny_by_default(tmp_path: Path) -> None:
    database, _repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        finding, requirement = _ready_requirement(database, scan, environment, identities)
        draft = plan_draft(scan, environment, identities, finding_id=finding.id)
        plan = VerificationPlanCompiler().compile(requirement, draft)
        policy = VerificationPolicy()

        assert policy.evaluate(plan, environment, VerificationPolicyConfig()).decision is PolicyDecision.DENY
        static = VerificationPlan.model_validate(
            plan.model_copy(
                update={
                    "risk_class": RiskClass.R0_STATIC,
                    "request_budget": RequestBudget(
                        max_requests=0,
                        max_response_bytes=0,
                        timeout_seconds=1,
                    ),
                }
            ).model_dump(mode="python")
        )
        assert (
            policy.evaluate(static, environment, VerificationPolicyConfig()).decision is PolicyDecision.ALLOW_AUTOMATIC
        )
        assert (
            policy.evaluate(
                plan,
                environment,
                VerificationPolicyConfig(enabled=True, allow_safe_read=True),
            ).decision
            is PolicyDecision.REQUIRE_APPROVAL
        )

        high_impact = plan.model_copy(update={"risk_class": RiskClass.R3_HIGH_IMPACT})
        assert (
            policy.evaluate(
                high_impact,
                environment,
                VerificationPolicyConfig(
                    enabled=True,
                    allow_safe_read=True,
                    allow_reversible_write=True,
                ),
            ).decision
            is PolicyDecision.DENY
        )
        prohibited = plan.model_copy(update={"risk_class": RiskClass.R4_PROHIBITED})
        assert (
            policy.evaluate(
                prohibited,
                environment,
                VerificationPolicyConfig(
                    enabled=True,
                    allow_safe_read=True,
                    allow_reversible_write=True,
                ),
            ).decision
            is PolicyDecision.DENY
        )

        reversible = plan.model_copy(
            update={
                "risk_class": RiskClass.R2_REVERSIBLE_WRITE,
                "expected_side_effects": [{"description": "fixture row changes", "reversible": True}],
            }
        )
        no_reset = policy.evaluate(
            reversible,
            environment,
            VerificationPolicyConfig(enabled=True, allow_reversible_write=True),
        )
        assert no_reset.decision is PolicyDecision.DENY
        resettable = environment.model_copy(update={"reset_capability": ResetCapability.AUTOMATED})
        assert (
            policy.evaluate(
                reversible,
                resettable,
                VerificationPolicyConfig(enabled=True, allow_reversible_write=True),
            ).decision
            is PolicyDecision.REQUIRE_APPROVAL
        )
    finally:
        database.close()
