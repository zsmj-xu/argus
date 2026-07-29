from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

from argus.control.repositories import Repositories
from argus.domain.errors import ConflictError, SchemaValidationError
from argus.verification.approvals import (
    ApprovalService,
    StaleVerificationApproval,
)
from argus.verification.models import (
    ApprovalDecision,
    Approval,
    RequestBudget,
    VerificationPlanStatus,
)
from argus.verification.planning import VerificationPlanCompiler
from argus.verification.policy import VerificationPolicyConfig
from argus.verification.requirements import RequirementResolver, VerifierDeclaration

from .helpers import plan_draft, seed_verification


def _persisted_plan(database, repositories, scan, environment, identities):
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
    repositories.requirements.upsert(requirement)
    draft = plan_draft(scan, environment, identities, finding_id=finding.id)
    plan = VerificationPlanCompiler().compile(requirement, draft)
    return finding, repositories.plans.create(plan)


def test_approval_is_hash_bound_and_revision_supersedes_old_approval(
    tmp_path: Path,
) -> None:
    database, repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        finding, plan = _persisted_plan(database, repositories, scan, environment, identities)
        with pytest.raises(SchemaValidationError, match="canonical fields"):
            repositories.plans.create(
                plan.model_copy(
                    update={
                        "id": UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                        "plan_hash": "0" * 64,
                    }
                )
            )
        with pytest.raises(ConflictError, match="current plan hash"):
            repositories.approvals.create(
                Approval(
                    plan_id=plan.id,
                    plan_hash="0" * 64,
                )
            )
        service = ApprovalService(database)
        approval = service.request(
            plan.id,
            VerificationPolicyConfig(enabled=True, allow_safe_read=True),
        )
        decided = service.decide(
            approval.id,
            ApprovalDecision.APPROVED,
            reviewer="alice",
            reason="Bounded static plan reviewed.",
        )
        assert decided.plan_hash == plan.plan_hash
        assert repositories.plans.get(plan.id).status is VerificationPlanStatus.APPROVED

        revised = VerificationPlanCompiler().revise(
            plan,
            request_budget=RequestBudget(
                max_requests=3,
                max_response_bytes=128_000,
                timeout_seconds=10,
            ),
        )
        repositories.plans.create(revised)

        assert repositories.plans.get(plan.id).status is VerificationPlanStatus.SUPERSEDED
        assert repositories.approvals.get(approval.id).decision is ApprovalDecision.SUPERSEDED
        assert repositories.plans.get(revised.id).status is VerificationPlanStatus.READY
        events = Repositories(database).events.list(scan_id=scan.id)
        assert "verification.approval.approved" in [event.event_type for event in events]
        assert finding.id == events[-1].finding_id
    finally:
        database.close()


def test_expired_approval_cannot_be_approved(tmp_path: Path) -> None:
    database, repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        _finding, plan = _persisted_plan(database, repositories, scan, environment, identities)
        service = ApprovalService(database)
        approval = service.request(
            plan.id,
            VerificationPolicyConfig(enabled=True, allow_safe_read=True),
            ttl=timedelta(microseconds=1),
        )

        with pytest.raises(StaleVerificationApproval, match="expired"):
            service.decide(
                approval.id,
                ApprovalDecision.APPROVED,
                reviewer="alice",
                reason="Too late.",
            )
        assert repositories.approvals.get(approval.id).decision is ApprovalDecision.EXPIRED
        assert repositories.plans.get(plan.id).status is VerificationPlanStatus.READY
    finally:
        database.close()


def test_environment_or_identity_change_supersedes_approved_plan(
    tmp_path: Path,
) -> None:
    database, repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        _finding, plan = _persisted_plan(database, repositories, scan, environment, identities)
        service = ApprovalService(database)
        approval = service.request(
            plan.id,
            VerificationPolicyConfig(enabled=True, allow_safe_read=True),
        )
        service.decide(
            approval.id,
            ApprovalDecision.APPROVED,
            reviewer="alice",
            reason="Original bindings reviewed.",
        )

        repositories.environments.update(
            environment.model_copy(update={"updated_at": environment.updated_at + timedelta(seconds=1)})
        )

        assert repositories.plans.get(plan.id).status is VerificationPlanStatus.SUPERSEDED
        assert repositories.approvals.get(approval.id).decision is ApprovalDecision.SUPERSEDED
    finally:
        database.close()
