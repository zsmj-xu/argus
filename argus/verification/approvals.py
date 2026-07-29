"""Hash-bound M8 approval workflow with no execution capability."""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

from argus.control.db import Database
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.domain.errors import ConflictError
from argus.domain.models import utc_now
from argus.verification.models import (
    Approval,
    ApprovalDecision,
    PolicyDecision,
    VerificationPlanStatus,
)
from argus.verification.persistence import VerificationRepositories
from argus.verification.policy import VerificationPolicy, VerificationPolicyConfig


class VerificationPolicyDenied(PermissionError):
    pass


class StaleVerificationApproval(ConflictError):
    pass


class ApprovalService:
    """Create and decide approvals bound to the current canonical plan hash."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self.verification = VerificationRepositories(database)
        self.control = Repositories(database)
        self.policy = VerificationPolicy()

    def request(
        self,
        plan_id: UUID,
        config: VerificationPolicyConfig,
        *,
        ttl: timedelta = timedelta(hours=24),
    ) -> Approval:
        plan = self.verification.plans.get(plan_id)
        if plan.status is VerificationPlanStatus.SUPERSEDED:
            raise StaleVerificationApproval("cannot approve a superseded plan")
        environment = self.verification.environments.get(plan.environment_id)
        result = self.policy.evaluate(plan, environment, config)
        if result.decision is PolicyDecision.DENY:
            raise VerificationPolicyDenied(result.reason)

        now = utc_now()
        if result.decision is PolicyDecision.ALLOW_AUTOMATIC:
            approval = Approval(
                plan_id=plan.id,
                plan_hash=plan.plan_hash,
                decision=ApprovalDecision.APPROVED,
                reviewer="system",
                reason=result.reason,
                created_at=now,
                decided_at=now,
                expires_at=now + ttl,
            )
            created = self.verification.approvals.create(approval)
            self.verification.plans.set_status(plan.id, VerificationPlanStatus.APPROVED)
            self._event("verification.approval.auto_approved", plan.finding_id, created)
            return created

        approval = self.verification.approvals.create(
            Approval(
                plan_id=plan.id,
                plan_hash=plan.plan_hash,
                created_at=now,
                expires_at=now + ttl,
            )
        )
        self.verification.plans.set_status(plan.id, VerificationPlanStatus.PENDING_APPROVAL)
        self._event("verification.approval.requested", plan.finding_id, approval)
        return approval

    def decide(
        self,
        approval_id: UUID,
        decision: ApprovalDecision,
        *,
        reviewer: str,
        reason: str,
    ) -> Approval:
        if decision not in {ApprovalDecision.APPROVED, ApprovalDecision.REJECTED}:
            raise ValueError("human approval decision must be approved or rejected")
        if not reviewer.strip() or not reason.strip():
            raise ValueError("approval decisions require reviewer and reason")

        approval = self.verification.approvals.get(approval_id)
        plan = self.verification.plans.get(approval.plan_id)
        now = utc_now()
        if plan.status is VerificationPlanStatus.SUPERSEDED or approval.plan_hash != plan.plan_hash:
            raise StaleVerificationApproval("approval plan hash no longer matches the current plan")
        if approval.expires_at is not None and approval.expires_at <= now:
            expired = approval.model_copy(
                update={
                    "decision": ApprovalDecision.EXPIRED,
                    "reviewer": "system",
                    "reason": "approval request expired",
                    "decided_at": now,
                }
            )
            self.verification.approvals.decide(expired)
            self.verification.plans.set_status(plan.id, VerificationPlanStatus.READY)
            self._event("verification.approval.expired", plan.finding_id, expired)
            raise StaleVerificationApproval("approval request has expired")

        decided = approval.model_copy(
            update={
                "decision": decision,
                "reviewer": reviewer.strip(),
                "reason": reason.strip(),
                "decided_at": now,
            }
        )
        decided = Approval.model_validate(decided.model_dump(mode="python"))
        persisted = self.verification.approvals.decide(decided)
        target = (
            VerificationPlanStatus.APPROVED
            if decision is ApprovalDecision.APPROVED
            else VerificationPlanStatus.REJECTED
        )
        self.verification.plans.set_status(plan.id, target)
        self._event(f"verification.approval.{decision.value}", plan.finding_id, persisted)
        return persisted

    def _event(self, event_type: str, finding_id: UUID, approval: Approval) -> None:
        finding = self.control.findings.get(finding_id)
        scan = self.control.scans.get(finding.scan_id)
        EventService(self.control.events).append(
            event_type,
            project_id=scan.project_id,
            scan_id=scan.id,
            finding_id=finding.id,
            payload={
                "approval_id": str(approval.id),
                "plan_id": str(approval.plan_id),
                "plan_hash": approval.plan_hash,
                "decision": approval.decision.value,
            },
        )
