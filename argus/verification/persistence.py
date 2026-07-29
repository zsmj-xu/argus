"""Control Store repositories for M8 verification planning records."""

from __future__ import annotations

from datetime import datetime
from typing import TypeVar, cast
from uuid import UUID

from pydantic import BaseModel, ValidationError
from sqlalchemy import Select, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError

from argus.control.db import Database
from argus.control.orm import (
    VerificationApprovalRow,
    VerificationAttemptRow,
    VerificationEnvironmentRow,
    VerificationEvidenceRow,
    VerificationIdentityRow,
    VerificationPlanRow,
    VerificationRequirementRow,
)
from argus.domain.errors import ConflictError, NotFoundError, SchemaValidationError
from argus.domain.models import utc_now
from argus.verification.models import (
    Approval,
    ApprovalDecision,
    EnvironmentProfile,
    IdentityProfile,
    VerificationAttempt,
    VerificationConclusion,
    VerificationEvidence,
    VerificationPlan,
    VerificationPlanStatus,
    VerificationRequirement,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


def _validated(model_type: type[ModelT], data: dict[str, object]) -> ModelT:
    try:
        return model_type.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError(f"invalid persisted {model_type.__name__}: {exc}") from exc


def _revalidated(model_type: type[ModelT], value: ModelT) -> ModelT:
    return _validated(model_type, value.model_dump(mode="python", warnings="none"))


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _environment_from_row(row: VerificationEnvironmentRow) -> EnvironmentProfile:
    return _validated(
        EnvironmentProfile,
        {
            "id": row.id,
            "project_id": row.project_id,
            "kind": row.kind,
            "target_base_url": row.target_base_url,
            "scope_allowlist": row.scope_allowlist,
            "capabilities": row.capabilities,
            "health_checks": row.health_checks,
            "reset_capability": row.reset_capability,
            "source_snapshot_binding": row.source_snapshot_binding,
            "test_only": row.test_only,
            "allow_private_addresses": row.allow_private_addresses,
            "enabled": row.enabled,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        },
    )


def _identity_from_row(row: VerificationIdentityRow) -> IdentityProfile:
    return _validated(
        IdentityProfile,
        {
            "id": row.id,
            "project_id": row.project_id,
            "handle": row.handle,
            "role": row.role,
            "tenant": row.tenant,
            "attributes": row.identity_attributes,
            "credential_ref": row.credential_ref,
            "enabled": row.enabled,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        },
    )


def _requirement_from_row(row: VerificationRequirementRow) -> VerificationRequirement:
    return _validated(
        VerificationRequirement,
        {
            "finding_id": row.finding_id,
            "required_environment_capabilities": row.required_environment_capabilities,
            "required_identity_roles": row.required_identity_roles,
            "required_test_data": row.required_test_data,
            "missing_fields": row.missing_fields,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        },
    )


def _plan_from_row(row: VerificationPlanRow) -> VerificationPlan:
    return _validated(
        VerificationPlan,
        {
            "id": row.id,
            "finding_id": row.finding_id,
            "snapshot_id": row.snapshot_id,
            "environment_id": row.environment_id,
            "identity_handles": row.identity_handles,
            "actions": row.actions,
            "request_budget": row.request_budget,
            "expected_observations": row.expected_observations,
            "expected_side_effects": row.expected_side_effects,
            "rollback_strategy": row.rollback_strategy,
            "health_checks": row.health_checks,
            "abort_conditions": row.abort_conditions,
            "risk_class": row.risk_class,
            "plan_hash": row.plan_hash,
            "status": row.status,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        },
    )


def _approval_from_row(row: VerificationApprovalRow) -> Approval:
    return _validated(
        Approval,
        {
            "id": row.id,
            "plan_id": row.plan_id,
            "plan_hash": row.plan_hash,
            "decision": row.decision,
            "reviewer": row.reviewer,
            "reason": row.reason,
            "created_at": row.created_at,
            "decided_at": row.decided_at,
            "expires_at": row.expires_at,
        },
    )


def _attempt_from_row(row: VerificationAttemptRow) -> VerificationAttempt:
    return _validated(
        VerificationAttempt,
        {
            "id": row.id,
            "plan_id": row.plan_id,
            "plan_hash": row.plan_hash,
            "finding_id": row.finding_id,
            "snapshot_id": row.snapshot_id,
            "environment_id": row.environment_id,
            "conclusion": row.conclusion,
            "request_count": row.request_count,
            "response_bytes": row.response_bytes,
            "health_before": row.health_before,
            "health_after": row.health_after,
            "abort_reason": row.abort_reason,
            "started_at": row.started_at,
            "finished_at": row.finished_at,
        },
    )


def _evidence_from_row(row: VerificationEvidenceRow) -> VerificationEvidence:
    return _validated(
        VerificationEvidence,
        {
            "id": row.id,
            "attempt_id": row.attempt_id,
            "plan_id": row.plan_id,
            "action_id": row.action_id,
            "identity_handle": row.identity_handle,
            "request_summary": row.request_summary,
            "response_status": row.response_status,
            "response_headers": row.response_headers,
            "body_hash": row.body_hash,
            "body_excerpt": row.body_excerpt,
            "observation": row.observation,
            "predicate_result": row.predicate_result,
            "conclusion": row.conclusion,
            "artifact_hash": row.artifact_hash,
            "artifact_size_bytes": row.artifact_size_bytes,
            "created_at": row.created_at,
        },
    )


def _supersede_plans(
    session: object,
    plan_ids: list[str],
    *,
    reason: str,
) -> None:
    from sqlalchemy.orm import Session

    if not plan_ids:
        return
    assert isinstance(session, Session)
    now = _dt(utc_now())
    session.execute(
        update(VerificationPlanRow)
        .where(
            VerificationPlanRow.id.in_(plan_ids),
            VerificationPlanRow.status.in_(PlanRepository._ACTIVE),
        )
        .values(status=VerificationPlanStatus.SUPERSEDED.value, updated_at=now)
    )
    session.execute(
        update(VerificationApprovalRow)
        .where(
            VerificationApprovalRow.plan_id.in_(plan_ids),
            VerificationApprovalRow.decision.in_([ApprovalDecision.PENDING.value, ApprovalDecision.APPROVED.value]),
        )
        .values(
            decision=ApprovalDecision.SUPERSEDED.value,
            reviewer="system",
            reason=reason,
            decided_at=now,
        )
    )


class EnvironmentRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, environment: EnvironmentProfile) -> EnvironmentProfile:
        environment = _revalidated(EnvironmentProfile, environment)
        row = VerificationEnvironmentRow(
            id=str(environment.id),
            project_id=str(environment.project_id),
            kind=environment.kind.value,
            target_base_url=environment.target_base_url,
            scope_allowlist=[item.model_dump(mode="json") for item in environment.scope_allowlist],
            capabilities=environment.capabilities,
            health_checks=[item.model_dump(mode="json") for item in environment.health_checks],
            reset_capability=environment.reset_capability.value,
            source_snapshot_binding=(
                str(environment.source_snapshot_binding) if environment.source_snapshot_binding is not None else None
            ),
            test_only=environment.test_only,
            allow_private_addresses=environment.allow_private_addresses,
            enabled=environment.enabled,
            created_at=_dt(environment.created_at) or "",
            updated_at=_dt(environment.updated_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification environment could not be created: {environment.id}") from exc
        return environment

    def get(self, environment_id: UUID) -> EnvironmentProfile:
        with self.database.session() as session:
            row = session.get(VerificationEnvironmentRow, str(environment_id))
            if row is None:
                raise NotFoundError(f"verification environment not found: {environment_id}")
            return _environment_from_row(row)

    def list(self, *, project_id: UUID | None = None) -> list[EnvironmentProfile]:
        statement: Select[tuple[VerificationEnvironmentRow]] = select(VerificationEnvironmentRow)
        if project_id is not None:
            statement = statement.where(VerificationEnvironmentRow.project_id == str(project_id))
        statement = statement.order_by(VerificationEnvironmentRow.created_at, VerificationEnvironmentRow.id)
        with self.database.session() as session:
            return [_environment_from_row(row) for row in session.scalars(statement).all()]

    def update(self, environment: EnvironmentProfile) -> EnvironmentProfile:
        environment = _revalidated(EnvironmentProfile, environment)
        statement = (
            update(VerificationEnvironmentRow)
            .where(VerificationEnvironmentRow.id == str(environment.id))
            .values(
                kind=environment.kind.value,
                target_base_url=environment.target_base_url,
                scope_allowlist=[item.model_dump(mode="json") for item in environment.scope_allowlist],
                capabilities=environment.capabilities,
                health_checks=[item.model_dump(mode="json") for item in environment.health_checks],
                reset_capability=environment.reset_capability.value,
                source_snapshot_binding=(
                    str(environment.source_snapshot_binding)
                    if environment.source_snapshot_binding is not None
                    else None
                ),
                test_only=environment.test_only,
                allow_private_addresses=environment.allow_private_addresses,
                enabled=environment.enabled,
                updated_at=_dt(environment.updated_at),
            )
        )
        with self.database.session() as session:
            plan_ids = list(
                session.scalars(
                    select(VerificationPlanRow.id).where(
                        VerificationPlanRow.environment_id == str(environment.id),
                        VerificationPlanRow.status.in_(PlanRepository._ACTIVE),
                    )
                ).all()
            )
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                raise NotFoundError(f"verification environment not found: {environment.id}")
            _supersede_plans(
                session,
                plan_ids,
                reason="verification environment changed",
            )
        return environment


class IdentityRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, identity: IdentityProfile) -> IdentityProfile:
        identity = _revalidated(IdentityProfile, identity)
        row = VerificationIdentityRow(
            id=str(identity.id),
            project_id=str(identity.project_id),
            handle=identity.handle,
            role=identity.role,
            tenant=identity.tenant,
            identity_attributes=identity.attributes,
            credential_ref=identity.credential_ref,
            enabled=identity.enabled,
            created_at=_dt(identity.created_at) or "",
            updated_at=_dt(identity.updated_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification identity could not be created: {identity.handle}") from exc
        return identity

    def get(self, identity_id: UUID) -> IdentityProfile:
        with self.database.session() as session:
            row = session.get(VerificationIdentityRow, str(identity_id))
            if row is None:
                raise NotFoundError(f"verification identity not found: {identity_id}")
            return _identity_from_row(row)

    def list(self, *, project_id: UUID | None = None) -> list[IdentityProfile]:
        statement: Select[tuple[VerificationIdentityRow]] = select(VerificationIdentityRow)
        if project_id is not None:
            statement = statement.where(VerificationIdentityRow.project_id == str(project_id))
        statement = statement.order_by(VerificationIdentityRow.created_at, VerificationIdentityRow.id)
        with self.database.session() as session:
            return [_identity_from_row(row) for row in session.scalars(statement).all()]

    def update(self, identity: IdentityProfile) -> IdentityProfile:
        identity = _revalidated(IdentityProfile, identity)
        statement = (
            update(VerificationIdentityRow)
            .where(VerificationIdentityRow.id == str(identity.id))
            .values(
                handle=identity.handle,
                role=identity.role,
                tenant=identity.tenant,
                identity_attributes=identity.attributes,
                credential_ref=identity.credential_ref,
                enabled=identity.enabled,
                updated_at=_dt(identity.updated_at),
            )
        )
        try:
            with self.database.session() as session:
                current = session.get(VerificationIdentityRow, str(identity.id))
                if current is None:
                    raise NotFoundError(f"verification identity not found: {identity.id}")
                plan_ids = list(
                    session.scalars(
                        select(VerificationPlanRow.id).where(
                            VerificationPlanRow.identity_handles.contains(current.handle),
                            VerificationPlanRow.environment_id.in_(
                                select(VerificationEnvironmentRow.id).where(
                                    VerificationEnvironmentRow.project_id == current.project_id
                                )
                            ),
                            VerificationPlanRow.status.in_(PlanRepository._ACTIVE),
                        )
                    ).all()
                )
                changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
                if changed != 1:
                    raise NotFoundError(f"verification identity not found: {identity.id}")
                _supersede_plans(
                    session,
                    plan_ids,
                    reason="verification identity changed",
                )
        except IntegrityError as exc:
            raise ConflictError(f"verification identity could not be updated: {identity.handle}") from exc
        return identity


class RequirementRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upsert(self, requirement: VerificationRequirement) -> VerificationRequirement:
        requirement = _revalidated(VerificationRequirement, requirement)
        with self.database.session() as session:
            row = session.get(VerificationRequirementRow, str(requirement.finding_id))
            if row is None:
                session.add(
                    VerificationRequirementRow(
                        finding_id=str(requirement.finding_id),
                        required_environment_capabilities=requirement.required_environment_capabilities,
                        required_identity_roles=requirement.required_identity_roles,
                        required_test_data=requirement.required_test_data,
                        missing_fields=requirement.missing_fields,
                        created_at=_dt(requirement.created_at) or "",
                        updated_at=_dt(requirement.updated_at) or "",
                    )
                )
            else:
                row.required_environment_capabilities = requirement.required_environment_capabilities
                row.required_identity_roles = requirement.required_identity_roles
                row.required_test_data = requirement.required_test_data
                row.missing_fields = requirement.missing_fields
                row.updated_at = _dt(requirement.updated_at) or ""
                requirement = requirement.model_copy(update={"created_at": datetime.fromisoformat(row.created_at)})
            session.flush()
        return requirement

    def get(self, finding_id: UUID) -> VerificationRequirement:
        with self.database.session() as session:
            row = session.get(VerificationRequirementRow, str(finding_id))
            if row is None:
                raise NotFoundError(f"verification requirement not found for finding: {finding_id}")
            return _requirement_from_row(row)

    def list(self) -> list[VerificationRequirement]:
        statement = select(VerificationRequirementRow).order_by(VerificationRequirementRow.created_at)
        with self.database.session() as session:
            return [_requirement_from_row(row) for row in session.scalars(statement).all()]


class PlanRepository:
    _ACTIVE = {
        VerificationPlanStatus.READY.value,
        VerificationPlanStatus.PENDING_APPROVAL.value,
        VerificationPlanStatus.APPROVED.value,
    }

    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, plan: VerificationPlan) -> VerificationPlan:
        plan = _revalidated(VerificationPlan, plan)
        from argus.verification.planning import compute_plan_hash

        if compute_plan_hash(plan) != plan.plan_hash:
            raise SchemaValidationError("verification plan hash does not match its canonical fields")
        now = utc_now()
        try:
            with self.database.session() as session:
                same = session.scalar(
                    select(VerificationPlanRow).where(
                        VerificationPlanRow.finding_id == str(plan.finding_id),
                        VerificationPlanRow.plan_hash == plan.plan_hash,
                        VerificationPlanRow.status.in_(self._ACTIVE),
                    )
                )
                if same is not None:
                    return _plan_from_row(same)

                active_ids = list(
                    session.scalars(
                        select(VerificationPlanRow.id).where(
                            VerificationPlanRow.finding_id == str(plan.finding_id),
                            VerificationPlanRow.status.in_(self._ACTIVE),
                        )
                    ).all()
                )
                if active_ids:
                    session.execute(
                        update(VerificationPlanRow)
                        .where(VerificationPlanRow.id.in_(active_ids))
                        .values(
                            status=VerificationPlanStatus.SUPERSEDED.value,
                            updated_at=_dt(now),
                        )
                    )
                    session.execute(
                        update(VerificationApprovalRow)
                        .where(
                            VerificationApprovalRow.plan_id.in_(active_ids),
                            VerificationApprovalRow.decision.in_(
                                [
                                    ApprovalDecision.PENDING.value,
                                    ApprovalDecision.APPROVED.value,
                                ]
                            ),
                        )
                        .values(
                            decision=ApprovalDecision.SUPERSEDED.value,
                            reviewer="system",
                            reason="plan hash changed",
                            decided_at=_dt(now),
                        )
                    )
                session.add(
                    VerificationPlanRow(
                        id=str(plan.id),
                        finding_id=str(plan.finding_id),
                        snapshot_id=str(plan.snapshot_id),
                        environment_id=str(plan.environment_id),
                        identity_handles=plan.identity_handles,
                        actions=[item.model_dump(mode="json") for item in plan.actions],
                        request_budget=plan.request_budget.model_dump(mode="json"),
                        expected_observations=[item.model_dump(mode="json") for item in plan.expected_observations],
                        expected_side_effects=[item.model_dump(mode="json") for item in plan.expected_side_effects],
                        rollback_strategy=plan.rollback_strategy.model_dump(mode="json"),
                        health_checks=plan.health_checks,
                        abort_conditions=[item.model_dump(mode="json") for item in plan.abort_conditions],
                        risk_class=plan.risk_class.value,
                        plan_hash=plan.plan_hash,
                        status=plan.status.value,
                        created_at=_dt(plan.created_at) or "",
                        updated_at=_dt(plan.updated_at) or "",
                    )
                )
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification plan could not be created: {plan.id}") from exc
        return plan

    def get(self, plan_id: UUID) -> VerificationPlan:
        with self.database.session() as session:
            row = session.get(VerificationPlanRow, str(plan_id))
            if row is None:
                raise NotFoundError(f"verification plan not found: {plan_id}")
            return _plan_from_row(row)

    def list(self, *, finding_id: UUID | None = None) -> list[VerificationPlan]:
        statement: Select[tuple[VerificationPlanRow]] = select(VerificationPlanRow)
        if finding_id is not None:
            statement = statement.where(VerificationPlanRow.finding_id == str(finding_id))
        statement = statement.order_by(VerificationPlanRow.created_at, VerificationPlanRow.id)
        with self.database.session() as session:
            return [_plan_from_row(row) for row in session.scalars(statement).all()]

    def set_status(self, plan_id: UUID, status: VerificationPlanStatus) -> VerificationPlan:
        now = utc_now()
        with self.database.session() as session:
            changed = cast(
                CursorResult[tuple[object]],
                session.execute(
                    update(VerificationPlanRow)
                    .where(VerificationPlanRow.id == str(plan_id))
                    .values(status=status.value, updated_at=_dt(now))
                ),
            ).rowcount
            if changed != 1:
                raise NotFoundError(f"verification plan not found: {plan_id}")
            row = session.get(VerificationPlanRow, str(plan_id))
            assert row is not None
            return _plan_from_row(row)


class ApprovalRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, approval: Approval) -> Approval:
        approval = _revalidated(Approval, approval)
        try:
            with self.database.session() as session:
                plan = session.get(VerificationPlanRow, str(approval.plan_id))
                if plan is None:
                    raise NotFoundError(f"verification plan not found: {approval.plan_id}")
                if plan.plan_hash != approval.plan_hash or plan.status == VerificationPlanStatus.SUPERSEDED.value:
                    raise ConflictError("verification approval does not match the current plan hash")
                existing = session.scalar(
                    select(VerificationApprovalRow).where(
                        VerificationApprovalRow.plan_id == str(approval.plan_id),
                        VerificationApprovalRow.plan_hash == approval.plan_hash,
                        VerificationApprovalRow.decision == ApprovalDecision.PENDING.value,
                    )
                )
                if existing is not None:
                    return _approval_from_row(existing)
                session.add(
                    VerificationApprovalRow(
                        id=str(approval.id),
                        plan_id=str(approval.plan_id),
                        plan_hash=approval.plan_hash,
                        decision=approval.decision.value,
                        reviewer=approval.reviewer,
                        reason=approval.reason,
                        created_at=_dt(approval.created_at) or "",
                        decided_at=_dt(approval.decided_at),
                        expires_at=_dt(approval.expires_at),
                    )
                )
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification approval could not be created: {approval.id}") from exc
        return approval

    def get(self, approval_id: UUID) -> Approval:
        with self.database.session() as session:
            row = session.get(VerificationApprovalRow, str(approval_id))
            if row is None:
                raise NotFoundError(f"verification approval not found: {approval_id}")
            return _approval_from_row(row)

    def list(self, *, plan_id: UUID | None = None) -> list[Approval]:
        statement: Select[tuple[VerificationApprovalRow]] = select(VerificationApprovalRow)
        if plan_id is not None:
            statement = statement.where(VerificationApprovalRow.plan_id == str(plan_id))
        statement = statement.order_by(VerificationApprovalRow.created_at, VerificationApprovalRow.id)
        with self.database.session() as session:
            return [_approval_from_row(row) for row in session.scalars(statement).all()]

    def decide(self, approval: Approval) -> Approval:
        approval = _revalidated(Approval, approval)
        statement = (
            update(VerificationApprovalRow)
            .where(
                VerificationApprovalRow.id == str(approval.id),
                VerificationApprovalRow.decision == ApprovalDecision.PENDING.value,
            )
            .values(
                decision=approval.decision.value,
                reviewer=approval.reviewer,
                reason=approval.reason,
                decided_at=_dt(approval.decided_at),
                expires_at=_dt(approval.expires_at),
            )
        )
        with self.database.session() as session:
            current = session.get(VerificationApprovalRow, str(approval.id))
            if current is None:
                raise NotFoundError(f"verification approval not found: {approval.id}")
            plan = session.get(VerificationPlanRow, current.plan_id)
            if (
                plan is None
                or plan.plan_hash != approval.plan_hash
                or plan.status == VerificationPlanStatus.SUPERSEDED.value
            ):
                raise ConflictError("verification approval does not match the current plan hash")
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                raise ConflictError(
                    f"verification approval is no longer pending: {approval.id} decision={current.decision}"
                )
        return approval


class VerificationAttemptRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, attempt: VerificationAttempt) -> VerificationAttempt:
        attempt = _revalidated(VerificationAttempt, attempt)
        row = VerificationAttemptRow(
            id=str(attempt.id),
            plan_id=str(attempt.plan_id),
            plan_hash=attempt.plan_hash,
            finding_id=str(attempt.finding_id),
            snapshot_id=str(attempt.snapshot_id),
            environment_id=str(attempt.environment_id),
            conclusion=attempt.conclusion.value,
            request_count=attempt.request_count,
            response_bytes=attempt.response_bytes,
            health_before=attempt.health_before,
            health_after=attempt.health_after,
            abort_reason=attempt.abort_reason,
            started_at=_dt(attempt.started_at) or "",
            finished_at=_dt(attempt.finished_at),
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification attempt could not be created: {attempt.id}") from exc
        return attempt

    def get(self, attempt_id: UUID) -> VerificationAttempt:
        with self.database.session() as session:
            row = session.get(VerificationAttemptRow, str(attempt_id))
            if row is None:
                raise NotFoundError(f"verification attempt not found: {attempt_id}")
            return _attempt_from_row(row)

    def list(self, *, plan_id: UUID | None = None) -> list[VerificationAttempt]:
        statement: Select[tuple[VerificationAttemptRow]] = select(VerificationAttemptRow)
        if plan_id is not None:
            statement = statement.where(VerificationAttemptRow.plan_id == str(plan_id))
        statement = statement.order_by(VerificationAttemptRow.started_at.desc(), VerificationAttemptRow.id)
        with self.database.session() as session:
            return [_attempt_from_row(row) for row in session.scalars(statement).all()]

    def reserve_request(self, attempt_id: UUID, *, max_requests: int) -> VerificationAttempt:
        statement = (
            update(VerificationAttemptRow)
            .where(
                VerificationAttemptRow.id == str(attempt_id),
                VerificationAttemptRow.conclusion == VerificationConclusion.RUNNING.value,
                VerificationAttemptRow.request_count < max_requests,
            )
            .values(request_count=VerificationAttemptRow.request_count + 1)
        )
        with self.database.session() as session:
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                raise ConflictError("verification request budget exhausted or attempt is terminal")
        return self.get(attempt_id)

    def add_response_bytes(self, attempt_id: UUID, *, amount: int, max_response_bytes: int) -> VerificationAttempt:
        if amount < 0:
            raise ValueError("response byte amount must be non-negative")
        statement = (
            update(VerificationAttemptRow)
            .where(
                VerificationAttemptRow.id == str(attempt_id),
                VerificationAttemptRow.conclusion == VerificationConclusion.RUNNING.value,
                VerificationAttemptRow.response_bytes + amount <= max_response_bytes,
            )
            .values(response_bytes=VerificationAttemptRow.response_bytes + amount)
        )
        with self.database.session() as session:
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                raise ConflictError("verification response byte budget exhausted")
        return self.get(attempt_id)

    def update(self, attempt: VerificationAttempt) -> VerificationAttempt:
        attempt = _revalidated(VerificationAttempt, attempt)
        statement = (
            update(VerificationAttemptRow)
            .where(VerificationAttemptRow.id == str(attempt.id))
            .values(
                conclusion=attempt.conclusion.value,
                request_count=attempt.request_count,
                response_bytes=attempt.response_bytes,
                health_before=attempt.health_before,
                health_after=attempt.health_after,
                abort_reason=attempt.abort_reason,
                finished_at=_dt(attempt.finished_at),
            )
        )
        with self.database.session() as session:
            changed = cast(CursorResult[tuple[object]], session.execute(statement)).rowcount
            if changed != 1:
                raise NotFoundError(f"verification attempt not found: {attempt.id}")
        return attempt


class VerificationEvidenceRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create(self, evidence: VerificationEvidence) -> VerificationEvidence:
        evidence = _revalidated(VerificationEvidence, evidence)
        row = VerificationEvidenceRow(
            id=str(evidence.id),
            attempt_id=str(evidence.attempt_id),
            plan_id=str(evidence.plan_id),
            action_id=evidence.action_id,
            identity_handle=evidence.identity_handle,
            request_summary=evidence.request_summary,
            response_status=evidence.response_status,
            response_headers=evidence.response_headers,
            body_hash=evidence.body_hash,
            body_excerpt=evidence.body_excerpt,
            observation=evidence.observation,
            predicate_result=evidence.predicate_result.value,
            conclusion=evidence.conclusion.value,
            artifact_hash=evidence.artifact_hash,
            artifact_size_bytes=evidence.artifact_size_bytes,
            created_at=_dt(evidence.created_at) or "",
        )
        try:
            with self.database.session() as session:
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise ConflictError(f"verification evidence could not be created: {evidence.id}") from exc
        return evidence

    def list(self, *, attempt_id: UUID | None = None) -> list[VerificationEvidence]:
        statement: Select[tuple[VerificationEvidenceRow]] = select(VerificationEvidenceRow)
        if attempt_id is not None:
            statement = statement.where(VerificationEvidenceRow.attempt_id == str(attempt_id))
        statement = statement.order_by(VerificationEvidenceRow.created_at, VerificationEvidenceRow.id)
        with self.database.session() as session:
            return [_evidence_from_row(row) for row in session.scalars(statement).all()]


class VerificationRepositories:
    def __init__(self, database: Database) -> None:
        self.environments = EnvironmentRepository(database)
        self.identities = IdentityRepository(database)
        self.requirements = RequirementRepository(database)
        self.plans = PlanRepository(database)
        self.approvals = ApprovalRepository(database)
        self.attempts = VerificationAttemptRepository(database)
        self.evidence = VerificationEvidenceRepository(database)
