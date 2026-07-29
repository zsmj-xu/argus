"""Policy-enforcing M9 broker and authorization differential verifier."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import JsonValue

from argus.artifacts.store import ArtifactStore
from argus.control.events import EventService
from argus.control.repositories import Repositories
from argus.domain.models import utc_now
from argus.verification.evidence import bounded_excerpt, redact_headers
from argus.verification.executors.http_readonly import (
    ReadonlyHttpExecutor,
    ReadonlyResponse,
    ResponseTooLarge,
)
from argus.verification.health import health_result
from argus.verification.http_policy import HttpRequestPolicy, render_resource_path
from argus.verification.identity_broker import IdentityBroker
from argus.verification.models import (
    ApprovalDecision,
    EnvironmentKind,
    PredicateResult,
    RiskClass,
    VerificationAction,
    VerificationAttempt,
    VerificationConclusion,
    VerificationEvidence,
    VerificationPlan,
    VerificationPlanStatus,
)
from argus.verification.secrets import SecretProvider


class VerificationExecutionDenied(PermissionError):
    pass


@dataclass(frozen=True)
class ActionResult:
    action: VerificationAction
    response: ReadonlyResponse
    url: str


@dataclass(frozen=True)
class RequestResult:
    response: ReadonlyResponse
    url: str


class VerificationBroker:
    """The only component allowed to turn an approved M9 plan into network I/O."""

    def __init__(
        self,
        repositories: Repositories,
        artifact_store: ArtifactStore,
        secret_provider: SecretProvider,
        *,
        http_policy: HttpRequestPolicy | None = None,
        executor: ReadonlyHttpExecutor | None = None,
    ) -> None:
        self.repositories = repositories
        self.artifact_store = artifact_store
        self.identity_broker = IdentityBroker(secret_provider)
        self.http_policy = http_policy or HttpRequestPolicy()
        self.executor = executor or ReadonlyHttpExecutor()

    def run(self, plan_id: UUID, *, test_data: dict[str, str]) -> VerificationAttempt:
        plan = self._authorized_plan(plan_id)
        attempt = self.repositories.verification.attempts.create(
            VerificationAttempt(
                plan_id=plan.id,
                plan_hash=plan.plan_hash,
                finding_id=plan.finding_id,
                snapshot_id=plan.snapshot_id,
                environment_id=plan.environment_id,
            )
        )
        results: list[ActionResult] = []
        try:
            before = self._run_health_checks(attempt, plan)
            attempt = self.repositories.verification.attempts.get(attempt.id).model_copy(
                update={"health_before": before}
            )
            self.repositories.verification.attempts.update(attempt)
            if any(not bool(item["healthy"]) for item in before):
                raise VerificationExecutionDenied("preflight health check failed")
            for index, action in enumerate(plan.actions, start=1):
                values = {key: test_data[key] for key in action.test_data_refs if key in test_data}
                if len(values) != len(action.test_data_refs):
                    raise VerificationExecutionDenied("approved action is missing explicit test data")
                path = render_resource_path(action.resource_path, values)
                request_result = self._request(
                    attempt.id,
                    plan,
                    path,
                    method=action.method,
                    action=action,
                )
                results.append(
                    ActionResult(
                        action,
                        request_result.response,
                        request_result.url,
                    )
                )
                if index % 5 == 0:
                    periodic = self._run_health_checks(attempt, plan)
                    if any(not bool(item["healthy"]) for item in periodic):
                        raise VerificationExecutionDenied("periodic health check failed")
            conclusion = self._authorization_conclusion(results)
            after = self._run_health_checks(attempt, plan)
            if any(not bool(item["healthy"]) for item in after):
                conclusion = VerificationConclusion.ABORTED
            self._persist_evidence(attempt.id, plan, results, conclusion)
            latest = self.repositories.verification.attempts.get(attempt.id)
            finished = latest.model_copy(
                update={
                    "conclusion": conclusion,
                    "health_after": after,
                    "abort_reason": (
                        "post-verification health check failed"
                        if conclusion is VerificationConclusion.ABORTED
                        else None
                    ),
                    "finished_at": utc_now(),
                }
            )
            persisted = self.repositories.verification.attempts.update(finished)
        except Exception as exc:
            latest = self.repositories.verification.attempts.get(attempt.id)
            if latest.conclusion is VerificationConclusion.RUNNING:
                latest = latest.model_copy(
                    update={
                        "conclusion": VerificationConclusion.ABORTED,
                        "abort_reason": type(exc).__name__,
                        "finished_at": utc_now(),
                    }
                )
                self.repositories.verification.attempts.update(latest)
            self._event("verification.attempt.aborted", latest, {"reason": type(exc).__name__})
            raise
        self._event(
            "verification.attempt.completed",
            persisted,
            {"conclusion": persisted.conclusion.value},
        )
        return persisted

    def _authorized_plan(self, plan_id: UUID) -> VerificationPlan:
        plan = self.repositories.verification.plans.get(plan_id)
        if plan.status is not VerificationPlanStatus.APPROVED:
            raise VerificationExecutionDenied("verification plan is not approved")
        if plan.risk_class is not RiskClass.R1_SAFE_READ:
            raise VerificationExecutionDenied("M9 only executes R1_SAFE_READ plans")
        if any(action.method not in ReadonlyHttpExecutor.SAFE_METHODS for action in plan.actions):
            raise VerificationExecutionDenied("plan contains a non-safe HTTP method")
        approvals = self.repositories.verification.approvals.list(plan_id=plan.id)
        now = utc_now()
        current = next(
            (
                approval
                for approval in reversed(approvals)
                if approval.decision is ApprovalDecision.APPROVED
                and approval.plan_hash == plan.plan_hash
                and (approval.expires_at is None or approval.expires_at > now)
            ),
            None,
        )
        if current is None:
            raise VerificationExecutionDenied("no current, unexpired approval matches the plan hash")
        environment = self.repositories.verification.environments.get(plan.environment_id)
        finding = self.repositories.findings.get(plan.finding_id)
        scan = self.repositories.scans.get(finding.scan_id)
        if (
            environment.kind is not EnvironmentKind.EXISTING_URL
            or not environment.test_only
            or environment.project_id != scan.project_id
            or finding.snapshot_id != plan.snapshot_id
            or scan.snapshot_id != plan.snapshot_id
            or (
                environment.source_snapshot_binding is not None
                and environment.source_snapshot_binding != plan.snapshot_id
            )
        ):
            raise VerificationExecutionDenied("plan bindings do not match a test-only existing_url environment")
        identities = self.repositories.verification.identities.list(project_id=environment.project_id)
        available = {item.handle for item in identities if item.enabled}
        if not set(plan.identity_handles) <= available:
            raise VerificationExecutionDenied("plan identity handles are unavailable")
        return plan

    def _request(
        self,
        attempt_id: UUID,
        plan: VerificationPlan,
        resource_path: str,
        *,
        method: str,
        action: VerificationAction | None,
    ) -> RequestResult:
        plan = self._authorized_plan(plan.id)
        attempt = self.repositories.verification.attempts.get(attempt_id)
        if attempt.abort_reason is not None or attempt.conclusion is not VerificationConclusion.RUNNING:
            raise VerificationExecutionDenied("attempt has an active abort condition")
        if method not in ReadonlyHttpExecutor.SAFE_METHODS:
            raise VerificationExecutionDenied("broker rejected a non-safe HTTP method")
        current_resource = resource_path
        previous_url: str | None = None
        for redirect_count in range(4):
            plan = self._authorized_plan(plan.id)
            environment = self.repositories.verification.environments.get(plan.environment_id)
            identity_headers: tuple[tuple[str, str], ...] = ()
            if action is not None:
                if action.identity_handle not in plan.identity_handles:
                    raise VerificationExecutionDenied("identity handle is outside the approved plan")
                identity = next(
                    (
                        item
                        for item in self.repositories.verification.identities.list(project_id=environment.project_id)
                        if item.handle == action.identity_handle
                    ),
                    None,
                )
                if identity is None:
                    raise VerificationExecutionDenied("approved identity is unavailable")
                identity_headers = self.identity_broker.bind(identity).headers
            latest = self.repositories.verification.attempts.reserve_request(
                attempt_id, max_requests=plan.request_budget.max_requests
            )
            target = self.http_policy.approve(
                environment,
                current_resource,
                previous_url=previous_url,
            )
            current_url = target.url
            remaining = plan.request_budget.max_response_bytes - latest.response_bytes
            try:
                response = self.executor.request(
                    method=method,
                    url=current_url,
                    host=target.host,
                    pinned_ip=target.pinned_ip,
                    headers=identity_headers,
                    timeout_seconds=plan.request_budget.timeout_seconds,
                    max_bytes=remaining,
                )
            except ResponseTooLarge:
                raise
            self.repositories.verification.attempts.add_response_bytes(
                attempt_id,
                amount=len(response.body),
                max_response_bytes=plan.request_budget.max_response_bytes,
            )
            if response.status >= 500:
                raise VerificationExecutionDenied("server error triggered an abort condition")
            location = next(
                (value for name, value in response.headers if name.lower() == "location"),
                None,
            )
            if response.status not in {301, 302, 303, 307, 308} or location is None:
                return RequestResult(response=response, url=current_url)
            if redirect_count == 3:
                raise VerificationExecutionDenied("redirect budget exceeded")
            current_resource = location
            previous_url = current_url
        raise AssertionError("unreachable")

    def _run_health_checks(self, attempt: VerificationAttempt, plan: VerificationPlan) -> list[dict[str, JsonValue]]:
        environment = self.repositories.verification.environments.get(plan.environment_id)
        selected = [
            item for item in environment.health_checks if not plan.health_checks or item.id in plan.health_checks
        ]
        return [
            health_result(
                spec,
                self._request(
                    attempt.id,
                    plan,
                    spec.path,
                    method=spec.method,
                    action=None,
                ).response.status,
            )
            for spec in selected
        ]

    @staticmethod
    def _authorization_conclusion(results: list[ActionResult]) -> VerificationConclusion:
        by_handle = {result.action.identity_handle: result.response for result in results}
        owner = by_handle.get("owner")
        peer = by_handle.get("peer")
        if owner is None or peer is None or owner.status < 200 or owner.status >= 300:
            return VerificationConclusion.INCONCLUSIVE
        if peer.status in {401, 403, 404}:
            return VerificationConclusion.REJECTED
        if 200 <= peer.status < 300 and hashlib.sha256(owner.body).digest() == hashlib.sha256(peer.body).digest():
            return VerificationConclusion.CONFIRMED
        return VerificationConclusion.INCONCLUSIVE

    def _persist_evidence(
        self,
        attempt_id: UUID,
        plan: VerificationPlan,
        results: list[ActionResult],
        conclusion: VerificationConclusion,
    ) -> None:
        for result in results:
            response = result.response
            body_hash = hashlib.sha256(response.body).hexdigest()
            predicate = (
                PredicateResult.PASS
                if conclusion in {VerificationConclusion.CONFIRMED, VerificationConclusion.REJECTED}
                else PredicateResult.INCONCLUSIVE
            )
            payload: dict[str, JsonValue] = {
                "plan_id": str(plan.id),
                "plan_hash": plan.plan_hash,
                "action_id": result.action.id,
                "identity_handle": result.action.identity_handle,
                "request": {
                    "method": result.action.method,
                    "path": urlsplit(result.url).path,
                },
                "response": {
                    "status": response.status,
                    "headers": redact_headers(response.headers),
                    "body_hash": body_hash,
                    "body_excerpt": bounded_excerpt(response.body),
                },
                "predicate_result": predicate.value,
                "conclusion": conclusion.value,
            }
            blob = self.artifact_store.put_json(cast(JsonValue, payload))
            self.repositories.verification.evidence.create(
                VerificationEvidence(
                    attempt_id=attempt_id,
                    plan_id=plan.id,
                    action_id=result.action.id,
                    identity_handle=result.action.identity_handle,
                    request_summary=cast(dict[str, JsonValue], payload["request"]),
                    response_status=response.status,
                    response_headers=cast(dict[str, JsonValue], payload["response"])["headers"],  # type: ignore[arg-type]
                    body_hash=body_hash,
                    body_excerpt=bounded_excerpt(response.body),
                    observation={"comparison": "authorization_differential_read"},
                    predicate_result=predicate,
                    conclusion=conclusion,
                    artifact_hash=blob.content_hash,
                    artifact_size_bytes=blob.size_bytes,
                )
            )

    def _event(
        self,
        event_type: str,
        attempt: VerificationAttempt,
        extra: dict[str, JsonValue],
    ) -> None:
        finding = self.repositories.findings.get(attempt.finding_id)
        scan = self.repositories.scans.get(finding.scan_id)
        EventService(self.repositories.events).append(
            event_type,
            project_id=scan.project_id,
            scan_id=scan.id,
            finding_id=finding.id,
            payload={
                "attempt_id": str(attempt.id),
                "plan_id": str(attempt.plan_id),
                "plan_hash": attempt.plan_hash,
                **extra,
            },
        )
