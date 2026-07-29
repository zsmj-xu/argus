"""Strict M8 verification domain models.

The objects in this module are declarative only. They cannot execute an
action, open a socket, launch a process, or resolve a credential.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
import re
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from argus.domain.models import DomainModel, Sha256, utc_now

NonEmptyStr = Annotated[str, Field(min_length=1)]
JsonObject = dict[str, JsonValue]
_HANDLE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_ENV_REFERENCE = re.compile(r"^env:[A-Za-z_][A-Za-z0-9_]*$")
_KEYCHAIN_REFERENCE = re.compile(r"^keychain:[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$")
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class EnvironmentKind(str, Enum):
    EXISTING_URL = "existing_url"
    DOCKER_COMPOSE = "docker_compose"
    CUSTOM = "custom"


class ResetCapability(str, Enum):
    NONE = "none"
    MANUAL = "manual"
    AUTOMATED = "automated"


class RiskClass(str, Enum):
    R0_STATIC = "R0_STATIC"
    R1_SAFE_READ = "R1_SAFE_READ"
    R2_REVERSIBLE_WRITE = "R2_REVERSIBLE_WRITE"
    R3_HIGH_IMPACT = "R3_HIGH_IMPACT"
    R4_PROHIBITED = "R4_PROHIBITED"


class VerificationPlanStatus(str, Enum):
    READY = "ready"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class ApprovalDecision(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"


class PolicyDecision(str, Enum):
    ALLOW_AUTOMATIC = "allow_automatic"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class VerificationConclusion(str, Enum):
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ABORTED = "aborted"


class PredicateResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class ScopeRule(DomainModel):
    scheme: str
    host: NonEmptyStr
    port: int | None = Field(default=None, ge=1, le=65535)
    path_prefix: str = "/"

    @field_validator("scheme")
    @classmethod
    def validate_scheme(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"http", "https"}:
            raise ValueError("scope scheme must be http or https")
        return normalized

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        normalized = value.strip().lower().rstrip(".")
        if not normalized or any(character.isspace() for character in normalized):
            raise ValueError("scope host must be a non-empty hostname")
        if any(character in normalized for character in "/?#@"):
            raise ValueError("scope host must not contain URL syntax")
        return normalized

    @field_validator("path_prefix")
    @classmethod
    def validate_path_prefix(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value:
            raise ValueError("scope path_prefix must be an absolute path without query or fragment")
        return value


class HealthCheckSpec(DomainModel):
    id: NonEmptyStr
    method: str = "GET"
    path: NonEmptyStr
    expected_statuses: list[int] = Field(default_factory=lambda: [200], min_length=1)

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in _SAFE_METHODS:
            raise ValueError("health check method must be GET, HEAD, or OPTIONS")
        return normalized

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value:
            raise ValueError("health check path must be relative to the environment base URL")
        return value

    @field_validator("expected_statuses")
    @classmethod
    def validate_statuses(cls, values: list[int]) -> list[int]:
        if any(value < 100 or value > 599 for value in values):
            raise ValueError("health check status must be an HTTP status code")
        if len(values) != len(set(values)):
            raise ValueError("health check statuses must not contain duplicates")
        return values


class EnvironmentProfile(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    kind: EnvironmentKind
    target_base_url: str | None = None
    scope_allowlist: list[ScopeRule] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    health_checks: list[HealthCheckSpec] = Field(default_factory=list)
    reset_capability: ResetCapability = ResetCapability.NONE
    source_snapshot_binding: UUID | None = None
    test_only: bool = False
    allow_private_addresses: bool = False
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("target_base_url")
    @classmethod
    def validate_target_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("target_base_url must be an HTTP(S) origin/path without credentials, query, or fragment")
        return value.rstrip("/")

    @field_validator("capabilities")
    @classmethod
    def unique_capabilities(cls, values: list[str]) -> list[str]:
        if any(not value for value in values) or len(values) != len(set(values)):
            raise ValueError("environment capabilities must be non-empty and unique")
        return values

    @model_validator(mode="after")
    def validate_existing_url(self) -> EnvironmentProfile:
        if self.kind is EnvironmentKind.EXISTING_URL and (self.target_base_url is None or not self.scope_allowlist):
            raise ValueError("existing_url environments require target_base_url and scope_allowlist")
        if self.kind is EnvironmentKind.EXISTING_URL:
            assert self.target_base_url is not None
            parsed = urlsplit(self.target_base_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if not any(
                rule.scheme == parsed.scheme
                and rule.host == parsed.hostname
                and (rule.port is None or rule.port == port)
                for rule in self.scope_allowlist
            ):
                raise ValueError("target_base_url must be covered by scope_allowlist")
        if self.allow_private_addresses and not self.test_only:
            raise ValueError("private addresses may only be enabled for a test-only environment")
        return self


class IdentityProfile(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    project_id: UUID
    handle: str
    role: NonEmptyStr
    tenant: str | None = None
    attributes: JsonObject = Field(default_factory=dict)
    credential_ref: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("handle")
    @classmethod
    def validate_handle(cls, value: str) -> str:
        if _HANDLE.fullmatch(value) is None:
            raise ValueError("identity handle must be a stable lowercase identifier")
        return value

    @field_validator("credential_ref")
    @classmethod
    def validate_credential_ref(cls, value: str) -> str:
        if _ENV_REFERENCE.fullmatch(value) is None and _KEYCHAIN_REFERENCE.fullmatch(value) is None:
            raise ValueError("credential_ref must be an env: or keychain: reference")
        return value


class VerificationRequirement(DomainModel):
    finding_id: UUID
    required_environment_capabilities: list[str] = Field(default_factory=list)
    required_identity_roles: list[str] = Field(default_factory=list)
    required_test_data: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RequestBudget(DomainModel):
    max_requests: int = Field(ge=0, le=100)
    max_response_bytes: int = Field(ge=0, le=100 * 1024 * 1024)
    timeout_seconds: int = Field(ge=1, le=300)


class VerificationAction(DomainModel):
    id: str
    method: str
    resource_path: NonEmptyStr
    identity_handle: str
    test_data_refs: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)

    @field_validator("id", "identity_handle")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _HANDLE.fullmatch(value) is None:
            raise ValueError("action IDs and identity handles must be stable lowercase identifiers")
        return value

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in _SAFE_METHODS | _WRITE_METHODS:
            raise ValueError("verification action method is unsupported")
        return normalized

    @field_validator("resource_path")
    @classmethod
    def validate_resource_path(cls, value: str) -> str:
        if not value.startswith("/") or "://" in value:
            raise ValueError("resource_path must be relative to the approved environment")
        return value


class ExpectedObservation(DomainModel):
    id: str
    description: NonEmptyStr
    predicate: NonEmptyStr

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _HANDLE.fullmatch(value) is None:
            raise ValueError("observation ID must be a stable lowercase identifier")
        return value


class ExpectedSideEffect(DomainModel):
    description: NonEmptyStr
    reversible: bool


class RollbackStrategy(DomainModel):
    mode: ResetCapability
    instructions: list[str] = Field(default_factory=list)


class AbortCondition(DomainModel):
    id: str
    description: NonEmptyStr

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _HANDLE.fullmatch(value) is None:
            raise ValueError("abort condition ID must be a stable lowercase identifier")
        return value


class VerificationPlan(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    snapshot_id: UUID
    environment_id: UUID
    identity_handles: list[str] = Field(min_length=1)
    actions: list[VerificationAction] = Field(min_length=1)
    request_budget: RequestBudget
    expected_observations: list[ExpectedObservation] = Field(min_length=1)
    expected_side_effects: list[ExpectedSideEffect] = Field(default_factory=list)
    rollback_strategy: RollbackStrategy
    health_checks: list[str] = Field(default_factory=list)
    abort_conditions: list[AbortCondition] = Field(min_length=1)
    risk_class: RiskClass
    plan_hash: Sha256
    status: VerificationPlanStatus = VerificationPlanStatus.READY
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_cross_references(self) -> VerificationPlan:
        if len(self.identity_handles) != len(set(self.identity_handles)):
            raise ValueError("identity_handles must not contain duplicates")
        if any(action.identity_handle not in self.identity_handles for action in self.actions):
            raise ValueError("every action identity_handle must be declared by the plan")
        observation_ids = {item.id for item in self.expected_observations}
        if len(observation_ids) != len(self.expected_observations):
            raise ValueError("expected observation IDs must be unique")
        if any(
            observation_id not in observation_ids
            for action in self.actions
            for observation_id in action.observation_ids
        ):
            raise ValueError("actions must reference declared observations")
        methods = {action.method for action in self.actions}
        if self.risk_class is RiskClass.R1_SAFE_READ and not methods <= _SAFE_METHODS:
            raise ValueError("R1_SAFE_READ plans may only declare safe read methods")
        if self.risk_class is RiskClass.R2_REVERSIBLE_WRITE and not self.expected_side_effects:
            raise ValueError("R2_REVERSIBLE_WRITE plans must declare expected side effects")
        if self.risk_class is RiskClass.R0_STATIC and self.request_budget.max_requests != 0:
            raise ValueError("R0_STATIC plans cannot budget network requests")
        return self


class Approval(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    plan_hash: Sha256
    decision: ApprovalDecision = ApprovalDecision.PENDING
    reviewer: str | None = None
    reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    decided_at: datetime | None = None
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_decision_metadata(self) -> Approval:
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("approval expiry must be after creation")
        if self.decision is ApprovalDecision.PENDING:
            if self.reviewer is not None or self.reason is not None or self.decided_at is not None:
                raise ValueError("pending approvals cannot contain decision metadata")
        elif not self.reviewer or not self.reason or self.decided_at is None:
            raise ValueError("decided approvals require reviewer, reason, and decided_at")
        return self


class PolicyResult(DomainModel):
    decision: PolicyDecision
    reason: NonEmptyStr


class VerificationAttempt(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    plan_id: UUID
    plan_hash: Sha256
    finding_id: UUID
    snapshot_id: UUID
    environment_id: UUID
    conclusion: VerificationConclusion = VerificationConclusion.RUNNING
    request_count: int = Field(default=0, ge=0)
    response_bytes: int = Field(default=0, ge=0)
    health_before: list[JsonObject] | None = None
    health_after: list[JsonObject] | None = None
    abort_reason: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> VerificationAttempt:
        terminal = self.conclusion is not VerificationConclusion.RUNNING
        if terminal != (self.finished_at is not None):
            raise ValueError("terminal attempts require finished_at; running attempts must omit it")
        if self.conclusion is VerificationConclusion.ABORTED and not self.abort_reason:
            raise ValueError("aborted attempts require abort_reason")
        return self


class VerificationEvidence(DomainModel):
    id: UUID = Field(default_factory=uuid4)
    attempt_id: UUID
    plan_id: UUID
    action_id: str
    identity_handle: str
    request_summary: JsonObject
    response_status: int = Field(ge=100, le=599)
    response_headers: JsonObject
    body_hash: Sha256
    body_excerpt: str
    observation: JsonObject
    predicate_result: PredicateResult
    conclusion: VerificationConclusion
    artifact_hash: Sha256
    artifact_size_bytes: int = Field(ge=0)
    created_at: datetime = Field(default_factory=utc_now)
