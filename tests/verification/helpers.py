from __future__ import annotations

from pathlib import Path
from uuid import UUID

from argus.control.db import Database, control_db_path
from argus.verification.models import (
    AbortCondition,
    EnvironmentKind,
    EnvironmentProfile,
    ExpectedObservation,
    IdentityProfile,
    RequestBudget,
    ResetCapability,
    RiskClass,
    RollbackStrategy,
    ScopeRule,
    VerificationAction,
)
from argus.verification.persistence import VerificationRepositories
from argus.verification.planning import PlanDraft

from tests.control_plane.test_service import _seed


def seed_verification(tmp_path: Path):
    project, scan, task, artifact = _seed(tmp_path)
    database = Database(control_db_path(tmp_path / "runs"))
    repositories = VerificationRepositories(database)
    environment = repositories.environments.create(
        EnvironmentProfile(
            project_id=project.id,
            kind=EnvironmentKind.EXISTING_URL,
            target_base_url="https://test.example.local",
            scope_allowlist=[
                ScopeRule(
                    scheme="https",
                    host="test.example.local",
                    path_prefix="/api/",
                )
            ],
            capabilities=["existing_url", "readonly_http"],
            reset_capability=ResetCapability.NONE,
            source_snapshot_binding=scan.snapshot_id,
            test_only=True,
        )
    )
    identities = [
        repositories.identities.create(
            IdentityProfile(
                project_id=project.id,
                handle="owner",
                role="owner",
                tenant="tenant-a",
                credential_ref="env:ARGUS_TEST_OWNER_TOKEN",
            )
        ),
        repositories.identities.create(
            IdentityProfile(
                project_id=project.id,
                handle="peer",
                role="peer",
                tenant="tenant-a",
                credential_ref="env:ARGUS_TEST_PEER_TOKEN",
            )
        ),
    ]
    return database, repositories, project, scan, task, artifact, environment, identities


def plan_draft(scan, environment, identities, *, finding_id: UUID) -> PlanDraft:
    return PlanDraft(
        finding_id=finding_id,
        snapshot_id=scan.snapshot_id,
        environment=environment,
        identities=identities,
        actions=[
            VerificationAction(
                id="owner_read",
                method="GET",
                resource_path="/api/orders/{resource_id}",
                identity_handle="owner",
                test_data_refs=["resource_id"],
                observation_ids=["owner_result"],
            ),
            VerificationAction(
                id="peer_read",
                method="GET",
                resource_path="/api/orders/{resource_id}",
                identity_handle="peer",
                test_data_refs=["resource_id"],
                observation_ids=["peer_result"],
            ),
        ],
        request_budget=RequestBudget(
            max_requests=2,
            max_response_bytes=128_000,
            timeout_seconds=10,
        ),
        expected_observations=[
            ExpectedObservation(
                id="owner_result",
                description="Owner can read the fixture resource.",
                predicate="status in [200]",
            ),
            ExpectedObservation(
                id="peer_result",
                description="Peer cannot read the owner's fixture resource.",
                predicate="status in [401,403,404]",
            ),
        ],
        expected_side_effects=[],
        rollback_strategy=RollbackStrategy(mode=ResetCapability.NONE),
        health_checks=[],
        abort_conditions=[
            AbortCondition(
                id="unexpected_server_error",
                description="Abort on any 5xx response.",
            )
        ],
        risk_class=RiskClass.R1_SAFE_READ,
    )
