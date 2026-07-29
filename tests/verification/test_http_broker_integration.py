from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import timedelta
import json
from pathlib import Path
import threading
from typing import cast
from uuid import UUID

import pytest

from argus.artifacts.store import ArtifactStore
from argus.control.repositories import Repositories
from argus.control_plane.service import ControlPlaneService
from argus.verification.approvals import ApprovalService
from argus.verification.broker import VerificationBroker, VerificationExecutionDenied
from argus.verification.http_policy import HttpRequestPolicy
from argus.verification.models import (
    Approval,
    ApprovalDecision,
    EnvironmentProfile,
    ScopeRule,
    VerificationConclusion,
    VerificationPlanStatus,
)
from argus.verification.planning import VerificationPlanCompiler
from argus.verification.policy import VerificationPolicyConfig
from argus.verification.requirements import RequirementResolver, VerifierDeclaration
from argus.verification.secrets import EnvironmentSecretProvider

from .helpers import plan_draft, seed_verification


class _VulnerableHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path != "/api/orders/fixture-1":
            self.send_error(404)
            return
        if self.headers.get("Authorization") not in {
            "Bearer owner-secret",
            "Bearer peer-secret",
        }:
            self.send_error(401)
            return
        body = json.dumps(
            {
                "id": "fixture-1",
                "owner_id": "owner",
                "shipping_address": "test-only",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=must-not-persist")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _NoNetworkResolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, host: str, port: int) -> list[str]:
        self.calls += 1
        raise AssertionError("DNS must not run")


def _persist_plan(database, repositories, scan, environment, identities):
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
    plan = VerificationPlanCompiler().compile(
        requirement,
        plan_draft(scan, environment, identities, finding_id=finding.id),
    )
    return finding, repositories.plans.create(plan)


def test_unapproved_plan_causes_zero_dns_and_zero_network(tmp_path: Path) -> None:
    database, verification, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        _finding, plan = _persist_plan(database, verification, scan, environment, identities)
        resolver = _NoNetworkResolver()
        broker = VerificationBroker(
            Repositories(database),
            ArtifactStore(tmp_path / "runs"),
            EnvironmentSecretProvider({}),
            http_policy=HttpRequestPolicy(resolver),
        )
        with pytest.raises(VerificationExecutionDenied, match="not approved"):
            broker.run(plan.id, test_data={"resource_id": "fixture-1"})
        assert resolver.calls == 0
        assert verification.attempts.list(plan_id=plan.id) == []
    finally:
        database.close()


def test_expired_hash_bound_approval_causes_zero_dns(tmp_path: Path) -> None:
    from argus.domain.models import utc_now

    database, verification, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        _finding, plan = _persist_plan(database, verification, scan, environment, identities)
        now = utc_now()
        verification.approvals.create(
            Approval(
                plan_id=plan.id,
                plan_hash=plan.plan_hash,
                decision=ApprovalDecision.APPROVED,
                reviewer="expired-reviewer",
                reason="Expired fixture approval.",
                created_at=now - timedelta(hours=2),
                decided_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            )
        )
        verification.plans.set_status(plan.id, VerificationPlanStatus.APPROVED)
        resolver = _NoNetworkResolver()
        broker = VerificationBroker(
            Repositories(database),
            ArtifactStore(tmp_path / "runs"),
            EnvironmentSecretProvider({}),
            http_policy=HttpRequestPolicy(resolver),
        )
        with pytest.raises(VerificationExecutionDenied, match="unexpired approval"):
            broker.run(plan.id, test_data={"resource_id": "fixture-1"})
        assert resolver.calls == 0
    finally:
        database.close()


def test_loopback_authorization_differential_produces_redacted_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    database, verification, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        port = server.server_address[1]
        environment = verification.environments.update(
            EnvironmentProfile.model_validate(
                {
                    **environment.model_dump(mode="python"),
                    "target_base_url": f"http://127.0.0.1:{port}",
                    "scope_allowlist": [
                        ScopeRule(
                            scheme="http",
                            host="127.0.0.1",
                            port=port,
                            path_prefix="/api/",
                        )
                    ],
                    "allow_private_addresses": True,
                }
            )
        )
        _finding, plan = _persist_plan(database, verification, scan, environment, identities)
        approval_service = ApprovalService(database)
        approval = approval_service.request(
            plan.id,
            VerificationPolicyConfig(enabled=True, allow_safe_read=True),
        )
        approval_service.decide(
            approval.id,
            ApprovalDecision.APPROVED,
            reviewer="integration-test",
            reason="Loopback fixture reviewed.",
        )
        monkeypatch.setenv("ARGUS_TEST_OWNER_TOKEN", "owner-secret")
        monkeypatch.setenv("ARGUS_TEST_PEER_TOKEN", "peer-secret")
        result = ControlPlaneService(tmp_path / "runs").execute_verification(
            plan.id,
            {"test_data": {"resource_id": "fixture-1"}},
        )
        attempt = verification.attempts.get(UUID(str(cast(dict[str, object], result["attempt"])["id"])))

        assert attempt.conclusion is VerificationConclusion.CONFIRMED
        assert attempt.request_count == 2
        evidence = verification.evidence.list(attempt_id=attempt.id)
        assert len(evidence) == 2
        assert all(item.artifact_hash for item in evidence)
        assert all("must-not-persist" not in json.dumps(item.model_dump(mode="json")) for item in evidence)
        raw_database = database.path.read_bytes()
        assert b"owner-secret" not in raw_database
        assert b"peer-secret" not in raw_database
        assert b"must-not-persist" not in raw_database
    finally:
        database.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
