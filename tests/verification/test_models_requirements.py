from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from argus.config import DEFAULT_CONFIG, load_config
from argus.control.repositories import Repositories
from argus.domain.enums import PluginKind
from argus.plugins.contracts import NetworkPermission, PluginSpec
from argus.verification.models import EnvironmentKind, EnvironmentProfile, IdentityProfile, ScopeRule
from argus.verification.requirements import RequirementResolver, VerifierDeclaration

from .helpers import seed_verification


def test_verification_is_disabled_by_default_and_static_config_is_unchanged() -> None:
    assert DEFAULT_CONFIG["verification"] == {
        "enabled": False,
        "allow_safe_read": False,
        "allow_reversible_write": False,
    }
    assert load_config(None, [])["verification"]["enabled"] is False


def test_profiles_reject_inline_credentials_and_credential_values() -> None:
    with pytest.raises(ValidationError, match="without credentials"):
        EnvironmentProfile(
            project_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            kind=EnvironmentKind.EXISTING_URL,
            target_base_url="https://user:secret@example.test",
            scope_allowlist=[ScopeRule(scheme="https", host="example.test", path_prefix="/")],
        )

    with pytest.raises(ValidationError, match="credential_ref"):
        IdentityProfile(
            project_id=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            handle="owner",
            role="owner",
            credential_ref="actual-secret-value",
        )


def test_requirement_resolver_reports_missing_inputs_then_plan_ready(
    tmp_path: Path,
) -> None:
    database, repositories, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        finding = Repositories(database).findings.list(scan_id=scan.id)[0]
        declaration = VerifierDeclaration(
            verifier_id="authorization_differential_read",
            supported_vuln_classes=["authorization"],
            required_environment_capabilities=["readonly_http"],
            required_identity_roles=["owner", "peer"],
            required_test_data=["resource_id"],
        )
        missing = RequirementResolver().resolve(
            finding,
            declaration,
            environments=[],
            identities=[],
            test_data_keys=set(),
        )
        assert missing.missing_fields == [
            "environment.capability:readonly_http",
            "identity.role:owner",
            "identity.role:peer",
            "test_data:resource_id",
        ]

        ready = RequirementResolver().resolve(
            finding,
            declaration,
            environments=[environment],
            identities=identities,
            test_data_keys={"resource_id"},
        )
        assert ready.missing_fields == []
        repositories.requirements.upsert(ready)
        assert repositories.requirements.get(finding.id).missing_fields == []
    finally:
        database.close()


def test_finding_does_not_implicitly_create_verification_records(
    tmp_path: Path,
) -> None:
    database, repositories, *_rest = seed_verification(tmp_path)
    try:
        assert repositories.requirements.list() == []
        assert repositories.plans.list() == []
        assert repositories.approvals.list() == []
    finally:
        database.close()


def test_verifier_plugin_declaration_has_no_network_permission() -> None:
    verifier = PluginSpec(
        id="verifier.authorization-read",
        version="1.0.0",
        kind=PluginKind.VERIFIER,
        entrypoint="argus.verification.requirements:RequirementResolver",
    )

    assert verifier.permissions.network is NetworkPermission.NONE
