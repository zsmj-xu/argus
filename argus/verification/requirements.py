"""Resolve verifier declarations against available non-secret inputs."""

from __future__ import annotations

import re

from pydantic import Field, field_validator, model_validator

from argus.domain.models import DomainModel, StaticFindingV2, utc_now
from argus.verification.models import EnvironmentProfile, IdentityProfile, VerificationRequirement


class VerifierDeclaration(DomainModel):
    """Requirements declared by a verifier without granting execution access."""

    verifier_id: str
    supported_vuln_classes: list[str] = Field(min_length=1)
    required_environment_capabilities: list[str] = Field(default_factory=list)
    required_identity_roles: list[str] = Field(default_factory=list)
    required_test_data: list[str] = Field(default_factory=list)

    @field_validator("verifier_id")
    @classmethod
    def validate_verifier_id(cls, value: str) -> str:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", value) is None:
            raise ValueError("verifier_id must be a stable lowercase identifier")
        return value

    @model_validator(mode="after")
    def reject_duplicate_declarations(self) -> VerifierDeclaration:
        for label, values in (
            ("supported_vuln_classes", self.supported_vuln_classes),
            (
                "required_environment_capabilities",
                self.required_environment_capabilities,
            ),
            ("required_identity_roles", self.required_identity_roles),
            ("required_test_data", self.required_test_data),
        ):
            if any(not value for value in values) or len(values) != len(set(values)):
                raise ValueError(f"{label} must contain unique non-empty values")
        return self


class RequirementResolver:
    def resolve(
        self,
        finding: StaticFindingV2,
        declaration: VerifierDeclaration,
        *,
        environments: list[EnvironmentProfile],
        identities: list[IdentityProfile],
        test_data_keys: set[str],
    ) -> VerificationRequirement:
        if finding.vuln_class not in declaration.supported_vuln_classes:
            raise ValueError(f"verifier {declaration.verifier_id} does not support {finding.vuln_class}")

        active_environments = [item for item in environments if item.enabled]
        active_identities = [item for item in identities if item.enabled]
        missing: list[str] = []
        for capability in declaration.required_environment_capabilities:
            if not any(capability in environment.capabilities for environment in active_environments):
                missing.append(f"environment.capability:{capability}")
        for role in declaration.required_identity_roles:
            if not any(identity.role == role for identity in active_identities):
                missing.append(f"identity.role:{role}")
        for key in declaration.required_test_data:
            if key not in test_data_keys:
                missing.append(f"test_data:{key}")

        now = utc_now()
        return VerificationRequirement(
            finding_id=finding.id,
            required_environment_capabilities=list(declaration.required_environment_capabilities),
            required_identity_roles=list(declaration.required_identity_roles),
            required_test_data=list(declaration.required_test_data),
            missing_fields=missing,
            created_at=now,
            updated_at=now,
        )
