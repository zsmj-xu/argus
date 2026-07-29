"""Strongly typed PluginSpec and permission contracts."""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from argus.domain.enums import PluginKind

PLUGIN_API_VERSION = "argus.security/v2"
_PLUGIN_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\.v[1-9][0-9]*$")
_ENTRYPOINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

NonEmptyStr = Annotated[str, Field(min_length=1)]


class SourcePermission(str, Enum):
    NONE = "none"
    READ = "read"


class NetworkPermission(str, Enum):
    NONE = "none"
    LLM = "llm"


class SubprocessPermission(str, Enum):
    NONE = "none"
    RESTRICTED = "restricted"


class SecretsPermission(str, Enum):
    NONE = "none"
    LLM = "llm"


class IsolationMode(str, Enum):
    IN_PROCESS = "in_process"
    PROCESS = "process"


class PluginContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CapabilityRequirement(PluginContract):
    capability: str
    required: bool = True

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        if _CAPABILITY.fullmatch(value) is None:
            raise ValueError(f"invalid capability name: {value!r}")
        return value


class CapabilityDeclaration(PluginContract):
    capability: str
    artifact_type: NonEmptyStr
    schema_version: NonEmptyStr
    supplemental: bool = False

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        if _CAPABILITY.fullmatch(value) is None:
            raise ValueError(f"invalid capability name: {value!r}")
        return value


class PermissionSpec(PluginContract):
    source: SourcePermission = SourcePermission.NONE
    network: NetworkPermission = NetworkPermission.NONE
    subprocess: SubprocessPermission = SubprocessPermission.NONE
    secrets: SecretsPermission = SecretsPermission.NONE


class RuntimeSpec(PluginContract):
    isolation: IsolationMode = IsolationMode.PROCESS
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    memory_limit_mb: int = Field(default=1024, ge=64, le=16_384)
    max_output_bytes: int = Field(default=100 * 1024 * 1024, ge=1024, le=1024 * 1024 * 1024)


class PluginSpec(PluginContract):
    id: str
    version: str
    kind: PluginKind
    entrypoint: str
    consumes: list[CapabilityRequirement] = Field(default_factory=list)
    optional_consumes: list[CapabilityRequirement] = Field(default_factory=list)
    produces: list[CapabilityDeclaration] = Field(default_factory=list)
    permissions: PermissionSpec = Field(default_factory=PermissionSpec)
    runtime: RuntimeSpec = Field(default_factory=RuntimeSpec)
    config_schema: dict[str, JsonValue] = Field(default_factory=dict)
    output_schemas: dict[str, JsonValue] = Field(default_factory=dict)
    continue_on_failure: bool = False
    max_attempts: int = Field(default=1, ge=1, le=100)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _PLUGIN_ID.fullmatch(value) is None:
            raise ValueError(f"invalid plugin ID: {value!r}")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if _SEMVER.fullmatch(value) is None:
            raise ValueError(f"plugin version must be semantic x.y.z: {value!r}")
        try:
            Version(value)
        except InvalidVersion as exc:
            raise ValueError(f"invalid semantic version: {value!r}") from exc
        return value

    @field_validator("entrypoint")
    @classmethod
    def validate_entrypoint(cls, value: str) -> str:
        if _ENTRYPOINT.fullmatch(value) is None:
            raise ValueError(f"invalid plugin entrypoint: {value!r}")
        return value

    @field_validator("optional_consumes")
    @classmethod
    def validate_optional_requirements(
        cls,
        values: list[CapabilityRequirement],
    ) -> list[CapabilityRequirement]:
        if any(item.required for item in values):
            raise ValueError("optional_consumes entries must set required=false")
        return values

    @model_validator(mode="after")
    def validate_capability_sets(self) -> PluginSpec:
        consumed = [item.capability for item in self.consumes]
        optional = [item.capability for item in self.optional_consumes]
        produced = [item.capability for item in self.produces]
        for label, values in (
            ("consumes", consumed),
            ("optional_consumes", optional),
            ("produces", produced),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate capability in {label}")
        overlap = set(consumed) & set(optional)
        if overlap:
            raise ValueError(f"capabilities cannot be both required and optional: {sorted(overlap)}")
        unknown_schemas = set(self.output_schemas) - set(produced)
        if unknown_schemas:
            raise ValueError(f"output schemas reference undeclared capabilities: {sorted(unknown_schemas)}")
        return self

    @property
    def produced_capabilities(self) -> frozenset[str]:
        return frozenset(item.capability for item in self.produces)
