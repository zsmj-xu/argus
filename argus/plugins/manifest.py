"""Strict YAML Manifest parsing without importing plugin entrypoints."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from argus.domain.enums import PluginKind
from argus.domain.errors import ArgusV2Error
from argus.plugins.contracts import (
    PLUGIN_API_VERSION,
    CapabilityDeclaration,
    CapabilityRequirement,
    IsolationMode,
    PermissionSpec,
    PluginSpec,
    RuntimeSpec,
)


class ManifestError(ArgusV2Error):
    """A plugin Manifest is unreadable or violates its schema."""


class ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ManifestMetadata(ManifestModel):
    id: str
    version: str


class ManifestCapabilityDeclaration(ManifestModel):
    capability: str
    artifact_type: str = Field(alias="artifactType")
    schema_version: str = Field(alias="schemaVersion")
    supplemental: bool = False


class ManifestRuntime(ManifestModel):
    isolation: str = "process"
    timeout_seconds: int = Field(default=300, alias="timeoutSeconds")
    memory_limit_mb: int = Field(default=1024, alias="memoryLimitMb")
    max_output_bytes: int = Field(default=100 * 1024 * 1024, alias="maxOutputBytes")


class PluginManifest(ManifestModel):
    api_version: str = Field(alias="apiVersion")
    kind: PluginKind
    metadata: ManifestMetadata
    entrypoint: str
    consumes: list[CapabilityRequirement] = Field(default_factory=list)
    produces: list[ManifestCapabilityDeclaration] = Field(default_factory=list)
    permissions: PermissionSpec = Field(default_factory=PermissionSpec)
    runtime: ManifestRuntime = Field(default_factory=ManifestRuntime)
    config_schema: dict[str, JsonValue] = Field(default_factory=dict, alias="configSchema")
    output_schemas: dict[str, JsonValue] = Field(default_factory=dict, alias="outputSchemas")
    continue_on_failure: bool = Field(default=False, alias="continueOnFailure")
    max_attempts: int = Field(default=1, alias="maxAttempts")

    def to_spec(self) -> PluginSpec:
        if self.api_version != PLUGIN_API_VERSION:
            raise ManifestError(f"unsupported plugin apiVersion {self.api_version!r}; expected {PLUGIN_API_VERSION!r}")
        required = [item for item in self.consumes if item.required]
        optional = [
            CapabilityRequirement(capability=item.capability, required=False)
            for item in self.consumes
            if not item.required
        ]
        return PluginSpec(
            id=self.metadata.id,
            version=self.metadata.version,
            kind=self.kind,
            entrypoint=self.entrypoint,
            consumes=required,
            optional_consumes=optional,
            produces=[
                CapabilityDeclaration(
                    capability=item.capability,
                    artifact_type=item.artifact_type,
                    schema_version=item.schema_version,
                    supplemental=item.supplemental,
                )
                for item in self.produces
            ],
            permissions=self.permissions,
            runtime=RuntimeSpec(
                isolation=IsolationMode(self.runtime.isolation),
                timeout_seconds=self.runtime.timeout_seconds,
                memory_limit_mb=self.runtime.memory_limit_mb,
                max_output_bytes=self.runtime.max_output_bytes,
            ),
            config_schema=self.config_schema,
            output_schemas=self.output_schemas,
            continue_on_failure=self.continue_on_failure,
            max_attempts=self.max_attempts,
        )


def load_manifest(path: str | Path) -> PluginSpec:
    manifest_path = Path(path)
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot read plugin Manifest {manifest_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"plugin Manifest must be a YAML mapping: {manifest_path}")
    try:
        manifest = PluginManifest.model_validate(raw)
        return manifest.to_spec()
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ManifestError):
            raise
        raise ManifestError(f"invalid plugin Manifest {manifest_path}: {exc}") from exc
