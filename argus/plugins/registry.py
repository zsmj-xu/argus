"""Manifest-only plugin discovery and capability index."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from argus.domain.enums import PluginKind
from argus.domain.errors import ArgusV2Error
from argus.plugins.contracts import (
    IsolationMode,
    NetworkPermission,
    PluginSpec,
    SecretsPermission,
    SubprocessPermission,
)
from argus.plugins.manifest import load_manifest


class RegistryError(ArgusV2Error):
    """Base error for plugin registry construction."""


class DuplicatePluginError(RegistryError):
    """Two Manifests declare the same plugin ID."""


class ExternalPluginNotEnabledError(RegistryError):
    """External discovery was requested without explicit authorization."""


class PermissionPolicyError(RegistryError):
    """A Manifest asks for permissions unavailable in the current runtime."""


class PluginOrigin(str, Enum):
    BUILTIN = "builtin"
    EXTERNAL = "external"
    LEGACY_ADAPTER = "legacy_adapter"


class RegisteredPlugin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    spec: PluginSpec
    origin: PluginOrigin
    manifest_path: str | None = None


class RegistryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_builtin_subprocess: bool = True

    def enforce(self, plugin: RegisteredPlugin) -> None:
        spec = plugin.spec
        if plugin.origin is PluginOrigin.EXTERNAL and spec.runtime.isolation is not IsolationMode.PROCESS:
            raise PermissionPolicyError("external plugins must use process isolation")
        if plugin.origin is PluginOrigin.EXTERNAL and (
            spec.permissions.network is not NetworkPermission.NONE
            or spec.permissions.secrets is not SecretsPermission.NONE
            or spec.permissions.subprocess is not SubprocessPermission.NONE
        ):
            raise PermissionPolicyError("external plugins cannot request network, secrets, or subprocess permissions")
        if spec.permissions.subprocess is SubprocessPermission.RESTRICTED and (
            plugin.origin is not PluginOrigin.BUILTIN
            or not self.allow_builtin_subprocess
            or spec.kind is not PluginKind.GRAPH_PROVIDER
        ):
            raise PermissionPolicyError(f"plugin {spec.id!r} requests unavailable subprocess permission")


class PluginRegistry:
    def __init__(self, *, policy: RegistryPolicy | None = None) -> None:
        self.policy = policy or RegistryPolicy()
        self._plugins: dict[str, RegisteredPlugin] = {}

    @classmethod
    def discover(
        cls,
        *,
        builtin_root: str | Path | None = None,
        external_roots: list[str | Path] | None = None,
        allow_external: bool = False,
        policy: RegistryPolicy | None = None,
    ) -> PluginRegistry:
        registry = cls(policy=policy)
        builtin = Path(builtin_root) if builtin_root is not None else Path(__file__).with_name("builtin")
        registry._discover_root(builtin, PluginOrigin.BUILTIN)
        external = external_roots or []
        if external and not allow_external:
            raise ExternalPluginNotEnabledError("external plugin directories require explicit allow_external=true")
        for root in external:
            registry._discover_root(Path(root), PluginOrigin.EXTERNAL)
        return registry

    def _discover_root(self, root: Path, origin: PluginOrigin) -> None:
        if not root.exists():
            return
        resolved_root = root.resolve()
        for path in sorted(root.rglob("plugin.yaml")):
            resolved_path = path.resolve()
            try:
                resolved_path.relative_to(resolved_root)
            except ValueError as exc:
                raise RegistryError(f"plugin Manifest escapes discovery root: {path}") from exc
            self.register(
                load_manifest(resolved_path),
                origin=origin,
                manifest_path=str(resolved_path),
            )

    def register(
        self,
        spec: PluginSpec,
        *,
        origin: PluginOrigin,
        manifest_path: str | None = None,
    ) -> None:
        plugin = RegisteredPlugin(spec=spec, origin=origin, manifest_path=manifest_path)
        self.policy.enforce(plugin)
        if spec.id in self._plugins:
            current = self._plugins[spec.id]
            raise DuplicatePluginError(
                f"duplicate plugin ID {spec.id!r}: "
                f"{current.manifest_path or current.origin.value} and "
                f"{manifest_path or origin.value}"
            )
        self._plugins[spec.id] = plugin

    def get(self, plugin_id: str) -> RegisteredPlugin | None:
        return self._plugins.get(plugin_id)

    def require(self, plugin_id: str) -> RegisteredPlugin:
        plugin = self.get(plugin_id)
        if plugin is None:
            raise KeyError(plugin_id)
        return plugin

    def all(self) -> list[RegisteredPlugin]:
        return [self._plugins[key] for key in sorted(self._plugins)]

    def producers(self, capability: str) -> list[RegisteredPlugin]:
        return [plugin for plugin in self.all() if capability in plugin.spec.produced_capabilities]
