"""Capability producer selection independent of plugin semantics."""

from __future__ import annotations

from argus.plugins.registry import PluginRegistry, RegisteredPlugin
from argus.planning.validation import (
    AmbiguousCapabilityError,
    InvalidProviderError,
    MissingCapabilityError,
)


def resolve_producer(
    capability: str,
    *,
    registry: PluginRegistry,
    provider_choices: dict[str, str],
) -> RegisteredPlugin:
    candidates = registry.producers(capability)
    configured_id = provider_choices.get(capability)
    if configured_id is not None:
        configured = registry.get(configured_id)
        if configured is None:
            raise InvalidProviderError(f"provider {configured_id!r} configured for {capability!r} is unknown")
        if configured not in candidates:
            raise InvalidProviderError(f"plugin {configured_id!r} does not produce {capability!r}")
        return configured
    if not candidates:
        raise MissingCapabilityError(f"no plugin produces required capability {capability!r}")
    if len(candidates) > 1:
        ids = [item.spec.id for item in candidates]
        raise AmbiguousCapabilityError(
            f"capability {capability!r} has multiple producers {ids}; configure an explicit provider"
        )
    return candidates[0]
