"""Deferred entrypoint import for task execution (M4 and later)."""

from __future__ import annotations

import importlib

from argus.domain.errors import ArgusV2Error
from argus.plugins.registry import PluginOrigin, PluginRegistry


class PluginLoadError(ArgusV2Error):
    """A selected plugin entrypoint could not be loaded."""


class ExternalPluginExecutionError(PluginLoadError):
    """External plugins must never be imported into the main process."""


def load_entrypoint(registry: PluginRegistry, plugin_id: str) -> object:
    plugin = registry.get(plugin_id)
    if plugin is None:
        raise PluginLoadError(f"unknown plugin: {plugin_id}")
    if plugin.origin is PluginOrigin.EXTERNAL:
        raise ExternalPluginExecutionError(f"external plugin {plugin_id!r} cannot execute in the main process")
    module_name, object_name = plugin.spec.entrypoint.split(":", maxsplit=1)
    try:
        module = importlib.import_module(module_name)
        return getattr(module, object_name)
    except (ImportError, AttributeError) as exc:
        raise PluginLoadError(f"cannot load plugin {plugin_id!r} entrypoint {plugin.spec.entrypoint!r}: {exc}") from exc
