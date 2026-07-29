from __future__ import annotations

import sys
from pathlib import Path

import pytest

from argus.plugins.loader import ExternalPluginExecutionError, load_entrypoint
from argus.plugins.manifest import ManifestError, load_manifest
from argus.plugins.registry import (
    DuplicatePluginError,
    ExternalPluginNotEnabledError,
    PluginRegistry,
)


def _manifest(plugin_id: str = "test.detector") -> str:
    return f"""\
apiVersion: argus.security/v2
kind: detector
metadata:
  id: {plugin_id}
  version: 1.2.3
entrypoint: should_never_import:PLUGIN
consumes:
  - capability: code.graph.v1
    required: true
produces:
  - capability: candidate.test.v1
    artifactType: candidate.test
    schemaVersion: "1.0"
"""


def test_manifest_is_strict_and_registry_discovery_does_not_import_entrypoint(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "plugin" / "plugin.yaml"
    manifest.parent.mkdir()
    manifest.write_text(_manifest(), encoding="utf-8")

    registry = PluginRegistry.discover(builtin_root=tmp_path)

    assert registry.require("test.detector").spec.version == "1.2.3"
    assert "should_never_import" not in sys.modules


def test_manifest_rejects_unknown_fields_and_non_semantic_version(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "plugin.yaml"
    manifest.write_text(_manifest().replace("version: 1.2.3", "version: latest") + "surprise: true\n")

    with pytest.raises(ManifestError):
        load_manifest(manifest)


def test_registry_rejects_duplicate_ids(tmp_path: Path) -> None:
    for directory in ("one", "two"):
        path = tmp_path / directory
        path.mkdir()
        (path / "plugin.yaml").write_text(_manifest(), encoding="utf-8")

    with pytest.raises(DuplicatePluginError, match="duplicate plugin ID"):
        PluginRegistry.discover(builtin_root=tmp_path)


def test_external_discovery_and_execution_require_separate_authorization(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    external.mkdir()
    (external / "plugin.yaml").write_text(_manifest("external.detector"), encoding="utf-8")
    with pytest.raises(ExternalPluginNotEnabledError):
        PluginRegistry.discover(builtin_root=tmp_path / "none", external_roots=[external])

    registry = PluginRegistry.discover(
        builtin_root=tmp_path / "none",
        external_roots=[external],
        allow_external=True,
    )
    with pytest.raises(ExternalPluginExecutionError, match="main process"):
        load_entrypoint(registry, "external.detector")


def test_builtin_manifests_are_discoverable() -> None:
    registry = PluginRegistry.discover()

    assert [plugin.spec.id for plugin in registry.all()] == [
        "comparison.authorization",
        "comparison.injection",
        "detector.authorization",
        "detector.injection",
        "graph.codegraph",
        "reporter.markdown",
        "review.legacy-enrichment",
        "review.legacy-findings",
        "semantic.business-flow-to-security-ir",
    ]
