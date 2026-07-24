"""Validate imported benchmark targets and ground-truth metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ROOT / "evaluation" / "targets"
GROUND_TRUTH = ROOT / "evaluation" / "ground_truth"

EXPECTED_ASSETS = {
    "vampi.json": "VAmPI",
    "crapi.json": "crAPI",
    "crapi-community.json": "crAPI",
    "flowmart.json": "flowmart",
}
INVARIANT_KINDS = {"ownership", "authentication", "role", "replay", "trust_boundary"}
COMPARISON_CLASSES = {"injection", "xss", "auth", "authz", "ssrf"}
REQUIRED_VULN_FIELDS = {
    "id",
    "in_scope",
    "invariant_kind",
    "vuln_type",
    "location",
    "handler",
    "endpoint",
    "description",
    "source",
}


def _load(name: str) -> dict[str, Any]:
    with (GROUND_TRUTH / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


def test_expected_targets_and_ground_truth_files_are_present() -> None:
    assert {path.name for path in GROUND_TRUTH.glob("*.json")} == set(EXPECTED_ASSETS)
    assert {path.name for path in TARGETS.iterdir() if path.is_dir()} == set(EXPECTED_ASSETS.values())


def test_import_does_not_track_nested_repository_or_generated_graph_metadata() -> None:
    """Runtime scans may create ignored metadata, but it must never enter the fixture."""
    import subprocess

    tracked = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "evaluation/targets/**/.git/**",
            "evaluation/targets/**/.codegraph/**",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert tracked == []


def test_import_excludes_private_key_material() -> None:
    sensitive_suffixes = {".key", ".pem", ".p12", ".keystore", ".jks"}
    assert not [path for path in TARGETS.rglob("*") if path.is_file() and path.suffix.lower() in sensitive_suffixes]
    assert not list(TARGETS.rglob(".env"))
    assert not list(TARGETS.rglob("jwks.json"))


@pytest.mark.parametrize(("filename", "target_name"), EXPECTED_ASSETS.items())
def test_ground_truth_schema_and_source_locations(filename: str, target_name: str) -> None:
    payload = _load(filename)
    assert isinstance(payload.get("target"), str) and payload["target"].strip()
    assert set(payload.get("invariant_kinds_in_scope", [])) == INVARIANT_KINDS

    vulnerabilities = payload.get("vulnerabilities")
    assert isinstance(vulnerabilities, list) and vulnerabilities
    service_path = payload.get("service_path", "")
    assert isinstance(service_path, str)
    target_root = TARGETS / target_name / service_path

    ids: set[str] = set()
    for vulnerability in vulnerabilities:
        assert isinstance(vulnerability, dict)
        assert REQUIRED_VULN_FIELDS <= set(vulnerability)

        vulnerability_id = vulnerability["id"]
        assert isinstance(vulnerability_id, str) and vulnerability_id
        assert vulnerability_id not in ids
        ids.add(vulnerability_id)

        assert isinstance(vulnerability["in_scope"], bool)
        invariant_kind = vulnerability["invariant_kind"]
        assert isinstance(invariant_kind, str) and invariant_kind
        if vulnerability["in_scope"]:
            assert invariant_kind in INVARIANT_KINDS

        comparison_in_scope = vulnerability.get("comparison_in_scope")
        if comparison_in_scope is not None:
            assert isinstance(comparison_in_scope, bool)
        comparison_class = vulnerability.get("comparison_vuln_class")
        if comparison_in_scope:
            assert comparison_class in COMPARISON_CLASSES
        elif comparison_class is not None:
            assert comparison_class in COMPARISON_CLASSES

        comparison_location = vulnerability.get("comparison_location")
        if comparison_location is not None:
            assert isinstance(comparison_location, dict)
            assert comparison_location.get("file") == vulnerability["location"]
            start = comparison_location.get("line")
            end = comparison_location.get("end_line")
            assert isinstance(start, int) and start > 0
            assert isinstance(end, int) and end >= start

        for key in ("vuln_type", "location", "handler", "endpoint", "description", "source"):
            assert isinstance(vulnerability[key], str) and vulnerability[key].strip()

        location = Path(vulnerability["location"])
        assert not location.is_absolute()
        assert ".." not in location.parts
        assert (target_root / location).is_file(), f"missing source for {vulnerability_id}: {target_root / location}"


def test_vulnerability_ids_are_globally_unique() -> None:
    seen: set[str] = set()
    for filename in EXPECTED_ASSETS:
        for vulnerability in _load(filename)["vulnerabilities"]:
            vulnerability_id = vulnerability["id"]
            assert vulnerability_id not in seen
            seen.add(vulnerability_id)


def test_comparison_scope_counts_are_explicit_and_stable() -> None:
    expected = {
        "vampi.json": 6,
        "flowmart.json": 6,
        "crapi.json": 7,
        "crapi-community.json": 2,
    }
    for filename, expected_count in expected.items():
        vulnerabilities = _load(filename)["vulnerabilities"]
        actual = sum(
            vulnerability.get("comparison_in_scope", vulnerability["in_scope"]) for vulnerability in vulnerabilities
        )
        assert actual == expected_count, filename
