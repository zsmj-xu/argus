from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from argus.domain.enums import ScanEngine, ScanStatus
from argus.domain.hashing import canonical_json_bytes, sha256_digest
from argus.domain.models import Project, Scan

SHA = "a" * 64


def test_domain_datetimes_are_utc_and_timezone_aware() -> None:
    project = Project(
        name="demo",
        repository_path="/tmp/demo",
        created_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
        updated_at=datetime(2026, 7, 29, 12, tzinfo=timezone.utc),
    )

    assert project.created_at.tzinfo is timezone.utc
    assert project.updated_at.tzinfo is timezone.utc


def test_domain_rejects_naive_datetimes() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Project(
            name="demo",
            repository_path="/tmp/demo",
            created_at=datetime(2026, 7, 29, 12),
        )


def test_json_fields_reject_non_json_objects() -> None:
    with pytest.raises(ValidationError):
        Project(
            name="demo",
            repository_path="/tmp/demo",
            default_config={"unsafe": object()},
        )


def test_scan_defaults_to_created_legacy_state() -> None:
    scan = Scan(
        project_id=uuid4(),
        snapshot_id=uuid4(),
        config_hash=SHA,
    )

    assert scan.status is ScanStatus.CREATED
    assert scan.engine is ScanEngine.LEGACY
    assert scan.version == 1


def test_canonical_hash_is_stable_across_mapping_order() -> None:
    left = {"nested": {"b": 2, "a": 1}, "items": ["x", "y"]}
    right = {"items": ["x", "y"], "nested": {"a": 1, "b": 2}}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert sha256_digest(left) == sha256_digest(right)
    assert len(sha256_digest(left)) == 64
