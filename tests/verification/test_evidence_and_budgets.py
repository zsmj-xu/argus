from __future__ import annotations

from pathlib import Path

import pytest

from argus.control.repositories import Repositories
from argus.domain.errors import ConflictError
from argus.verification.evidence import bounded_excerpt, redact_headers
from argus.verification.models import VerificationAttempt

from .test_http_broker_integration import _persist_plan
from .helpers import seed_verification


def test_sensitive_headers_and_json_body_are_redacted_irreversibly() -> None:
    headers = redact_headers(
        [
            ("Authorization", "Bearer top-secret"),
            ("Set-Cookie", "session=top-secret"),
            ("Content-Type", "application/json"),
        ]
    )
    serialized = str(headers)
    assert "top-secret" not in serialized
    assert "[REDACTED:sha256:" in serialized
    assert headers["content-type"] == "application/json"

    excerpt = bounded_excerpt(b'{"token":"top-secret","nested":{"csrf":"secret"},"id":"fixture"}')
    assert "top-secret" not in excerpt
    assert "secret" not in excerpt
    assert "fixture" in excerpt


def test_attempt_budgets_are_reserved_atomically(tmp_path: Path) -> None:
    database, verification, _project, scan, _task, _artifact, environment, identities = seed_verification(tmp_path)
    try:
        finding, plan = _persist_plan(database, verification, scan, environment, identities)
        attempt = verification.attempts.create(
            VerificationAttempt(
                plan_id=plan.id,
                plan_hash=plan.plan_hash,
                finding_id=finding.id,
                snapshot_id=plan.snapshot_id,
                environment_id=environment.id,
            )
        )
        verification.attempts.reserve_request(attempt.id, max_requests=2)
        verification.attempts.reserve_request(attempt.id, max_requests=2)
        with pytest.raises(ConflictError, match="budget exhausted"):
            verification.attempts.reserve_request(attempt.id, max_requests=2)
        verification.attempts.add_response_bytes(
            attempt.id,
            amount=10,
            max_response_bytes=10,
        )
        with pytest.raises(ConflictError, match="byte budget"):
            verification.attempts.add_response_bytes(
                attempt.id,
                amount=1,
                max_response_bytes=10,
            )
        assert Repositories(database).verification.attempts.get(attempt.id).request_count == 2
    finally:
        database.close()
