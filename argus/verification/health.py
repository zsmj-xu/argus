"""Deterministic health result helpers for M9 verification."""

from __future__ import annotations

from pydantic import JsonValue

from argus.verification.models import HealthCheckSpec


def health_result(spec: HealthCheckSpec, status: int) -> dict[str, JsonValue]:
    return {
        "id": spec.id,
        "status": status,
        "healthy": status in spec.expected_statuses,
    }
