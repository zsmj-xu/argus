"""Persistent, hash-bound static review gates."""

from __future__ import annotations

from collections.abc import Mapping

from argus.control.repositories import Repositories
from argus.domain.enums import ReviewStatus, ReviewSubjectType
from argus.domain.hashing import sha256_digest
from argus.domain.models import ReviewRequest, Scan, Task
from argus.execution.contracts import RuntimeInput

_LEGACY_GATE_NAMES = {
    "review.legacy-enrichment": "review-enrichment",
    "review.legacy-findings": "review-findings",
}


def gate_enabled(scan: Scan, task: Task) -> bool:
    configured = scan.config.get("checkpoints", True)
    if isinstance(configured, bool):
        return configured
    if isinstance(configured, list):
        legacy_name = _LEGACY_GATE_NAMES.get(task.plugin_id, task.plugin_id)
        return legacy_name in configured or task.plugin_id in configured
    return True


def subject_hash(inputs: Mapping[str, RuntimeInput]) -> str:
    return sha256_digest(
        {
            capability: {
                "artifact_id": str(item.artifact.id),
                "content_hash": item.artifact.content_hash,
            }
            for capability, item in sorted(inputs.items())
        }
    )


def ensure_review(
    repositories: Repositories,
    *,
    scan: Scan,
    task: Task,
    inputs: Mapping[str, RuntimeInput],
) -> ReviewRequest:
    current_hash = subject_hash(inputs)
    existing = repositories.reviews.list(task_id=task.id)
    if existing:
        latest = existing[-1]
        if latest.subject_hash == current_hash and latest.status in {
            ReviewStatus.OPEN,
            ReviewStatus.APPROVED,
            ReviewStatus.REJECTED,
        }:
            return latest
    subject_type = (
        ReviewSubjectType.FINDING_SET if task.plugin_id == "review.legacy-findings" else ReviewSubjectType.ARTIFACT
    )
    return repositories.reviews.create(
        ReviewRequest(
            scan_id=scan.id,
            task_id=task.id,
            subject_type=subject_type,
            subject_ids=[item.artifact.id for item in inputs.values()],
            subject_hash=current_hash,
        )
    )
