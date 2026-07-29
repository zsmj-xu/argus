"""Canonical event append service."""

from __future__ import annotations

from uuid import UUID

from pydantic import JsonValue

from argus.control.repositories import EventRepository
from argus.domain.enums import EventLevel
from argus.domain.models import Event
from argus.security.redaction import redact_payload


class EventService:
    def __init__(self, repository: EventRepository) -> None:
        self.repository = repository

    def append(
        self,
        event_type: str,
        *,
        level: EventLevel = EventLevel.INFO,
        payload: dict[str, JsonValue] | None = None,
        project_id: UUID | None = None,
        scan_id: UUID | None = None,
        task_id: UUID | None = None,
        finding_id: UUID | None = None,
    ) -> Event:
        event = Event(
            project_id=project_id,
            scan_id=scan_id,
            task_id=task_id,
            finding_id=finding_id,
            event_type=event_type,
            level=level,
            payload=redact_payload(payload or {}),
        )
        return self.repository.append(event)
