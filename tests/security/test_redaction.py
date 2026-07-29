from __future__ import annotations

from pathlib import Path

from argus.control.db import Database, upgrade_database
from argus.control.events import EventService
from argus.control.repositories import Repositories


def test_event_service_redacts_nested_sensitive_values(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control.db"
    upgrade_database(path)
    database = Database(path)
    try:
        event = EventService(Repositories(database).events).append(
            "security.test",
            payload={
                "authorization": "Bearer secret",
                "nested": {"api_key": "top-secret", "safe": "visible"},
            },
        )
    finally:
        database.close()

    assert event.payload["authorization"] != "Bearer secret"
    nested = event.payload["nested"]
    assert isinstance(nested, dict)
    assert nested["api_key"] != "top-secret"
    assert nested["safe"] == "visible"
