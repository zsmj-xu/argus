from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from argus.control.db import Database, upgrade_database
from argus.control.repositories import Repositories


@pytest.fixture
def control_db(tmp_path: Path) -> Iterator[Database]:
    path = tmp_path / "control.db"
    upgrade_database(path)
    database = Database(path)
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def repositories(control_db: Database) -> Repositories:
    return Repositories(control_db)
