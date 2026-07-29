"""Explicit database configuration and Alembic migration entry points."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, URL, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def control_db_path(runs_root: str | Path = "runs") -> Path:
    return Path(runs_root).resolve() / "control.db"


def sqlite_url(path: str | Path) -> URL:
    return URL.create("sqlite+pysqlite", database=str(Path(path).resolve()))


def _set_sqlite_pragmas(dbapi_connection: sqlite3.Connection, _connection_record: object) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def make_engine(path: str | Path) -> Engine:
    """Create an engine without creating or altering the schema."""
    engine = create_engine(sqlite_url(path), future=True)
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def alembic_config(path: str | Path) -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).with_name("migrations")))
    config.set_main_option("sqlalchemy.url", sqlite_url(path).render_as_string(hide_password=False))
    return config


def upgrade_database(path: str | Path, revision: str = "head") -> None:
    """Explicitly apply migrations to an existing or empty database."""
    database_path = Path(path).resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(database_path), revision)


class Database:
    """Session factory for an already-migrated V2 control database."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.engine = make_engine(self.path)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @classmethod
    def from_runs_root(cls, runs_root: str | Path = "runs") -> Database:
        return cls(control_db_path(runs_root))

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as session:
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def close(self) -> None:
        self.engine.dispose()
