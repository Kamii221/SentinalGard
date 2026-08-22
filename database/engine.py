"""SQLite engine/session management.

Uses WAL journaling and NORMAL synchronous mode, which is the standard
low-overhead configuration for an application that does frequent small
writes from background threads while a GUI reads concurrently.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import sessionmaker

from config.settings import Settings
from database.models import Base


def _apply_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_db_engine(db_path: Path) -> Engine:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    event.listen(engine, "connect", _apply_sqlite_pragmas)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(settings: Settings) -> Engine:
    """Create an engine bound to ``settings`` and create all tables that
    don't already exist.

    Deliberately not cached process-wide: callers (the CLI bootstrap, the
    FastAPI app, tests) each own the engine/sessionmaker they get back, so
    running against different settings (e.g. isolated per-test databases)
    never silently reuses another instance's connection.
    """
    engine = create_db_engine(settings.data.resolved_db_path())
    Base.metadata.create_all(engine)
    return engine
