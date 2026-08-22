"""SQLite engine/session management.

Uses WAL journaling and NORMAL synchronous mode, which is the standard
low-overhead configuration for an application that does frequent small
writes from background threads while a GUI reads concurrently.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from config.settings import Settings
from database.models import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


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


def init_engine(settings: Settings) -> Engine:
    """Initialize (or return the existing) process-wide engine/session factory."""
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_db_engine(settings.data.resolved_db_path())
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def init_db(settings: Settings) -> Engine:
    """Create all tables that don't already exist."""
    engine = init_engine(settings)
    Base.metadata.create_all(engine)
    return engine


def get_session() -> Iterator[Session]:
    """Yield a session for a single unit of work; call ``init_db`` first."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized; call init_db(settings) first")
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()
