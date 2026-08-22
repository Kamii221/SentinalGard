import datetime as dt
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from config.settings import load_settings
from database.engine import create_db_engine, init_db
from database.models import Base, Event, Website
from database.retention import prune_old_records


@pytest.fixture()
def settings(tmp_path: Path):
    s = load_settings()
    s.data.data_dir = tmp_path
    return s


def test_init_db_creates_all_tables(settings) -> None:
    engine = init_db(settings)
    with engine.connect() as conn:
        from sqlalchemy import inspect

        tables = set(inspect(conn).get_table_names())

    expected = {
        "events",
        "alerts",
        "websites",
        "processes",
        "network_connections",
        "files",
        "rules",
        "allowlist",
        "blocklist",
        "quarantine",
        "incidents",
        "settings",
    }
    assert expected.issubset(tables)


def test_insert_and_query_event(tmp_path: Path) -> None:
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        session.add(
            Event(
                event_type="process_create",
                source="process_monitor",
                process="powershell.exe",
                severity="high",
                risk_score=75,
                details={"cmdline": "-EncodedCommand ..."},
            )
        )
        session.commit()

        stored = session.query(Event).one()
        assert stored.event_type == "process_create"
        assert stored.risk_score == 75
        assert stored.details["cmdline"].startswith("-EncodedCommand")


def test_retention_prunes_old_rows(tmp_path: Path, settings) -> None:
    engine = init_db(settings)
    old = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=100)
    recent = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

    with Session(engine) as session:
        session.add(Event(event_type="test", source="test", timestamp=old))
        session.add(Event(event_type="test", source="test", timestamp=recent))
        session.add(Website(url="http://example.com", domain="example.com", browser="chrome", timestamp=old))
        session.commit()

        deleted = prune_old_records(session, settings.retention)
        assert deleted["events"] == 1
        assert deleted["websites"] == 1

        remaining = session.query(Event).all()
        assert len(remaining) == 1
        assert remaining[0].timestamp > old
