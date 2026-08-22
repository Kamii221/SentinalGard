import datetime as dt
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RetentionConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Base, Event
from monitors.retention_monitor import RetentionMonitor


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def test_prune_once_removes_old_rows_and_keeps_recent(session_factory) -> None:
    old = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=100)
    recent = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

    with session_factory() as session:
        session.add(Event(event_type="test", source="test", timestamp=old))
        session.add(Event(event_type="test", source="test", timestamp=recent))
        session.commit()

    monitor = RetentionMonitor(session_factory, MonitoringConfig(), RetentionConfig())
    monitor._prune_once()

    with session_factory() as session:
        remaining = session.execute(select(Event)).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].timestamp == recent


def test_prune_once_survives_a_broken_session(monkeypatch, session_factory) -> None:
    monitor = RetentionMonitor(session_factory, MonitoringConfig(), RetentionConfig())

    def _broken_factory():
        raise RuntimeError("simulated DB connection failure")

    monkeypatch.setattr(monitor, "_session_factory", _broken_factory)
    monitor._prune_once()  # must not raise


def test_retention_monitor_runs_immediately_on_start(tmp_path: Path) -> None:
    """Real thread: confirms pruning happens right at start(), not only
    after waiting a full interval -- important since the default
    interval is 24h and nobody should have to wait that long for a
    never-pruned database to get its first cleanup."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    old = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(days=100)
    with session_factory() as session:
        session.add(Event(event_type="test", source="test", timestamp=old))
        session.commit()

    # A huge interval -- if pruning only ran on the interval, this test
    # would never see it happen within the timeout below.
    monitor = RetentionMonitor(session_factory, MonitoringConfig(retention_prune_interval_hours=999), RetentionConfig())
    monitor.start()
    try:
        deadline = time.monotonic() + 5.0
        pruned = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                if session.execute(select(Event)).scalars().all() == []:
                    pruned = True
                    break
            time.sleep(0.1)
        assert pruned, "expected the startup prune to remove the old row"
    finally:
        monitor.stop()
