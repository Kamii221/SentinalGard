import subprocess
import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from config.settings import MonitoringConfig, RiskConfig, load_settings
from database.engine import create_db_engine, create_session_factory
from database.models import Base, Event, ProcessRecord
from monitors.process_monitor import ProcessMonitor, _ProcInfo, _score_process


def _proc_info(**overrides) -> _ProcInfo:
    base = dict(
        pid=1234,
        ppid=1,
        name="notepad.exe",
        exe="C:\\Windows\\notepad.exe",
        cmdline="notepad.exe",
        username="alice",
        create_time=1000.0,
    )
    base.update(overrides)
    return _ProcInfo(**base)


def test_benign_process_scores_zero() -> None:
    risk, reasons = _score_process(_proc_info())
    assert risk == 0
    assert reasons == []


def test_lolbin_name_is_flagged() -> None:
    risk, reasons = _score_process(_proc_info(name="powershell.exe", cmdline="powershell.exe"))
    assert risk == 20
    assert any("LOLBin" in r for r in reasons)


def test_suspicious_powershell_cmdline_is_flagged() -> None:
    risk, reasons = _score_process(
        _proc_info(
            name="powershell.exe",
            cmdline="powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA...",
        )
    )
    # Both the LOLBin name and the command-line indicators fire.
    assert risk == 50
    assert len(reasons) == 2


def test_score_is_capped_at_100() -> None:
    risk, _ = _score_process(
        _proc_info(name="powershell.exe", cmdline="powershell -enc -nop bypass downloadstring iex(")
    )
    assert risk <= 100


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


@pytest.fixture()
def monitor(session_factory) -> ProcessMonitor:
    return ProcessMonitor(session_factory, MonitoringConfig(), RiskConfig())


def test_write_batch_persists_process_record_and_event(monitor: ProcessMonitor, session_factory) -> None:
    from monitors.process_monitor import _ProcessEvent

    info = _proc_info(name="powershell.exe", cmdline="powershell -EncodedCommand abc")
    monitor._write_batch([_ProcessEvent(info=info, status="running")])

    with session_factory() as session:  # type: Session
        record = session.execute(select(ProcessRecord).where(ProcessRecord.pid == 1234)).scalars().one()
        assert record.status == "running"
        # LOLBin name (20) + suspicious cmdline indicator (30).
        assert record.risk_score == 50
        assert record.name == "powershell.exe"

        event = session.execute(select(Event).where(Event.event_type == "process_create")).scalars().one()
        assert event.source == "process_monitor"
        assert event.details["pid"] == 1234
        assert "reasons" in event.details


def test_write_batch_terminated_process_has_zero_risk(monitor: ProcessMonitor, session_factory) -> None:
    from monitors.process_monitor import _ProcessEvent

    info = _proc_info()
    monitor._write_batch([_ProcessEvent(info=info, status="terminated")])

    with session_factory() as session:
        record = session.execute(select(ProcessRecord).where(ProcessRecord.pid == 1234)).scalars().one()
        assert record.status == "terminated"
        assert record.risk_score == 0
        assert record.sha256 is None

        event = session.execute(select(Event).where(Event.event_type == "process_terminate")).scalars().one()
        assert event.details["reasons"] == ["Process exited"]


def test_poll_diff_detects_new_and_terminated_pids(monitor: ProcessMonitor, monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item.status))

    # Seed as if pids 1 and 2 were already known from a prior poll.
    monitor._known = {1: _proc_info(pid=1, create_time=1.0), 2: _proc_info(pid=2, create_time=2.0)}

    # Simulate the next poll: pid 2 terminated, pid 3 is new, pid 1 unchanged.
    from monitors import process_monitor as pm_module

    monkeypatch.setattr(
        pm_module,
        "_snapshot",
        lambda: {1: _proc_info(pid=1, create_time=1.0), 3: _proc_info(pid=3, create_time=3.0)},
    )
    monitor._poll_once()

    assert sorted(seen) == ["running", "terminated"]
    assert set(monitor._known.keys()) == {1, 3}


def test_process_monitor_detects_a_real_spawned_process(tmp_path: Path) -> None:
    """End-to-end: start the real monitor with a fast poll interval,
    spawn an actual child process, and confirm it shows up in the DB."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    config = MonitoringConfig(process_poll_interval_seconds=0.2)
    monitor = ProcessMonitor(session_factory, config, RiskConfig())
    monitor.start()
    # Wait for the initial seed snapshot to finish before spawning: a
    # process created in the same instant as the seed can be folded into
    # it and never produce a "creation" event -- a known limitation of
    # polling-based detection, not something to paper over in the test.
    seed_deadline = time.monotonic() + 5.0
    while not monitor._known and time.monotonic() < seed_deadline:
        time.sleep(0.05)
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(1.5)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5.0
            found = False
            while time.monotonic() < deadline:
                with session_factory() as session:
                    match = session.execute(
                        select(ProcessRecord).where(ProcessRecord.pid == proc.pid, ProcessRecord.status == "running")
                    ).scalars().first()
                    if match is not None:
                        found = True
                        break
                time.sleep(0.2)
            assert found, "expected the spawned child process to be recorded"
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        monitor.stop()
