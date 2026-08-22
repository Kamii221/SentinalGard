from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Base, Event
from detection.persistence_analysis import (
    analyze_persistence_entry,
    check_lolbin_command,
    check_missing_target,
    check_suspicious_command_keywords,
    check_suspicious_location,
)
from monitors.persistence_monitor import (
    PersistenceEntry,
    PersistenceMonitor,
    _extract_target_path,
    _resolve_target_exists,
    default_startup_folders,
    enum_registry_run_keys,
    enum_scheduled_tasks,
    enum_services,
    enum_startup_folder_entries,
)

RISK = RiskConfig()


# --- Heuristics -------------------------------------------------------


def test_lolbin_command_is_flagged() -> None:
    finding = check_lolbin_command(r"C:\Windows\System32\regsvr32.exe /s evil.dll")
    assert finding is not None
    assert "regsvr32.exe" in finding.reason


def test_benign_command_not_flagged() -> None:
    assert check_lolbin_command(r'"C:\Program Files\Vendor\App\app.exe" --minimized') is None
    assert check_lolbin_command(None) is None


def test_suspicious_keywords_are_flagged() -> None:
    finding = check_suspicious_command_keywords("powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA")
    assert finding is not None


def test_suspicious_location_is_flagged() -> None:
    finding = check_suspicious_location(r"C:\Users\alice\AppData\Local\Temp\update.exe")
    assert finding is not None


def test_normal_location_not_flagged() -> None:
    assert check_suspicious_location(r"C:\Program Files\Vendor\App\app.exe") is None


def test_missing_target_is_flagged() -> None:
    assert check_missing_target(False) is not None
    assert check_missing_target(True) is None
    assert check_missing_target(None) is None


def test_analyze_benign_entry_has_no_detection() -> None:
    analysis = analyze_persistence_entry(
        command=r'"C:\Program Files\Vendor\App\app.exe"', target_exists=True, risk_config=RISK
    )
    assert analysis.risk == 0
    assert analysis.reasons == ["No detection"]


def test_analyze_severe_combination_reaches_high_or_critical() -> None:
    # Three independent signals: LOLBin (25) + suspicious keywords (30)
    # + suspicious location (20) = 75. Two signals alone (55, "medium")
    # deliberately stay below High -- see test_analyze_lolbin_plus_
    # keywords_stays_medium below for that boundary case.
    analysis = analyze_persistence_entry(
        command=r"C:\Users\alice\AppData\Local\Temp\powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA",
        target_exists=None,
        risk_config=RISK,
    )
    assert analysis.severity in ("high", "critical")


def test_analyze_two_signals_alone_stays_medium() -> None:
    analysis = analyze_persistence_entry(
        command=r"powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA -enc downloadstring",
        target_exists=None,
        risk_config=RISK,
    )
    assert analysis.severity == "medium"


# --- Target path extraction --------------------------------------------


def test_extract_target_path_handles_quoted_command() -> None:
    assert _extract_target_path(r'"C:\Program Files\App\app.exe" --flag') == r"C:\Program Files\App\app.exe"


def test_extract_target_path_handles_bare_command() -> None:
    assert _extract_target_path(r"C:\Windows\System32\rundll32.exe shell32.dll,Foo") == r"C:\Windows\System32\rundll32.exe"


def test_extract_target_path_handles_none() -> None:
    assert _extract_target_path(None) is None


def test_resolve_target_exists_never_flags_bare_command_name() -> None:
    # "cmd.exe" alone relies on PATH resolution -- can't be reliably
    # checked, so must return None (unknown), never False.
    assert _resolve_target_exists("cmd.exe /c dir") is None


def test_resolve_target_exists_for_real_file(tmp_path: Path) -> None:
    real_file = tmp_path / "app.exe"
    real_file.write_bytes(b"MZ")
    assert _resolve_target_exists(f'"{real_file}"') is True


def test_resolve_target_exists_for_missing_absolute_path(tmp_path: Path) -> None:
    missing = tmp_path / "gone.exe"
    assert _resolve_target_exists(f'"{missing}"') is False


# --- Backends (cross-platform-safe: Windows-only ones return []) -------


def test_windows_only_backends_return_empty_off_windows() -> None:
    import platform

    if platform.system() != "Windows":
        assert enum_registry_run_keys() == []
        assert enum_scheduled_tasks() == []
        assert enum_services() == []
        assert default_startup_folders() == []


def test_startup_folder_enumeration_is_cross_platform(tmp_path: Path) -> None:
    folder = tmp_path / "Startup"
    folder.mkdir()
    (folder / "updater.exe").write_bytes(b"MZ")
    (folder / "notes.txt").write_text("not a persistence entry, but the folder scanner doesn't filter by type")
    subdir = folder / "ignored_subdir"
    subdir.mkdir()

    entries = enum_startup_folder_entries([folder])
    names = {e.name for e in entries}
    assert "updater.exe" in names
    assert "notes.txt" in names  # startup folders run everything in them, not just .exe
    assert "ignored_subdir" not in names  # directories aren't launchable entries


def test_startup_folder_enumeration_handles_missing_folder(tmp_path: Path) -> None:
    assert enum_startup_folder_entries([tmp_path / "does_not_exist"]) == []


# --- Monitor: snapshot/diff/write using a fake backend ------------------


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def _fake_backend(entries: list[PersistenceEntry]):
    return lambda: entries


def test_write_one_persists_event(session_factory) -> None:
    monitor = PersistenceMonitor(session_factory, MonitoringConfig(), RISK, backends=[])
    entry = PersistenceEntry(
        source_type="registry_run",
        location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        name="Updater",
        command=r"powershell.exe -nop -w hidden -EncodedCommand abc",
    )
    with session_factory() as session:
        monitor._write_one(session, entry)
        session.commit()

        event = session.execute(select(Event).where(Event.event_type == "persistence_new")).scalars().one()
        assert event.source == "persistence_monitor"
        assert event.details["name"] == "Updater"
        assert event.details["source_type"] == "registry_run"
        assert event.risk_score > 0
        assert "reasons" in event.details


def test_snapshot_combines_all_backends(session_factory) -> None:
    entry_a = PersistenceEntry("registry_run", "HKCU\\Run", "A", "a.exe")
    entry_b = PersistenceEntry("service", "Services", "B", "b.exe")
    monitor = PersistenceMonitor(
        session_factory, MonitoringConfig(), RISK, backends=[_fake_backend([entry_a]), _fake_backend([entry_b])]
    )
    snapshot = monitor._snapshot()
    assert len(snapshot) == 2


def test_snapshot_survives_a_failing_backend(session_factory) -> None:
    def _broken_backend():
        raise RuntimeError("simulated backend failure")

    entry = PersistenceEntry("service", "Services", "Good", "good.exe")
    monitor = PersistenceMonitor(
        session_factory, MonitoringConfig(), RISK, backends=[_broken_backend, _fake_backend([entry])]
    )
    snapshot = monitor._snapshot()
    assert len(snapshot) == 1


def test_poll_diff_only_emits_new_entries(session_factory, monkeypatch) -> None:
    entry_old = PersistenceEntry("registry_run", "HKCU\\Run", "Old", "old.exe")
    entry_new = PersistenceEntry("registry_run", "HKCU\\Run", "New", "new.exe")

    backend_state = {"entries": [entry_old]}
    monitor = PersistenceMonitor(
        session_factory, MonitoringConfig(), RISK, backends=[lambda: backend_state["entries"]]
    )
    monitor._known = monitor._snapshot()  # seed with just entry_old

    seen = []
    monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item))

    backend_state["entries"] = [entry_old, entry_new]
    monitor._poll_once()

    assert len(seen) == 1
    assert seen[0].name == "New"


def test_poll_diff_treats_changed_command_as_new(session_factory, monkeypatch) -> None:
    # An existing Run entry whose target changes (e.g. hijacked) must
    # be treated as a new/worth-flagging observation, since the
    # identity key includes the command.
    original = PersistenceEntry("registry_run", "HKCU\\Run", "Updater", "legit.exe")
    hijacked = PersistenceEntry("registry_run", "HKCU\\Run", "Updater", "evil.exe")

    backend_state = {"entries": [original]}
    monitor = PersistenceMonitor(
        session_factory, MonitoringConfig(), RISK, backends=[lambda: backend_state["entries"]]
    )
    monitor._known = monitor._snapshot()

    seen = []
    monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item))

    backend_state["entries"] = [hijacked]
    monitor._poll_once()

    assert len(seen) == 1
    assert seen[0].command == "evil.exe"


def test_persistence_monitor_start_stop_with_fake_backend(session_factory) -> None:
    """End-to-end (minus real Windows APIs): the monitor's actual
    thread + QueueWriter machinery, using an injected fake backend
    since registry/service/task APIs don't exist on this platform."""
    import time

    entry = PersistenceEntry("registry_run", "HKCU\\Run", "Test", "test.exe")
    backend_state = {"entries": []}

    monitor = PersistenceMonitor(
        session_factory,
        MonitoringConfig(persistence_poll_interval_seconds=0.2),
        RiskConfig(),
        backends=[lambda: backend_state["entries"]],
    )
    monitor.start()
    try:
        # Wait for the seed (empty) to complete, then introduce the entry.
        deadline = time.monotonic() + 3.0
        while monitor._known == {} and time.monotonic() < deadline:
            time.sleep(0.05)
        # _known stays {} if the seed genuinely found nothing, which is
        # expected here (empty fake backend) -- just give it a moment.
        time.sleep(0.3)
        backend_state["entries"] = [entry]

        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                match = session.execute(select(Event).where(Event.event_type == "persistence_new")).scalars().first()
                if match is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the new persistence entry to be recorded"
    finally:
        monitor.stop()
