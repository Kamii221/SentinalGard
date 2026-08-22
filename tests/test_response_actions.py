import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from response.actions import (
    PROTECTED_PROCESS_NAMES,
    ResponseActionError,
    disable_persistence_entry,
    kill_process,
    quarantine_file,
    restore_quarantined_file,
)


# --- kill_process -----------------------------------------------------


def test_kill_process_refuses_to_kill_self() -> None:
    with pytest.raises(ResponseActionError, match="own process"):
        kill_process(os.getpid())


def test_kill_process_refuses_unknown_pid() -> None:
    # A PID essentially guaranteed not to exist.
    with pytest.raises(ResponseActionError, match="No process"):
        kill_process(999_999_999)


def test_kill_process_terminates_a_real_child_process() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.3)
        result = kill_process(proc.pid)
        assert result["pid"] == proc.pid
        assert "python" in result["name"].lower()

        proc.wait(timeout=5)
        assert proc.poll() is not None  # process actually exited
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_protected_process_names_are_refused(monkeypatch) -> None:
    import psutil

    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return "lsass.exe"

    monkeypatch.setattr("response.actions.psutil.Process", lambda pid: FakeProcess(pid))
    with pytest.raises(ResponseActionError, match="protected system process"):
        kill_process(4321)


def test_protected_process_names_list_is_reasonable() -> None:
    assert "lsass.exe" in PROTECTED_PROCESS_NAMES
    assert "csrss.exe" in PROTECTED_PROCESS_NAMES


# --- quarantine_file / restore_quarantined_file --------------------------


@pytest.fixture()
def quarantine_dir(tmp_path: Path) -> Path:
    d = tmp_path / "quarantine"
    return d


def test_quarantine_moves_file_and_computes_hash(tmp_path: Path, quarantine_dir: Path) -> None:
    target = tmp_path / "suspicious.exe"
    target.write_bytes(b"MZ" + b"\x00" * 100)

    result = quarantine_file(str(target), "test reason", quarantine_dir, hash_max_bytes=1_000_000)

    assert not target.exists()
    assert Path(result["quarantine_path"]).exists()
    assert Path(result["quarantine_path"]).suffix == ".quarantined"
    assert result["sha256"] is not None
    assert len(result["sha256"]) == 64


def test_quarantine_rejects_relative_path(quarantine_dir: Path) -> None:
    with pytest.raises(ResponseActionError, match="absolute"):
        quarantine_file("relative/path.exe", "", quarantine_dir, 1_000_000)


def test_quarantine_rejects_missing_file(tmp_path: Path, quarantine_dir: Path) -> None:
    with pytest.raises(ResponseActionError, match="does not exist"):
        quarantine_file(str(tmp_path / "gone.exe"), "", quarantine_dir, 1_000_000)


def test_quarantine_rejects_directory(tmp_path: Path, quarantine_dir: Path) -> None:
    a_dir = tmp_path / "somedir"
    a_dir.mkdir()
    with pytest.raises(ResponseActionError, match="regular file"):
        quarantine_file(str(a_dir), "", quarantine_dir, 1_000_000)


def test_quarantine_rejects_file_already_in_quarantine(quarantine_dir: Path) -> None:
    quarantine_dir.mkdir(parents=True)
    already_there = quarantine_dir / "existing.quarantined"
    already_there.write_bytes(b"x")
    with pytest.raises(ResponseActionError, match="already inside"):
        quarantine_file(str(already_there), "", quarantine_dir, 1_000_000)


def test_restore_moves_file_back(tmp_path: Path, quarantine_dir: Path) -> None:
    target = tmp_path / "app.exe"
    target.write_bytes(b"MZ")
    result = quarantine_file(str(target), "", quarantine_dir, 1_000_000)

    restore_quarantined_file(result["quarantine_path"], result["original_path"])

    assert target.exists()
    assert not Path(result["quarantine_path"]).exists()
    assert target.read_bytes() == b"MZ"


def test_restore_refuses_if_original_path_occupied(tmp_path: Path, quarantine_dir: Path) -> None:
    target = tmp_path / "app.exe"
    target.write_bytes(b"MZ")
    result = quarantine_file(str(target), "", quarantine_dir, 1_000_000)

    target.write_bytes(b"something-else-now")  # someone/something recreated it

    with pytest.raises(ResponseActionError, match="already exists"):
        restore_quarantined_file(result["quarantine_path"], result["original_path"])


def test_restore_refuses_missing_quarantine_file(tmp_path: Path) -> None:
    with pytest.raises(ResponseActionError, match="not found"):
        restore_quarantined_file(str(tmp_path / "nope.quarantined"), str(tmp_path / "restored.exe"))


# --- disable_persistence_entry (Windows-only backends; cross-platform
# startup-folder case genuinely exercised) --------------------------------


def test_disable_persistence_unknown_source_type_raises(tmp_path: Path) -> None:
    with pytest.raises(ResponseActionError, match="Unknown persistence source_type"):
        disable_persistence_entry(
            "not_a_real_type", "loc", "name", quarantine_dir=tmp_path / "q", hash_max_bytes=1_000_000
        )


def test_disable_persistence_startup_folder_quarantines_the_file(tmp_path: Path) -> None:
    startup_dir = tmp_path / "Startup"
    startup_dir.mkdir()
    entry = startup_dir / "updater.exe"
    entry.write_bytes(b"MZ")

    result = disable_persistence_entry(
        "startup_folder",
        str(startup_dir),
        "updater.exe",
        quarantine_dir=tmp_path / "quarantine",
        hash_max_bytes=1_000_000,
    )

    assert result["source_type"] == "startup_folder"
    assert result["action"] == "quarantined"
    assert not entry.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="this asserts the *non*-Windows fallback behavior")
def test_disable_persistence_registry_service_task_refused_off_windows(tmp_path: Path) -> None:
    for source_type in ("registry_run", "service", "scheduled_task"):
        with pytest.raises(ResponseActionError, match="Windows"):
            disable_persistence_entry(
                source_type, "HKCU\\Software\\Run", "Foo", quarantine_dir=tmp_path / "q", hash_max_bytes=1_000_000
            )
