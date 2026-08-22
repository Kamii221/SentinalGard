from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication

from agent.server import start_agent_in_background, wait_for_agent_ready
from config.settings import load_settings
from gui.app import run_gui
from gui.main_window import MainWindow


@pytest.fixture()
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


def _settings_with_port(tmp_path: Path, port: int):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.api.port = port
    # Process monitoring is exercised in tests/test_process_monitor.py;
    # keep it off here so these tests don't spin up a real background
    # psutil polling thread.
    settings.monitoring.enabled = False
    return settings


def test_main_window_lists_all_sections(qapp: QApplication, tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8797)
    window = MainWindow(settings)

    assert window._sidebar.count() == 12
    assert window._sidebar.item(0).text() == "Dashboard"
    assert window._sidebar.item(1).text() == "Live Activity"
    assert window._sidebar.item(11).text() == "Settings"
    assert window._sidebar.currentRow() == 0
    assert window._stack.count() == 12


def test_dashboard_shows_disconnected_state_without_agent(qapp: QApplication, tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8798)  # nothing listening
    window = MainWindow(settings)

    dashboard = window._stack.widget(0)
    assert "unreachable" in dashboard._status_label.text().lower()


def test_dashboard_reflects_live_agent_status(tmp_path: Path, qapp: QApplication) -> None:
    settings = _settings_with_port(tmp_path, 8799)
    handle = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)

        window = MainWindow(settings)
        dashboard = window._stack.widget(0)

        assert "ACTIVE" in dashboard._status_label.text()
        assert dashboard._cards["websites_scanned"]._value_label.text() == "0"
    finally:
        handle.stop()


def test_close_event_ignored_and_hides_window_when_minimized_to_tray(qapp: QApplication, tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8793)
    window = MainWindow(settings, minimize_to_tray=True)
    window.show()

    event = QCloseEvent()
    window.closeEvent(event)

    assert event.isAccepted() is False
    assert window.isVisible() is False


def test_close_event_accepted_without_tray(qapp: QApplication, tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8792)
    window = MainWindow(settings)  # minimize_to_tray defaults to False

    event = QCloseEvent()
    window.closeEvent(event)

    assert event.isAccepted() is True


def test_run_gui_recovers_when_it_loses_a_startup_race(
    monkeypatch: pytest.MonkeyPatch, qapp: QApplication, tmp_path: Path
) -> None:
    """Deterministic version of the race two instances launched together
    can hit: this one's own agent fails to bind (port already taken by
    the other instance), but a recheck finds that other instance's
    agent came up in the meantime -- run_gui must stop its own failed
    handle and fall back to being a plain client, not sit disconnected
    forever next to a perfectly good agent."""
    settings = _settings_with_port(tmp_path, 8789)

    calls = {"wait": 0}

    def fake_wait(_settings: object, timeout: float) -> bool:
        calls["wait"] += 1
        # 1: initial "is one already running" check -> no.
        # 2: post-start readiness wait -> our own start failed.
        # 3: race recheck -> the other instance is up now.
        return calls["wait"] >= 3

    class FakeHandle:
        def __init__(self) -> None:
            self.error = OSError("address already in use")
            self.stopped = False

        def stop(self, timeout: float = 5.0) -> None:
            self.stopped = True

    fake_handle = FakeHandle()
    monkeypatch.setattr("gui.app.wait_for_agent_ready", fake_wait)
    monkeypatch.setattr("gui.app.start_agent_in_background", lambda _settings: fake_handle)

    QTimer.singleShot(200, qapp.quit)
    run_gui(settings)

    assert calls["wait"] == 3
    assert fake_handle.stopped is True


def test_run_gui_connects_to_an_already_running_agent_instead_of_rebinding(
    qapp: QApplication, tmp_path: Path
) -> None:
    """Regression test: the GUI used to unconditionally try to start its
    own agent, which failed with "address already in use" (silently, on
    a background thread) whenever one was already running -- e.g. a
    second GUI launch, or the installer's autostart shortcut racing a
    manual launch. run_gui must detect that and connect instead."""
    settings = _settings_with_port(tmp_path, 8796)
    handle = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)

        # Let run_gui's event loop spin up and settle, then quit it --
        # there's no window interaction to simulate here.
        QTimer.singleShot(200, qapp.quit)
        run_gui(settings)

        # The agent run_gui connected to (but didn't start) must still be
        # running: it must not have tried to rebind the port, and must
        # not have stopped an agent it doesn't own.
        assert wait_for_agent_ready(settings, timeout=1.0)
    finally:
        handle.stop()
