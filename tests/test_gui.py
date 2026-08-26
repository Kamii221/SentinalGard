import time
from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication

from agent.server import AgentConnection, start_agent_in_background, wait_for_agent_ready
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
    assert dashboard._start_button.isEnabled()
    assert not dashboard._stop_button.isEnabled()


def test_dashboard_reflects_live_agent_status(tmp_path: Path, qapp: QApplication) -> None:
    settings = _settings_with_port(tmp_path, 8799)
    handle = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)

        window = MainWindow(settings)
        dashboard = window._stack.widget(0)

        assert "ACTIVE" in dashboard._status_label.text()
        assert dashboard._cards["websites_scanned"]._value_label.text() == "0"
        assert not dashboard._start_button.isEnabled()
        # This window's own controller didn't start the agent (it was
        # started directly, above, before MainWindow even existed) --
        # Stop must stay disabled, same as
        # test_stop_button_disabled_when_connected_to_an_agent_we_did_not_start.
        assert not dashboard._stop_button.isEnabled()
    finally:
        handle.stop()


def _wait_until_not_busy(dashboard, qapp: QApplication, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while dashboard._busy and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.05)


def test_start_agent_button_starts_the_agent_and_refreshes(qapp: QApplication, tmp_path: Path) -> None:
    """Real end-to-end exercise of the Start button: nothing is running
    when the window opens, clicking Start must actually start the
    agent on a background thread via the shared AgentController, and
    the dashboard must pick up the result via the Qt signal without
    the caller needing to pump anything but the event loop."""
    settings = _settings_with_port(tmp_path, 8787)
    window = MainWindow(settings)
    dashboard = window._stack.widget(0)
    assert dashboard._start_button.isEnabled()

    try:
        dashboard._start_agent()
        assert dashboard._busy is True

        _wait_until_not_busy(dashboard, qapp)

        assert dashboard._controller.reachable is True
        assert "ACTIVE" in dashboard._status_label.text()
        assert not dashboard._start_button.isEnabled()
        assert dashboard._stop_button.isEnabled()
    finally:
        dashboard._controller.stop()


def test_stop_agent_button_stops_the_agent_it_started(qapp: QApplication, tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8786)
    window = MainWindow(settings)
    dashboard = window._stack.widget(0)

    dashboard._start_agent()
    _wait_until_not_busy(dashboard, qapp)
    assert dashboard._controller.owns_agent

    dashboard._stop_agent()
    assert dashboard._busy is True
    _wait_until_not_busy(dashboard, qapp)

    assert not dashboard._controller.owns_agent
    assert not wait_for_agent_ready(settings, timeout=1.0)
    assert "stopped" in dashboard._status_label.text().lower()
    assert dashboard._start_button.isEnabled()
    assert not dashboard._stop_button.isEnabled()


def test_stop_button_disabled_when_connected_to_an_agent_we_did_not_start(
    qapp: QApplication, tmp_path: Path
) -> None:
    settings = _settings_with_port(tmp_path, 8785)
    handle = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)
        window = MainWindow(settings)  # connects via its own controller, doesn't start one
        dashboard = window._stack.widget(0)

        assert not dashboard._controller.owns_agent
        assert not dashboard._stop_button.isEnabled()
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


def test_run_gui_stops_the_agent_it_started(
    monkeypatch: pytest.MonkeyPatch, qapp: QApplication, tmp_path: Path
) -> None:
    """run_gui's AgentController owns the handle it started for it, so
    closing the window must stop that agent."""
    settings = _settings_with_port(tmp_path, 8789)

    class FakeHandle:
        def __init__(self) -> None:
            self.stopped = False

        def stop(self, timeout: float = 5.0) -> None:
            self.stopped = True

    fake_handle = FakeHandle()
    monkeypatch.setattr(
        "gui.agent_controller.ensure_agent_running",
        lambda _settings: AgentConnection(reachable=True, handle=fake_handle),
    )

    QTimer.singleShot(200, qapp.quit)
    run_gui(settings)

    assert fake_handle.stopped is True


def test_run_gui_does_not_touch_an_agent_it_did_not_start(
    monkeypatch: pytest.MonkeyPatch, qapp: QApplication, tmp_path: Path
) -> None:
    """When the controller connects to an agent it didn't start
    (handle=None) -- whether that's a pre-existing instance, or its
    own internal race-recovery finding another instance won -- run_gui
    must not try to stop anything on exit; there's nothing it owns."""
    settings = _settings_with_port(tmp_path, 8788)

    monkeypatch.setattr(
        "gui.agent_controller.ensure_agent_running",
        lambda _settings: AgentConnection(reachable=True, handle=None),
    )

    QTimer.singleShot(200, qapp.quit)
    exit_code = run_gui(settings)  # must not raise

    assert exit_code == 0


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
