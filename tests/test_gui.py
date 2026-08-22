from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from agent.server import start_agent_in_background, wait_for_agent_ready
from config.settings import load_settings
from gui.main_window import MainWindow


@pytest.fixture()
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


def _settings_with_port(tmp_path: Path, port: int):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.api.port = port
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
