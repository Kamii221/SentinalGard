"""GUI entrypoint: starts the local agent in the background, then the window."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from agent.logging_setup import get_logger
from agent.server import start_agent_in_background, wait_for_agent_ready
from config.settings import Settings
from gui.main_window import MainWindow
from gui.theme import DARK_STYLESHEET

_log = get_logger("gui")


def run_gui(settings: Settings) -> int:
    agent_handle = start_agent_in_background(settings)
    if not wait_for_agent_ready(settings, timeout=5.0):
        _log.warning("Agent did not become ready in time; GUI will start in a disconnected state")

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow(settings)
    window.show()

    exit_code = app.exec()

    _log.info("GUI closed; stopping background agent")
    agent_handle.stop()
    return exit_code
