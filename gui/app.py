"""GUI entrypoint: starts the local agent in the background, then the window."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QSystemTrayIcon

from agent.logging_setup import get_logger
from agent.server import start_agent_in_background, wait_for_agent_ready
from config.settings import Settings
from gui.main_window import MainWindow
from gui.theme import DARK_STYLESHEET
from gui.tray import install_tray_icon

_log = get_logger("gui")


def run_gui(settings: Settings, start_minimized: bool = False) -> int:
    # A previous launch (the installer's "start with Windows" shortcut,
    # an already-open window, a `--serve` instance, ...) may already have
    # the agent bound to this port. Trying to bind again would just fail
    # with "address already in use" on a background thread where nothing
    # surfaces the error -- the GUI would sit there reporting "Agent
    # unreachable" forever. Check first, and connect to what's already
    # running instead of racing it.
    agent_handle = None
    if wait_for_agent_ready(settings, timeout=0.5):
        _log.info("Agent already running on %s:%d; connecting to it", settings.api.host, settings.api.port)
    else:
        agent_handle = start_agent_in_background(settings)
        if not wait_for_agent_ready(settings, timeout=5.0):
            # The 0.5s check above isn't airtight: two instances launched
            # together (e.g. the installer's autostart entry racing a
            # manual launch right after login) can both see "nothing
            # running yet" and both try to bind. Whichever loses gets
            # here with agent_handle.error set (most likely "address
            # already in use") -- check once more for a winner before
            # giving up, instead of sitting disconnected forever with a
            # perfectly good agent already running right next to it.
            if agent_handle.error is not None:
                _log.warning("This instance's agent failed to start: %s", agent_handle.error)
            if wait_for_agent_ready(settings, timeout=2.0):
                _log.info("Another instance's agent is up; connecting to it instead")
                agent_handle.stop()
                agent_handle = None
            else:
                _log.warning(
                    "Agent did not become ready in time; GUI will start in a disconnected state. "
                    "Logs: %s",
                    settings.data.resolved_log_dir(),
                )

    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    tray = None
    if tray_available:
        # Otherwise Qt would quit the whole app the moment the window
        # closes -- defeating the point of minimizing to the tray.
        app.setQuitOnLastWindowClosed(False)

    window = MainWindow(settings, minimize_to_tray=tray_available)

    if tray_available:
        tray = install_tray_icon(app, window)

    if start_minimized and tray_available:
        _log.info("Starting minimized to the system tray")
    else:
        window.show()

    exit_code = app.exec()

    if tray is not None:
        tray.hide()
    if agent_handle is not None:
        _log.info("GUI closed; stopping the agent it started")
        agent_handle.stop()
    else:
        _log.info("GUI closed; leaving the agent it connected to (but didn't start) running")
    return exit_code
