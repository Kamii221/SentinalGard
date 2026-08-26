"""GUI entrypoint: starts the local agent in the background, then the window."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QSystemTrayIcon

from agent.logging_setup import get_logger
from config.settings import Settings
from gui.agent_controller import AgentController
from gui.main_window import MainWindow
from gui.theme import DARK_STYLESHEET
from gui.tray import install_tray_icon

_log = get_logger("gui")


def run_gui(settings: Settings, start_minimized: bool = False) -> int:
    # A previous launch (the installer's "start with Windows" shortcut,
    # an already-open window, a `--serve` instance, ...) may already have
    # the agent bound to this port -- the controller connects to it
    # instead of racing it to bind again. Whatever happens here, the
    # dashboard's Start/Stop buttons operate on this same controller for
    # the rest of the window's life.
    controller = AgentController(settings)
    connection = controller.start()
    if connection.reachable:
        _log.info("Connected to agent on %s:%d", settings.api.host, settings.api.port)
    else:
        _log.warning(
            "Agent not reachable at startup (%s); GUI will start in a disconnected state. Logs: %s",
            connection.error,
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

    window = MainWindow(settings, controller, minimize_to_tray=tray_available)

    if tray_available:
        tray = install_tray_icon(app, window)

    if start_minimized and tray_available:
        _log.info("Starting minimized to the system tray")
    else:
        window.show()

    exit_code = app.exec()

    if tray is not None:
        tray.hide()
    # Reflects whatever the dashboard's Start/Stop buttons did during
    # the session -- if the user already clicked Stop, controller.handle
    # is already None and this is a no-op; if they clicked Start after
    # an initial failure, this stops what that click started.
    if controller.owns_agent:
        _log.info("GUI closed; stopping the agent")
        controller.stop()
    else:
        _log.info("GUI closed; leaving any agent it's connected to (but doesn't own) running")
    return exit_code
