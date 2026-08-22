"""System tray integration.

Lets the window close to the tray instead of exiting, so SentinelGuard
can genuinely "run in the background" the way a consumer AV app is
expected to: monitoring keeps going, and the dashboard is a click away
without ever having to relaunch the app.
"""

from __future__ import annotations

from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QSystemTrayIcon

from gui.icon import build_app_icon


def install_tray_icon(app: QApplication, window: QMainWindow) -> QSystemTrayIcon:
    """Create the tray icon and wire it to `window`. Caller keeps a
    reference alive for the app's lifetime -- PySide6 doesn't."""
    tray = QSystemTrayIcon(build_app_icon(), app)
    tray.setToolTip("SentinelGuard")

    def _open_dashboard() -> None:
        window.showNormal()
        window.raise_()
        window.activateWindow()

    menu = QMenu()
    menu.addAction("Open Dashboard", _open_dashboard)
    menu.addSeparator()
    menu.addAction("Exit", app.quit)
    tray.setContextMenu(menu)

    def _on_activated(reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            _open_dashboard()

    tray.activated.connect(_on_activated)
    tray.show()
    return tray
