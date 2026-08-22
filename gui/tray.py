"""System tray integration.

Lets the window close to the tray instead of exiting, so SentinelGuard
can genuinely "run in the background" the way a consumer AV app is
expected to: monitoring keeps going, and the dashboard is a click away
without ever having to relaunch the app.

Drawn programmatically rather than loaded from an icon file -- there's
no bundled asset for one, and a simple filled circle is enough for a
tray glyph.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QApplication, QMainWindow, QMenu, QSystemTrayIcon

_ACCENT = "#4f8cff"


def build_tray_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(_ACCENT))
    painter.drawEllipse(4, 4, 56, 56)
    painter.setBrush(QColor("#ffffff"))
    painter.drawEllipse(24, 24, 16, 16)
    painter.end()
    return QIcon(pixmap)


def install_tray_icon(app: QApplication, window: QMainWindow) -> QSystemTrayIcon:
    """Create the tray icon and wire it to `window`. Caller keeps a
    reference alive for the app's lifetime -- PySide6 doesn't."""
    tray = QSystemTrayIcon(build_tray_icon(), app)
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
