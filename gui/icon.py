"""Shared branding icon: a shield with a checkmark, in the app's accent
color. Drawn programmatically rather than loaded from a designed asset
-- there's no bundled graphic in the repo, and a vector path scales
cleanly to every size Windows asks for (window/taskbar icon, tray icon,
and -- via scripts/generate_icon.py -- the .ico baked into the exe and
the installer).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

ACCENT = "#4f8cff"
ACCENT_DARK = "#2f5fd6"

_ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)


def _shield_path(size: float) -> QPainterPath:
    w = size
    path = QPainterPath()
    path.moveTo(w * 0.5, w * 0.04)
    path.cubicTo(w * 0.78, w * 0.14, w * 0.92, w * 0.18, w * 0.92, w * 0.18)
    path.lineTo(w * 0.92, w * 0.52)
    path.cubicTo(w * 0.92, w * 0.78, w * 0.74, w * 0.92, w * 0.5, w * 0.98)
    path.cubicTo(w * 0.26, w * 0.92, w * 0.08, w * 0.78, w * 0.08, w * 0.52)
    path.lineTo(w * 0.08, w * 0.18)
    path.cubicTo(w * 0.08, w * 0.18, w * 0.22, w * 0.14, w * 0.5, w * 0.04)
    path.closeSubpath()
    return path


def render_icon_pixmap(size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    shield = _shield_path(size)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(ACCENT))
    painter.drawPath(shield)
    painter.setPen(QPen(QColor(ACCENT_DARK), max(1.0, size * 0.02)))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(shield)

    check = QPainterPath()
    check.moveTo(size * 0.30, size * 0.52)
    check.lineTo(size * 0.45, size * 0.66)
    check.lineTo(size * 0.72, size * 0.34)
    painter.setPen(
        QPen(
            QColor("#ffffff"),
            max(2.0, size * 0.09),
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
    )
    painter.drawPath(check)

    painter.end()
    return pixmap


def build_app_icon() -> QIcon:
    icon = QIcon()
    for size in _ICON_SIZES:
        icon.addPixmap(render_icon_pixmap(size))
    return icon
