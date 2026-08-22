"""Small reusable widgets shared across GUI pages."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class StatCard(QFrame):
    """A single dashboard tile: a title and a big number."""

    def __init__(self, title: str) -> None:
        super().__init__()
        self.setObjectName("statCard")
        self.setContentsMargins(12, 12, 12, 12)

        title_label = QLabel(title)
        title_label.setObjectName("statTitle")

        self._value_label = QLabel("—")
        self._value_label.setObjectName("statValue")

        layout = QVBoxLayout(self)
        layout.addWidget(title_label)
        layout.addWidget(self._value_label)
        layout.addStretch()

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


class PlaceholderPage(QWidget):
    """Stand-in for a section whose backend lands in a later phase."""

    def __init__(self, title: str, note: str) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title)
        title_label.setObjectName("placeholderTitle")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        note_label = QLabel(note or "Not implemented yet.")
        note_label.setObjectName("placeholderNote")
        note_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        note_label.setWordWrap(True)
        note_label.setMaximumWidth(420)

        layout.addWidget(title_label)
        layout.addWidget(note_label)
