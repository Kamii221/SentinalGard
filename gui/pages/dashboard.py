"""Dashboard page: protection status + the headline counters from spec."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QGridLayout, QLabel, QVBoxLayout, QWidget

from agent.logging_setup import get_logger
from gui.api_client import AgentClient, AgentClientError
from gui.widgets import StatCard

_log = get_logger("gui.dashboard")

REFRESH_INTERVAL_MS = 3000

_TILES = [
    ("websites_scanned", "Websites scanned"),
    ("websites_blocked", "Websites blocked"),
    ("threats_detected", "Threats detected"),
    ("suspicious_processes", "Suspicious processes"),
    ("network_events", "Network events"),
    ("recent_alerts", "Recent alerts"),
]


class DashboardPage(QWidget):
    def __init__(self, client: AgentClient, log_dir: Path) -> None:
        super().__init__()
        self._client = client
        self._log_dir = log_dir

        self._status_label = QLabel("Checking protection status…")
        self._status_label.setObjectName("protectionStatus")

        self._cards: dict[str, StatCard] = {}
        grid = QGridLayout()
        grid.setSpacing(16)
        for index, (key, title) in enumerate(_TILES):
            card = StatCard(title)
            self._cards[key] = card
            grid.addWidget(card, index // 3, index % 3)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(self._status_label)
        layout.addLayout(grid)
        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def refresh(self) -> None:
        try:
            status = self._client.status()
        except AgentClientError as exc:
            _log.warning("Dashboard refresh failed: %s", exc)
            self._status_label.setText(f"⚠ Agent unreachable — see logs in {self._log_dir}")
            return

        state = status.get("protection_status", "unknown")
        self._status_label.setText(f"Protection status: {state.upper()}")
        for key, card in self._cards.items():
            card.set_value(str(status.get(key, 0)))
