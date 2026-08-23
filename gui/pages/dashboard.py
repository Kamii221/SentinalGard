"""Dashboard page: protection status + the headline counters from spec."""

from __future__ import annotations

import threading

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from agent.logging_setup import get_logger
from agent.server import AgentConnection, ensure_agent_running
from config.settings import Settings
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
    # ensure_agent_running() blocks for up to ~7.5s (startup + retries),
    # so the button click runs it on a background thread; this signal
    # marshals the result back onto the Qt/GUI thread, the only thread
    # allowed to touch widgets.
    _agent_start_finished = Signal(object)

    def __init__(self, client: AgentClient, settings: Settings) -> None:
        super().__init__()
        self._client = client
        self._settings = settings
        self._log_dir = settings.data.resolved_log_dir()
        self._starting = False

        self._status_label = QLabel("Checking protection status…")
        self._status_label.setObjectName("protectionStatus")

        self._start_button = QPushButton("Start Agent")
        self._start_button.clicked.connect(self._start_agent)
        self._start_button.hide()

        self._cards: dict[str, StatCard] = {}
        grid = QGridLayout()
        grid.setSpacing(16)
        for index, (key, title) in enumerate(_TILES):
            card = StatCard(title)
            self._cards[key] = card
            grid.addWidget(card, index // 3, index % 3)

        status_row = QHBoxLayout()
        status_row.addWidget(self._status_label)
        status_row.addWidget(self._start_button)
        status_row.addStretch()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addLayout(status_row)
        layout.addLayout(grid)
        layout.addStretch()

        self._agent_start_finished.connect(self._on_agent_start_finished)

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
            if not self._starting:
                self._status_label.setText(f"⚠ Agent unreachable — see logs in {self._log_dir}")
                self._start_button.show()
            return

        self._start_button.hide()
        state = status.get("protection_status", "unknown")
        self._status_label.setText(f"Protection status: {state.upper()}")
        for key, card in self._cards.items():
            card.set_value(str(status.get(key, 0)))

    def _start_agent(self) -> None:
        self._starting = True
        self._start_button.setEnabled(False)
        self._start_button.setText("Starting…")
        self._status_label.setText("Starting the agent…")

        def _worker() -> None:
            result = ensure_agent_running(self._settings)
            self._agent_start_finished.emit(result)

        threading.Thread(target=_worker, name="sentinelguard-gui-start-agent", daemon=True).start()

    def _on_agent_start_finished(self, result: AgentConnection) -> None:
        self._starting = False
        self._start_button.setEnabled(True)
        self._start_button.setText("Start Agent")
        if result.reachable:
            self._start_button.hide()
            self.refresh()
        else:
            self._status_label.setText(
                f"⚠ Failed to start: {result.error} — see logs in {self._log_dir}"
            )
