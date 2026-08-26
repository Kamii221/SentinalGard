"""Dashboard page: protection status + the headline counters from spec."""

from __future__ import annotations

import threading

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from agent.logging_setup import get_logger
from agent.server import AgentConnection
from config.settings import Settings
from gui.agent_controller import AgentController
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
    # AgentController.start()/.stop() can both block for a few seconds
    # (start: up to ~7.5s of readiness polling; stop: up to a 5s
    # thread-join timeout), so button clicks run them on a background
    # thread; this signal marshals the result back onto the Qt/GUI
    # thread, the only thread allowed to touch widgets.
    _agent_start_finished = Signal(object)
    _agent_stop_finished = Signal()

    def __init__(self, client: AgentClient, settings: Settings, controller: AgentController) -> None:
        super().__init__()
        self._client = client
        self._settings = settings
        self._controller = controller
        self._log_dir = settings.data.resolved_log_dir()
        self._busy = False  # a start/stop click is in flight
        # Distinguishes "we clicked Stop" from "unreachable for some
        # other reason" -- controller.owns_agent alone can't do this,
        # since stop() clears the handle as part of stopping, so by the
        # very next refresh() owns_agent is already false either way.
        self._stopped_by_user = False

        self._status_label = QLabel("Checking protection status…")
        self._status_label.setObjectName("protectionStatus")

        self._start_button = QPushButton("Start Agent")
        self._start_button.clicked.connect(self._start_agent)
        self._stop_button = QPushButton("Stop Agent")
        self._stop_button.clicked.connect(self._stop_agent)

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
        status_row.addWidget(self._stop_button)
        status_row.addStretch()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addLayout(status_row)
        layout.addLayout(grid)
        layout.addStretch()

        self._agent_start_finished.connect(self._on_agent_start_finished)
        self._agent_stop_finished.connect(self._on_agent_stop_finished)

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
            if not self._busy:
                if self._stopped_by_user:
                    self._status_label.setText("⏸ Agent stopped")
                else:
                    self._status_label.setText(f"⚠ Agent unreachable — see logs in {self._log_dir}")
                self._set_buttons_enabled(start=True, stop=self._controller.owns_agent)
            return

        if not self._busy:
            self._set_buttons_enabled(start=False, stop=self._controller.owns_agent)
        state = status.get("protection_status", "unknown")
        self._status_label.setText(f"Protection status: {state.upper()}")
        for key, card in self._cards.items():
            card.set_value(str(status.get(key, 0)))

    def _set_buttons_enabled(self, *, start: bool, stop: bool) -> None:
        self._start_button.setEnabled(start)
        self._stop_button.setEnabled(stop)

    def _start_agent(self) -> None:
        self._busy = True
        self._stopped_by_user = False
        self._set_buttons_enabled(start=False, stop=False)
        self._start_button.setText("Starting…")
        self._status_label.setText("Starting the agent…")

        def _worker() -> None:
            result = self._controller.start()
            self._agent_start_finished.emit(result)

        threading.Thread(target=_worker, name="sentinelguard-gui-start-agent", daemon=True).start()

    def _stop_agent(self) -> None:
        self._busy = True
        self._set_buttons_enabled(start=False, stop=False)
        self._stop_button.setText("Stopping…")
        self._status_label.setText("Stopping the agent…")

        def _worker() -> None:
            self._controller.stop()
            self._agent_stop_finished.emit()

        threading.Thread(target=_worker, name="sentinelguard-gui-stop-agent", daemon=True).start()

    def _on_agent_start_finished(self, result: AgentConnection) -> None:
        self._busy = False
        self._start_button.setText("Start Agent")
        if result.reachable:
            self.refresh()
        else:
            self._status_label.setText(f"⚠ Failed to start: {result.error} — see logs in {self._log_dir}")
            self._set_buttons_enabled(start=True, stop=False)

    def _on_agent_stop_finished(self) -> None:
        self._busy = False
        self._stopped_by_user = True
        self._stop_button.setText("Stop Agent")
        self.refresh()
