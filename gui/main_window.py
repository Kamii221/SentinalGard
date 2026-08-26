"""SentinelGuard main window: sidebar navigation over a stacked view."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QWidget,
)

from config.settings import Settings
from gui.agent_controller import AgentController
from gui.api_client import AgentClient
from gui.icon import build_app_icon
from gui.pages.dashboard import DashboardPage
from gui.widgets import PlaceholderPage

# (section name, note shown until its backend phase lands; None for Dashboard,
# which is implemented now).
_NAV_SECTIONS: list[tuple[str, str | None]] = [
    ("Dashboard", None),
    ("Live Activity", "Correlated real-time activity feed — lands with Phase 11 (behavior correlation)."),
    ("Websites", "Browser navigation history and verdicts — lands with Phase 4-5 (extensions + URL detection)."),
    ("Alerts", "Alert list and triage — lands with Phase 11 (risk scoring & correlation)."),
    ("Processes", "Process tree and details — lands with Phase 6 (process monitoring)."),
    ("Network", "Outbound connections by process/domain — lands with Phase 8 (network monitoring)."),
    ("Files", "File activity and hashes — lands with Phase 7 (file monitoring & YARA)."),
    ("Persistence", "Startup/Run keys, tasks, services — lands with Phase 9 (persistence monitoring)."),
    ("Logs", "Normalized Windows event log activity — lands with Phase 10 (log analyzer)."),
    ("Rules", "YAML detection rule management — lands with Phase 10-11 (rule engine)."),
    ("Quarantine", "Quarantined files and restore actions — lands with Phase 12 (response actions)."),
    ("Settings", "Agent, retention, and detection settings — filled in alongside later phases."),
]


class MainWindow(QMainWindow):
    def __init__(
        self, settings: Settings, controller: AgentController | None = None, minimize_to_tray: bool = False
    ) -> None:
        super().__init__()
        self._settings = settings
        self._client = AgentClient(settings)
        # Callers that don't care about Start/Stop wiring (most tests)
        # can omit this -- an unstarted controller is a safe default,
        # the dashboard just shows whatever DashboardPage's own status
        # polling already finds.
        self._controller = controller if controller is not None else AgentController(settings)
        # When a tray icon is available, closing the window (the titlebar
        # X) should just hide it -- monitoring keeps running in the
        # background and the dashboard reopens from the tray. Without a
        # tray to fall back to, closing the window behaves normally and
        # exits the app, since there'd be no other way to get it back.
        self._minimize_to_tray = minimize_to_tray

        self.setWindowTitle("SentinelGuard")
        self.setWindowIcon(build_app_icon())
        self.resize(1100, 700)

        self._sidebar = QListWidget()
        self._sidebar.setObjectName("sidebar")
        self._sidebar.setFixedWidth(200)

        self._stack = QStackedWidget()

        for name, note in _NAV_SECTIONS:
            self._sidebar.addItem(QListWidgetItem(name))
            if name == "Dashboard":
                self._stack.addWidget(DashboardPage(self._client, settings, self._controller))
            else:
                self._stack.addWidget(PlaceholderPage(name, note or ""))

        self._sidebar.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._sidebar.setCurrentRow(0)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._sidebar)
        layout.addWidget(self._stack, stretch=1)
        self.setCentralWidget(central)

        status_bar = QStatusBar()
        status_bar.showMessage(f"SentinelGuard v{settings.app.version}")
        self.setStatusBar(status_bar)

    def closeEvent(self, event) -> None:
        if self._minimize_to_tray:
            event.ignore()
            self.hide()
        else:
            super().closeEvent(event)
