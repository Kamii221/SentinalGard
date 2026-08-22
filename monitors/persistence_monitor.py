"""Persistence monitoring: registry Run/RunOnce keys, startup
folders, scheduled tasks, and services.

Most of these are inherently Windows-specific concepts with no
meaningful cross-platform equivalent (there's no "Run key" on Linux),
so each backend function safely returns an empty list on any other
platform or when the required Windows API isn't available -- this
monitor still starts and runs cleanly on non-Windows, it just finds
nothing, which is the correct, honest behavior rather than crashing
or fabricating data.

CAUTION: the registry/scheduled-task/service backends use winreg and
pywin32 APIs that only exist on Windows and could not be run/verified
in this project's Linux development environment. They're written
carefully against documented API behavior and every call is wrapped
defensively (per-target and per-backend try/except, degrading to
"skip this one" or "no data" rather than crashing), but they should
still be spot-checked on a real Windows machine before being relied
on.

Windows Administrator privileges may be required to enumerate the
HKEY_LOCAL_MACHINE hive, services, and some scheduled tasks; each
backend degrades gracefully (skips what it can't read) rather than
failing the whole scan.

Unlike file/process/network monitoring, persistence entries change
rarely, so a much longer poll interval (default 30s) is appropriate
here -- this is a low-frequency check, not a hot path.

There's no dedicated `persistence` table in the schema (see
database/models.py) -- findings are recorded through the normalized
`events` table (event_type="persistence_new"), with the
source-specific fields (registry key, task path, service name, ...)
captured in `details`.
"""

from __future__ import annotations

import os
import platform
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import Event
from detection.persistence_analysis import analyze_persistence_entry
from monitors.queue_worker import QueueWriter

_log = get_logger("monitors.persistence")


@dataclass(frozen=True)
class PersistenceEntry:
    source_type: str  # "registry_run" | "registry_runonce" | "startup_folder" | "scheduled_task" | "service"
    location: str
    name: str
    command: str | None


BackendFn = Callable[[], list[PersistenceEntry]]


def _is_windows() -> bool:
    return platform.system() == "Windows"


# --- Registry Run/RunOnce -------------------------------------------------


def enum_registry_run_keys() -> list[PersistenceEntry]:
    if not _is_windows():
        return []
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        return []

    targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "registry_run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry_runonce", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "registry_run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "registry_runonce", "HKLM"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "registry_run",
            "HKLM",
        ),
    ]

    entries: list[PersistenceEntry] = []
    for hive, subkey, source_type, hive_name in targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break  # no more values in this key
                    entries.append(
                        PersistenceEntry(
                            source_type=source_type,
                            location=f"{hive_name}\\{subkey}",
                            name=name,
                            command=str(value) if value is not None else None,
                        )
                    )
                    index += 1
        except FileNotFoundError:
            continue  # key doesn't exist on this system -- normal
        except OSError:
            _log.debug("Could not read registry key %s\\%s", hive_name, subkey, exc_info=True)
            continue
    return entries


# --- Startup folders (also exercisable cross-platform for tests) --------


def default_startup_folders() -> list[Path]:
    if not _is_windows():
        return []  # startup folders are a Windows Explorer/shell concept
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    candidates = []
    if appdata:
        candidates.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if programdata:
        candidates.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return [p for p in candidates if p.exists() and p.is_dir()]


def enum_startup_folder_entries(folders: list[Path]) -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    for folder in folders:
        try:
            for item in folder.iterdir():
                if item.is_file():
                    entries.append(
                        PersistenceEntry(
                            source_type="startup_folder", location=str(folder), name=item.name, command=str(item)
                        )
                    )
        except OSError:
            _log.debug("Could not list startup folder %s", folder, exc_info=True)
    return entries


# --- Scheduled tasks (Task Scheduler COM API) -----------------------------


def enum_scheduled_tasks() -> list[PersistenceEntry]:
    if not _is_windows():
        return []
    try:
        import win32com.client
    except ImportError:  # pragma: no cover - Windows only
        return []

    entries: list[PersistenceEntry] = []
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        _walk_task_folder(scheduler.GetFolder("\\"), entries)
    except Exception:
        _log.warning("Failed to enumerate scheduled tasks", exc_info=True)
    return entries


def _walk_task_folder(folder, entries: list[PersistenceEntry]) -> None:
    try:
        for task in folder.GetTasks(0):
            entries.append(
                PersistenceEntry(
                    source_type="scheduled_task",
                    location=folder.Path,
                    name=task.Name,
                    command=_task_command(task),
                )
            )
    except Exception:
        _log.debug("Failed to enumerate tasks in folder %s", getattr(folder, "Path", "?"), exc_info=True)

    try:
        for subfolder in folder.GetFolders(0):
            _walk_task_folder(subfolder, entries)
    except Exception:
        _log.debug("Failed to enumerate subfolders of %s", getattr(folder, "Path", "?"), exc_info=True)


def _task_command(task) -> str | None:
    try:
        actions = task.Definition.Actions
        parts = []
        for i in range(1, actions.Count + 1):
            action = actions.Item(i)
            path = getattr(action, "Path", "") or ""
            args = getattr(action, "Arguments", "") or ""
            combined = f"{path} {args}".strip()
            if combined:
                parts.append(combined)
        return "; ".join(parts) or None
    except Exception:
        return None


# --- Services (Service Control Manager) -----------------------------------


def enum_services() -> list[PersistenceEntry]:
    if not _is_windows():
        return []
    try:
        import win32service
    except ImportError:  # pragma: no cover - Windows only
        return []

    entries: list[PersistenceEntry] = []
    hscm = None
    try:
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        services = win32service.EnumServicesStatus(
            hscm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL
        )
        for short_name, _display_name, _status in services:
            command = _service_binary_path(win32service, hscm, short_name)
            entries.append(
                PersistenceEntry(source_type="service", location="Services", name=short_name, command=command)
            )
    except Exception:
        _log.warning("Failed to enumerate services", exc_info=True)
    finally:
        if hscm is not None:
            try:
                win32service.CloseServiceHandle(hscm)
            except Exception:
                pass
    return entries


def _service_binary_path(win32service, hscm, short_name: str) -> str | None:
    hservice = None
    try:
        hservice = win32service.OpenService(hscm, short_name, win32service.SERVICE_QUERY_CONFIG)
        config = win32service.QueryServiceConfig(hservice)
        return config[3]  # lpBinaryPathName
    except Exception:
        return None
    finally:
        if hservice is not None:
            try:
                win32service.CloseServiceHandle(hservice)
            except Exception:
                pass


# --- Target-path existence check ------------------------------------------


def _extract_target_path(command: str | None) -> str | None:
    if not command:
        return None
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        return command[1:end] if end != -1 else None
    return command.split(" ", 1)[0] if command else None


def _resolve_target_exists(command: str | None) -> bool | None:
    """None means "couldn't determine" -- never guess "missing" for a
    bare command name that relies on PATH resolution."""
    path_str = _extract_target_path(command)
    if not path_str:
        return None
    looks_absolute = path_str[1:3] == ":\\" or path_str.startswith("\\\\") or path_str.startswith("/")
    if not looks_absolute:
        return None
    try:
        return Path(path_str).exists()
    except OSError:
        return None


def _default_backends() -> list[BackendFn]:
    return [
        enum_registry_run_keys,
        lambda: enum_startup_folder_entries(default_startup_folders()),
        enum_scheduled_tasks,
        enum_services,
    ]


class PersistenceMonitor:
    """Polls persistence locations on a background thread and records
    newly seen entries, batched through a QueueWriter."""

    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
        backends: list[BackendFn] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config
        self._backends = backends if backends is not None else _default_backends()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-persistence-monitor", daemon=True)
        self._writer: QueueWriter[PersistenceEntry] = QueueWriter(
            "sentinelguard-persistence-writer", self._write_batch
        )
        self._known: dict[tuple, PersistenceEntry] = {}

    def start(self) -> None:
        self._writer.start()
        self._thread.start()
        _log.info(
            "Persistence monitor started (poll interval %.1fs)", self._config.persistence_poll_interval_seconds
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._writer.stop(timeout=timeout)
        _log.info("Persistence monitor stopped")

    def _snapshot(self) -> dict[tuple, PersistenceEntry]:
        result: dict[tuple, PersistenceEntry] = {}
        for backend in self._backends:
            try:
                for entry in backend():
                    key = (entry.source_type, entry.location, entry.name, entry.command)
                    result[key] = entry
            except Exception:
                _log.warning("Persistence backend %r failed", backend, exc_info=True)
        return result

    def _run(self) -> None:
        # Seed without emitting events for entries that already
        # existed before we started watching.
        self._known = self._snapshot()

        while not self._stop_event.wait(self._config.persistence_poll_interval_seconds):
            self._poll_once()

    def _poll_once(self) -> None:
        current = self._snapshot()
        for key, entry in current.items():
            if key not in self._known:
                self._writer.put(entry)
        self._known = current

    def _write_batch(self, batch: list[PersistenceEntry]) -> None:
        session = self._session_factory()
        try:
            for entry in batch:
                self._write_one(session, entry)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _write_one(self, session, entry: PersistenceEntry) -> None:
        target_exists = _resolve_target_exists(entry.command)
        analysis = analyze_persistence_entry(
            command=entry.command, target_exists=target_exists, risk_config=self._risk_config
        )

        session.add(
            Event(
                event_type="persistence_new",
                source="persistence_monitor",
                process=None,
                user=None,
                severity=analysis.severity,
                risk_score=analysis.risk,
                details={
                    "source_type": entry.source_type,
                    "location": entry.location,
                    "name": entry.name,
                    "command": entry.command,
                    "target_exists": target_exists,
                    "reasons": analysis.reasons,
                },
            )
        )
