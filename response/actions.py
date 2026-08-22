"""Response actions: kill process, quarantine/restore a file, disable
a persistence entry.

None of these are triggered automatically by detection (Phases 5-11)
-- matching "avoid aggressive automatic remediation in v1" -- they
only ever run when explicitly invoked through the API, which requires
an explicit ``confirm: true`` on every destructive one (checked at the
route layer in api/routes/response.py).

Disabling registry/service/scheduled-task persistence uses the same
Windows-only winreg/pywin32 APIs as Phase 9's persistence monitor, and
carries the same caveat: written carefully against documented API
behavior and wrapped defensively, but could not be run/verified in
this project's Linux development environment -- spot-check on a real
Windows machine before relying on it. Quarantine/restore (plain file
moves) and kill-process (psutil) work and are tested cross-platform.
"""

from __future__ import annotations

import os
import platform
import shutil
import uuid
from pathlib import Path

import psutil

from agent.logging_setup import get_logger
from monitors.hashing import hash_file

_log = get_logger("response.actions")

# Killing any of these -- by exact process name, case-insensitive --
# can crash or destabilize Windows. Refused regardless of `confirm`.
PROTECTED_PROCESS_NAMES = frozenset(
    {
        "system", "system idle process", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "smss.exe", "svchost.exe",
    }
)


class ResponseActionError(RuntimeError):
    """Raised for any action failure that should be surfaced to the caller as a 4xx."""


def _is_windows() -> bool:
    return platform.system() == "Windows"


# --- Kill process -----------------------------------------------------


def kill_process(pid: int) -> dict:
    if pid == os.getpid():
        raise ResponseActionError("Refusing to kill the SentinelGuard agent's own process")

    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        raise ResponseActionError(f"No process with PID {pid}")

    if name.lower() in PROTECTED_PROCESS_NAMES:
        raise ResponseActionError(f"Refusing to kill '{name}' (PID {pid}) -- a protected system process")

    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except psutil.NoSuchProcess:
        pass  # already gone -- treat as success
    except psutil.AccessDenied as exc:
        raise ResponseActionError(
            f"Access denied killing PID {pid} ('{name}') -- try running the agent as Administrator"
        ) from exc

    _log.info("Killed process pid=%d name=%s", pid, name)
    return {"pid": pid, "name": name}


# --- Quarantine / restore -----------------------------------------------


def quarantine_file(path_str: str, reason: str, quarantine_dir: Path, hash_max_bytes: int) -> dict:
    path = Path(path_str)
    if not path.is_absolute():
        raise ResponseActionError("Quarantine target must be an absolute path")
    if not path.exists():
        raise ResponseActionError(f"File does not exist: {path}")
    if not path.is_file():
        raise ResponseActionError(f"Not a regular file: {path}")

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    resolved_quarantine_dir = quarantine_dir.resolve()
    if resolved_quarantine_dir in path.resolve().parents:
        raise ResponseActionError("File is already inside the quarantine directory")

    sha256 = hash_file(str(path), hash_max_bytes)
    # A random name with a non-executable extension, disconnected from
    # the original filename, so quarantined files can't be accidentally
    # re-triggered by their name/extension alone.
    quarantine_path = quarantine_dir / f"{uuid.uuid4().hex}.quarantined"

    try:
        shutil.move(str(path), str(quarantine_path))
    except OSError as exc:
        raise ResponseActionError(f"Failed to move file to quarantine: {exc}") from exc

    if not _is_windows():
        try:
            os.chmod(quarantine_path, 0o000)
        except OSError:
            pass

    _log.info("Quarantined %s -> %s (reason=%s)", path, quarantine_path, reason)
    return {"original_path": str(path), "quarantine_path": str(quarantine_path), "sha256": sha256}


def restore_quarantined_file(quarantine_path_str: str, original_path_str: str) -> None:
    quarantine_path = Path(quarantine_path_str)
    if not quarantine_path.exists():
        raise ResponseActionError(f"Quarantined file not found: {quarantine_path}")

    original_path = Path(original_path_str)
    if original_path.exists():
        raise ResponseActionError(f"A file already exists at the original path: {original_path}")

    try:
        original_path.parent.mkdir(parents=True, exist_ok=True)
        if not _is_windows():
            os.chmod(quarantine_path, 0o644)
        shutil.move(str(quarantine_path), str(original_path))
    except OSError as exc:
        raise ResponseActionError(f"Failed to restore file: {exc}") from exc

    _log.info("Restored %s -> %s", quarantine_path, original_path)


# --- Disable persistence ---------------------------------------------------


def disable_persistence_entry(
    source_type: str, location: str, name: str, *, quarantine_dir: Path, hash_max_bytes: int
) -> dict:
    if source_type in ("registry_run", "registry_runonce"):
        return _disable_registry_value(location, name)
    if source_type == "service":
        return _disable_service(name)
    if source_type == "scheduled_task":
        return _disable_scheduled_task(location, name)
    if source_type == "startup_folder":
        return _disable_startup_folder_entry(location, name, quarantine_dir, hash_max_bytes)
    raise ResponseActionError(f"Unknown persistence source_type: {source_type}")


def _disable_registry_value(location: str, name: str) -> dict:
    if not _is_windows():
        raise ResponseActionError("Registry persistence can only be disabled on Windows")
    try:
        import winreg
    except ImportError:  # pragma: no cover - Windows only
        raise ResponseActionError("winreg is not available")

    hive_name, _, subkey = location.partition("\\")
    hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}.get(hive_name)
    if hive is None:
        raise ResponseActionError(f"Unrecognized registry hive in location: {location}")

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError as exc:
        raise ResponseActionError(f"Registry value '{name}' not found at {location}") from exc
    except PermissionError as exc:
        raise ResponseActionError(
            f"Access denied deleting registry value '{name}' -- try running the agent as Administrator"
        ) from exc
    except OSError as exc:
        raise ResponseActionError(f"Failed to delete registry value: {exc}") from exc

    _log.info("Disabled registry persistence: %s\\%s", location, name)
    return {"source_type": "registry", "location": location, "name": name, "action": "value_deleted"}


def _disable_service(name: str) -> dict:
    if not _is_windows():
        raise ResponseActionError("Services can only be disabled on Windows")
    try:
        import win32service
    except ImportError:  # pragma: no cover - Windows only
        raise ResponseActionError("pywin32 is not available")

    hscm = None
    hservice = None
    try:
        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        hservice = win32service.OpenService(hscm, name, win32service.SERVICE_CHANGE_CONFIG)
        win32service.ChangeServiceConfig(
            hservice,
            win32service.SERVICE_NO_CHANGE,
            win32service.SERVICE_DISABLED,
            win32service.SERVICE_NO_CHANGE,
            None,
            None,
            False,
            None,
            None,
            None,
            None,
        )
    except Exception as exc:
        raise ResponseActionError(f"Failed to disable service '{name}': {exc}") from exc
    finally:
        if hservice is not None:
            win32service.CloseServiceHandle(hservice)
        if hscm is not None:
            win32service.CloseServiceHandle(hscm)

    _log.info("Disabled service: %s", name)
    return {"source_type": "service", "name": name, "action": "start_type_set_to_disabled"}


def _disable_scheduled_task(location: str, name: str) -> dict:
    if not _is_windows():
        raise ResponseActionError("Scheduled tasks can only be disabled on Windows")
    try:
        import win32com.client
    except ImportError:  # pragma: no cover - Windows only
        raise ResponseActionError("pywin32 is not available")

    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder(location)
        task = folder.GetTask(name)
        task.Enabled = False
    except Exception as exc:
        raise ResponseActionError(f"Failed to disable scheduled task '{name}': {exc}") from exc

    _log.info("Disabled scheduled task: %s\\%s", location, name)
    return {"source_type": "scheduled_task", "location": location, "name": name, "action": "disabled"}


def _disable_startup_folder_entry(location: str, name: str, quarantine_dir: Path, hash_max_bytes: int) -> dict:
    path = Path(location) / name
    result = quarantine_file(
        str(path), "Disabled persistence: startup folder entry", quarantine_dir, hash_max_bytes
    )
    result["source_type"] = "startup_folder"
    result["action"] = "quarantined"
    return result
