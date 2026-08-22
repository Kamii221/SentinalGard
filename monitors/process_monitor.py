"""Process creation/termination monitoring via psutil polling.

Windows doesn't expose a lightweight OS-level process-creation event
API without WMI/ETW (that's Phase 10's Windows log analyzer
territory); polling the process table at a configurable interval is
the practical, dependency-light approach the tech list calls for.

Performance: only *new* processes get hashed -- never a continuous
full-system sweep -- and DB writes are batched through QueueWriter
rather than one commit per event. A poll interval in the low seconds
means very short-lived processes between polls can be missed; that's
a known trade-off of polling vs. a true kernel event feed.

Two lightweight built-in heuristics score newly created processes
(LOLBin process names, suspicious PowerShell command-line indicators
-- mirroring the spec's own example YAML rule). This is intentionally
not the full YAML rule engine (Phase 10-11); it just gives Phase 6
real, explainable severity data for the dashboard and later
correlation to build on. No Alert rows are created here -- Phase 11's
correlation engine decides which events become alerts.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass

import psutil
from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import Event, ProcessRecord
from detection.lolbins import LOLBIN_PROCESS_NAMES, SUSPICIOUS_CMDLINE_KEYWORDS
from detection.risk import severity_for_risk
from monitors.hashing import hash_file
from monitors.queue_worker import QueueWriter

_log = get_logger("monitors.process")


@dataclass(frozen=True)
class _ProcInfo:
    pid: int
    ppid: int | None
    name: str
    exe: str | None
    cmdline: str | None
    username: str | None
    create_time: float


@dataclass(frozen=True)
class _ProcessEvent:
    info: _ProcInfo
    status: str  # "running" | "terminated"


def _integrity_level(pid: int) -> str | None:
    """Best-effort Windows process integrity level.

    Requires Administrator privileges to be feasible.
    None on every other platform, and None (never raises) if the
    lookup fails -- e.g. insufficient privileges, or the process
    already exited.
    """
    if os.name != "nt":
        return None
    try:
        import win32api
        import win32con
        import win32security

        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        sid, _attrs = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
        rid = sid.GetSubAuthority(sid.GetSubAuthorityCount() - 1)
        if rid < 0x2000:
            return "low"
        if rid < 0x3000:
            return "medium"
        if rid < 0x4000:
            return "high"
        return "system"
    except Exception:
        return None


def _score_process(info: _ProcInfo) -> tuple[int, list[str]]:
    """Two independent, explainable heuristics -- not the full rule engine."""
    score = 0
    reasons: list[str] = []

    if info.name.lower() in LOLBIN_PROCESS_NAMES:
        score += 20
        reasons.append(f"'{info.name}' is a commonly abused Windows utility (potential LOLBin)")

    cmdline_lower = (info.cmdline or "").lower()
    hits = [kw.strip() for kw in SUSPICIOUS_CMDLINE_KEYWORDS if kw in cmdline_lower]
    if hits:
        score += 30
        reasons.append(f"Command line contains suspicious indicators ({', '.join(hits)})")

    return min(score, 100), reasons


def _snapshot() -> dict[int, _ProcInfo]:
    result: dict[int, _ProcInfo] = {}
    for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        cmdline = " ".join(info.get("cmdline") or []) or None
        pid = info["pid"]
        result[pid] = _ProcInfo(
            pid=pid,
            ppid=info.get("ppid"),
            name=info.get("name") or "",
            exe=info.get("exe"),
            cmdline=cmdline,
            username=info.get("username"),
            create_time=info.get("create_time") or 0.0,
        )
    return result


class ProcessMonitor:
    """Polls the process table on a background thread and records
    creation/termination events, batched through a QueueWriter."""

    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-process-monitor", daemon=True)
        self._writer: QueueWriter[_ProcessEvent] = QueueWriter(
            "sentinelguard-process-writer", self._write_batch
        )
        self._known: dict[int, _ProcInfo] = {}

    def start(self) -> None:
        self._writer.start()
        self._thread.start()
        _log.info("Process monitor started (poll interval %.1fs)", self._config.process_poll_interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._writer.stop(timeout=timeout)
        _log.info("Process monitor stopped")

    def _run(self) -> None:
        # Seed the known set without emitting synthetic "creation" events
        # for every process already running before we started. Known
        # limitation: a process created in the same instant as this seed
        # can be folded into it and never produce a "creation" event --
        # an inherent trade-off of polling rather than a true kernel
        # event feed. It still shows up in every subsequent poll as part
        # of the known set, so it isn't lost from monitoring going
        # forward, just that one creation event.
        self._known = _snapshot()

        while not self._stop_event.wait(self._config.process_poll_interval_seconds):
            self._poll_once()

    def _poll_once(self) -> None:
        current = _snapshot()

        for pid, info in current.items():
            prior = self._known.get(pid)
            if prior is None or prior.create_time != info.create_time:
                self._writer.put(_ProcessEvent(info=info, status="running"))

        for pid, info in self._known.items():
            if pid not in current:
                self._writer.put(_ProcessEvent(info=info, status="terminated"))

        self._known = current

    def _write_batch(self, batch: list[_ProcessEvent]) -> None:
        session = self._session_factory()
        try:
            for event in batch:
                self._write_one(session, event)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _write_one(self, session, event: _ProcessEvent) -> None:
        info = event.info
        if event.status == "running":
            risk, reasons = _score_process(info)
            sha256 = hash_file(info.exe, self._config.process_hash_max_bytes) if info.exe else None
            integrity = _integrity_level(info.pid)
        else:
            risk, reasons = 0, ["Process exited"]
            sha256, integrity = None, None

        severity = severity_for_risk(risk, self._risk_config)

        session.add(
            ProcessRecord(
                pid=info.pid,
                ppid=info.ppid,
                name=info.name,
                executable_path=info.exe,
                command_line=info.cmdline,
                sha256=sha256,
                user=info.username,
                integrity_level=integrity,
                status=event.status,
                severity=severity,
                risk_score=risk,
            )
        )
        session.add(
            Event(
                event_type="process_create" if event.status == "running" else "process_terminate",
                source="process_monitor",
                process=info.name,
                user=info.username,
                severity=severity,
                risk_score=risk,
                details={
                    "pid": info.pid,
                    "ppid": info.ppid,
                    "executable_path": info.exe,
                    "command_line": info.cmdline,
                    "sha256": sha256,
                    "integrity_level": integrity,
                    "reasons": reasons,
                },
            )
        )
