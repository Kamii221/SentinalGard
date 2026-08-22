"""File monitoring for security-sensitive locations.

Uses `watchdog` for OS-level filesystem events (event-driven, not
polling), restricted to a small set of security-sensitive top-level
directories (Downloads, Desktop, Temp, Startup on Windows; equivalent
dev-friendly paths elsewhere) -- never a full-disk scan, and never
recursive into arbitrary subdirectories. Only files whose extension is
executable/script/DLL trigger any hashing/reading; every other file
event is dropped by the handler before any I/O happens.

Detection combines detection/file_analysis.py's local heuristics with
an optional YARA scan (detection/yara_engine.py); a YARA match is a
strong, named signal added straight into the risk score and reasons.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import BlocklistEntry, Event, FileRecord
from detection.entropy import shannon_entropy
from detection.file_analysis import TRACKED_EXTENSIONS, analyze_file, file_category
from detection.risk import severity_for_risk
from detection.yara_engine import YaraEngine
from monitors.hashing import hash_file, read_sample
from monitors.queue_worker import QueueWriter

_log = get_logger("monitors.file")

_YARA_POINTS_PER_MATCH = 50


def default_watch_paths() -> list[Path]:
    """Security-sensitive locations to watch -- never the whole disk."""
    home = Path.home()

    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        candidates = [
            home / "Downloads",
            home / "Desktop",
            Path(localappdata) / "Temp" if localappdata else home / "AppData" / "Local" / "Temp",
            Path(appdata) if appdata else home / "AppData" / "Roaming",
        ]
        if appdata:
            candidates.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    else:
        # Dev/non-Windows fallback so the monitor is exercisable off Windows.
        candidates = [home / "Downloads", home / "Desktop", Path("/tmp")]

    return [p for p in candidates if p.exists() and p.is_dir()]


@dataclass(frozen=True)
class _FileEvent:
    path: str
    event_type: str  # "created" | "modified"


class _Handler(FileSystemEventHandler):
    def __init__(self, on_event) -> None:
        self._on_event = on_event

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._maybe_handle(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._maybe_handle(event.src_path, "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        # A rename/move into a tracked extension is treated as a
        # creation at the destination path -- this is exactly how many
        # real downloads land (e.g. browser ".crdownload" renamed to
        # the final ".exe" once the download completes), so skipping
        # on_moved would miss a common, security-relevant pattern.
        if event.is_directory:
            return
        self._maybe_handle(event.dest_path, "created")

    def _maybe_handle(self, path: str, event_type: str) -> None:
        if Path(path).suffix.lower() not in TRACKED_EXTENSIONS:
            return
        self._on_event(_FileEvent(path=path, event_type=event_type))


class FileMonitor:
    """Watches security-sensitive directories and records file events,
    batched through a QueueWriter."""

    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
        watch_paths: list[Path] | None = None,
        yara_engine: YaraEngine | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config
        if watch_paths is not None:
            self._watch_paths = [p for p in watch_paths if p.exists() and p.is_dir()]
        elif monitoring_config.file_watch_paths is not None:
            self._watch_paths = [
                p for p in (Path(raw) for raw in monitoring_config.file_watch_paths) if p.exists() and p.is_dir()
            ]
        else:
            self._watch_paths = default_watch_paths()

        self._yara_engine = yara_engine if yara_engine is not None else YaraEngine()
        self._observer = Observer()
        self._writer: QueueWriter[_FileEvent] = QueueWriter("sentinelguard-file-writer", self._write_batch)
        self._handler = _Handler(self._writer.put)

    def start(self) -> None:
        if not self._watch_paths:
            _log.warning("File monitor: no security-sensitive directories found to watch")
        self._writer.start()
        for path in self._watch_paths:
            self._observer.schedule(self._handler, str(path), recursive=False)
        self._observer.start()
        _log.info("File monitor started, watching: %s", ", ".join(str(p) for p in self._watch_paths) or "(none)")

    def stop(self, timeout: float = 5.0) -> None:
        self._observer.stop()
        self._observer.join(timeout=timeout)
        self._writer.stop(timeout=timeout)
        _log.info("File monitor stopped")

    def _write_batch(self, batch: list[_FileEvent]) -> None:
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

    def _write_one(self, session, event: _FileEvent) -> None:
        path = Path(event.path)
        sha256 = hash_file(event.path, self._config.file_hash_max_bytes)
        sample = read_sample(event.path, self._config.file_entropy_sample_bytes)

        known_malicious = False
        if sha256:
            match = session.execute(
                select(BlocklistEntry).where(BlocklistEntry.entry_type == "hash", BlocklistEntry.value == sha256)
            ).scalars().first()
            known_malicious = match is not None

        analysis = analyze_file(
            path=path,
            event_type=event.event_type,
            sample=sample,
            known_malicious_hash=known_malicious,
            risk_config=self._risk_config,
        )

        risk = analysis.risk
        reasons = list(analysis.reasons)
        yara_matches = self._yara_engine.scan_file(event.path)
        if yara_matches:
            if reasons == ["No detection"]:
                reasons = []
            for m in yara_matches:
                risk = min(100, risk + _YARA_POINTS_PER_MATCH)
                reasons.append(f"YARA rule '{m.rule}' matched: {m.description}")
            severity = severity_for_risk(risk, self._risk_config)
        else:
            severity = analysis.severity

        try:
            size = os.path.getsize(event.path)
        except OSError:
            size = None
        entropy_value = shannon_entropy(sample) if sample else None

        session.add(
            FileRecord(
                path=str(path),
                filename=path.name,
                event_type=event.event_type,
                sha256=sha256,
                size=size,
                entropy=entropy_value,
                file_type=file_category(path),
                severity=severity,
                risk_score=risk,
            )
        )
        session.add(
            Event(
                event_type=f"file_{event.event_type}",
                source="file_monitor",
                process=None,
                user=None,
                severity=severity,
                risk_score=risk,
                details={
                    "path": str(path),
                    "sha256": sha256,
                    "size": size,
                    "entropy": entropy_value,
                    "known_malicious": known_malicious,
                    "reasons": reasons,
                },
            )
        )
