"""Windows Event Log analyzer.

Parses a focused set of security-relevant channels/Event IDs
(detection/log_analysis.py's CHANNEL_EVENT_IDS) and normalizes them
into the spec's common event schema -- which is exactly the existing
`events` table (timestamp/host/event_type/source/process/user/
severity/risk_score/details), so no new table is needed here.

Polls each channel independently at a configurable interval
(monitoring.log_poll_interval_seconds), using an XPath time filter so
each poll only asks the Event Log API for events newer than the last
one seen on that channel -- not a full-log rescan. Starts each
channel's "since" cursor at the monitor's start time, so restarting
the agent never replays old history (same "seed without emitting for
what already existed" philosophy as the other monitors).

CAUTION: like Phase 9's registry/task/service backends, the actual
win32evtlog reading (`read_new_events_win32evtlog`) uses APIs that
only exist on Windows and could not be run/verified in this project's
Linux development environment. It's written carefully against the
documented, stable "Windows Event Log XML" rendering schema, and the
XML-parsing/classification logic *is* thoroughly tested against
realistic sample XML matching that schema -- but the win32evtlog call
sequence itself should be spot-checked on a real Windows machine.
Enumerating some channels (notably Security) typically requires
Administrator privileges; this degrades to "no events from this
channel" rather than crashing if access is denied.
"""

from __future__ import annotations

import datetime as dt
import platform
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable

from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import Event
from detection.log_analysis import CHANNEL_EVENT_IDS, classify_log_event
from monitors.queue_worker import QueueWriter

_log = get_logger("monitors.log")

_EVENT_XML_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass(frozen=True)
class RawLogEvent:
    channel: str
    event_id: int
    timestamp: dt.datetime  # naive UTC, matching the DB convention
    host: str
    fields: dict[str, str]


LogReaderFn = Callable[[str, tuple[int, ...], dt.datetime], list[RawLogEvent]]


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _parse_iso_timestamp(value: str) -> dt.datetime:
    """Windows renders SystemTime like '2026-08-22T13:00:00.1234567Z'."""
    value = value.rstrip("Z")
    if "." in value:
        base, frac = value.split(".", 1)
        frac = (frac + "000000")[:6]  # truncate/pad to microsecond precision
        value = f"{base}.{frac}"
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")


def parse_event_xml(xml_text: str) -> RawLogEvent:
    """Parse one <Event>...</Event> rendering into a RawLogEvent.

    Handles both the common EventData/Data[@Name] shape (Security,
    System channel events) and the UserData shape some newer
    providers use (e.g. PowerShell/Defender operational logs),
    generically -- every leaf element becomes a field keyed by its
    local (namespace-stripped) tag name.
    """
    root = ET.fromstring(xml_text)
    system = root.find("e:System", _EVENT_XML_NS)
    if system is None:
        raise ValueError("event XML has no <System> element")

    event_id_elem = system.find("e:EventID", _EVENT_XML_NS)
    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

    time_created = system.find("e:TimeCreated", _EVENT_XML_NS)
    system_time = time_created.get("SystemTime") if time_created is not None else None
    timestamp = _parse_iso_timestamp(system_time) if system_time else dt.datetime.utcnow()

    computer = system.find("e:Computer", _EVENT_XML_NS)
    host = computer.text if computer is not None and computer.text else ""

    fields: dict[str, str] = {}

    event_data = root.find("e:EventData", _EVENT_XML_NS)
    if event_data is not None:
        for data in event_data.findall("e:Data", _EVENT_XML_NS):
            name = data.get("Name")
            if name:
                fields[name] = data.text or ""

    user_data = root.find("e:UserData", _EVENT_XML_NS)
    if user_data is not None:
        for elem in user_data.iter():
            if list(elem):  # skip non-leaf elements
                continue
            if elem.text and elem.text.strip():
                tag = elem.tag.split("}")[-1]
                fields.setdefault(tag, elem.text.strip())

    return RawLogEvent(channel="", event_id=event_id, timestamp=timestamp, host=host, fields=fields)


def read_new_events_win32evtlog(channel: str, event_ids: tuple[int, ...], since: dt.datetime) -> list[RawLogEvent]:
    if not _is_windows():
        return []
    try:
        import win32evtlog
    except ImportError:  # pragma: no cover - Windows only
        return []

    since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    id_filter = " or ".join(f"EventID={eid}" for eid in event_ids)
    xpath = f"*[System[({id_filter}) and TimeCreated[@SystemTime>'{since_iso}']]]"

    results: list[RawLogEvent] = []
    handle = None
    try:
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath, xpath)
        while True:
            batch = win32evtlog.EvtNext(handle, 50)
            if not batch:
                break
            for event_handle in batch:
                try:
                    xml_text = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
                    parsed = parse_event_xml(xml_text)
                    results.append(
                        RawLogEvent(
                            channel=channel,
                            event_id=parsed.event_id,
                            timestamp=parsed.timestamp,
                            host=parsed.host,
                            fields=parsed.fields,
                        )
                    )
                except Exception:
                    _log.debug("Failed to parse an event from channel %s", channel, exc_info=True)
    except Exception:
        _log.debug("Could not query event log channel %s (may not exist, or access denied)", channel, exc_info=True)
    finally:
        if handle is not None:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass
    return results


class LogMonitor:
    """Polls Windows Event Log channels on a background thread and
    records newly seen, classifiable events, batched through a
    QueueWriter."""

    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
        reader: LogReaderFn | None = None,
        channels: dict[str, tuple[int, ...]] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config
        self._reader = reader if reader is not None else read_new_events_win32evtlog
        self._channels = channels if channels is not None else dict(CHANNEL_EVENT_IDS)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-log-monitor", daemon=True)
        self._writer: QueueWriter[RawLogEvent] = QueueWriter("sentinelguard-log-writer", self._write_batch)
        self._since: dict[str, dt.datetime] = {}

    def start(self) -> None:
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self._since = {channel: now for channel in self._channels}
        self._writer.start()
        self._thread.start()
        _log.info(
            "Log monitor started (poll interval %.1fs, channels: %s)",
            self._config.log_poll_interval_seconds,
            ", ".join(self._channels) or "(none configured)",
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._writer.stop(timeout=timeout)
        _log.info("Log monitor stopped")

    def _run(self) -> None:
        while not self._stop_event.wait(self._config.log_poll_interval_seconds):
            self._poll_once()

    def _poll_once(self) -> None:
        for channel, event_ids in self._channels.items():
            since = self._since.get(channel, dt.datetime.now(dt.timezone.utc).replace(tzinfo=None))
            try:
                events = self._reader(channel, event_ids, since)
            except Exception:
                _log.warning("Log reader failed for channel %s", channel, exc_info=True)
                continue

            latest = since
            for event in events:
                self._writer.put(event)
                if event.timestamp > latest:
                    latest = event.timestamp
            self._since[channel] = latest

    def _write_batch(self, batch: list[RawLogEvent]) -> None:
        session = self._session_factory()
        try:
            for raw in batch:
                self._write_one(session, raw)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _write_one(self, session, raw: RawLogEvent) -> None:
        classification = classify_log_event(raw.event_id, raw.fields, self._risk_config)
        if classification is None:
            # Defensive: shouldn't normally happen since we only query
            # for event IDs we know how to classify.
            return

        session.add(
            Event(
                timestamp=raw.timestamp,
                host=raw.host,
                event_type=classification.event_type,
                source=f"log:{raw.channel}",
                process=classification.process,
                user=classification.user,
                severity=classification.severity,
                risk_score=classification.risk,
                details={
                    "channel": raw.channel,
                    "event_id": raw.event_id,
                    "fields": raw.fields,
                    "reasons": classification.reasons,
                },
            )
        )
