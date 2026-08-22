"""SQLAlchemy ORM models for SentinelGuard's local SQLite store.

Every table that is frequently filtered/sorted by the GUI or detection
engine gets an explicit index: timestamp, domain, severity, process
name, and event_type, per the SentinelGuard data model.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Float, Index, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> dt.datetime:
    """Naive UTC "now".

    SQLite/SQLAlchemy do not reliably round-trip tzinfo, so by convention
    every datetime stored in this database is naive and UTC.
    """
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Event(Base):
    """Normalized event record (the common schema all monitors write to)."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    host: Mapped[str] = mapped_column(String(255), default="")
    event_type: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(64))
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(default=_utcnow)

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_event_type", "event_type"),
        Index("ix_events_severity", "severity"),
        Index("ix_events_process", "process"),
    )


class Alert(Base):
    """A user-facing alert, optionally derived from correlated events."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|resolved|false_positive
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
        Index("ix_alerts_severity", "severity"),
    )


class Website(Base):
    """A browser navigation event reported by an extension."""

    __tablename__ = "websites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str] = mapped_column(String(255))
    browser: Mapped[str] = mapped_column(String(32))  # chrome|edge|firefox
    scheme: Mapped[str] = mapped_column(String(16), default="https")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(String(16), default="allow")  # allow|block|allow_once

    __table_args__ = (
        Index("ix_websites_timestamp", "timestamp"),
        Index("ix_websites_domain", "domain"),
        Index("ix_websites_severity", "severity"),
    )


class ProcessRecord(Base):
    """A process creation/termination observation."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    pid: Mapped[int] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    executable_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    integrity_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|terminated
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_processes_timestamp", "timestamp"),
        Index("ix_processes_name", "name"),
        Index("ix_processes_severity", "severity"),
    )


class NetworkConnection(Base):
    """An observed outbound network connection."""

    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    local_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    local_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remote_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    direction: Mapped[str] = mapped_column(String(16), default="outbound")
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_network_connections_timestamp", "timestamp"),
        Index("ix_network_connections_domain", "domain"),
        Index("ix_network_connections_process", "process_name"),
        Index("ix_network_connections_severity", "severity"),
    )


class FileRecord(Base):
    """A security-relevant file observation (created/modified/deleted)."""

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    path: Mapped[str] = mapped_column(Text)
    filename: Mapped[str] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(16), default="created")  # created|modified|deleted
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        Index("ix_files_timestamp", "timestamp"),
        Index("ix_files_severity", "severity"),
    )


class Rule(Base):
    """Metadata for a loaded YAML detection rule."""

    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    rule_type: Mapped[str] = mapped_column(String(32))  # process|file|network|url|persistence|correlation
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    file_path: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_rules_severity", "severity"),
    )


class AllowlistEntry(Base):
    """A user-approved domain/IP/hash/path (supports allow_once via expires_at)."""

    __tablename__ = "allowlist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entry_type: Mapped[str] = mapped_column(String(16))  # domain|ip|hash|path
    value: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="user")
    expires_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_allowlist_value", "value"),
    )


class BlocklistEntry(Base):
    """A user- or feed-defined domain/IP/hash/path to always block."""

    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entry_type: Mapped[str] = mapped_column(String(16))  # domain|ip|hash|path
    value: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="user")
    created_at: Mapped[dt.datetime] = mapped_column(default=_utcnow)

    __table_args__ = (
        Index("ix_blocklist_value", "value"),
    )


class QuarantineItem(Base):
    """A file moved to quarantine storage."""

    __tablename__ = "quarantine"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    original_path: Mapped[str] = mapped_column(Text)
    quarantine_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    restored: Mapped[bool] = mapped_column(Boolean, default=False)
    restored_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        Index("ix_quarantine_timestamp", "timestamp"),
    )


class Incident(Base):
    """A correlated, high-confidence grouping of related events/alerts."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="informational")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="open")
    related_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_incidents_timestamp", "timestamp"),
        Index("ix_incidents_severity", "severity"),
    )


class SettingRecord(Base):
    """Runtime key/value application settings (distinct from the YAML config file)."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[dt.datetime] = mapped_column(default=_utcnow, onupdate=_utcnow)
