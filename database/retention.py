"""Retention pruning so the local database does not grow indefinitely.

This module only defines the pruning operation itself; scheduling it
periodically is wired up by the background worker introduced with the
FastAPI agent (Phase 2+).
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import delete
from sqlalchemy.orm import Session

from config.settings import RetentionConfig
from database.models import (
    Event,
    FileRecord,
    Incident,
    NetworkConnection,
    ProcessRecord,
    Website,
)

_TABLE_RETENTION_DAYS: dict[type, str] = {
    Event: "events_days",
    NetworkConnection: "network_connections_days",
    ProcessRecord: "processes_days",
    FileRecord: "files_days",
    Incident: "incidents_days",
}


def prune_old_records(session: Session, retention: RetentionConfig) -> dict[str, int]:
    """Delete rows older than each table's configured retention window.

    Returns a mapping of table name -> number of rows deleted.
    """
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    deleted: dict[str, int] = {}

    for model, attr in _TABLE_RETENTION_DAYS.items():
        days = getattr(retention, attr)
        cutoff = now - dt.timedelta(days=days)
        result = session.execute(delete(model).where(model.timestamp < cutoff))
        deleted[model.__tablename__] = result.rowcount or 0

    # Websites don't currently have their own retention setting; reuse
    # the events window since they're comparable in volume/sensitivity.
    cutoff = now - dt.timedelta(days=retention.events_days)
    result = session.execute(delete(Website).where(Website.timestamp < cutoff))
    deleted[Website.__tablename__] = result.rowcount or 0

    session.commit()
    return deleted
