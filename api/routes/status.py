"""Authenticated agent/dashboard status."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import StatusResponse
from api.security import require_agent_token
from database.models import Alert, NetworkConnection, ProcessRecord, Website

router = APIRouter(tags=["status"], dependencies=[Depends(require_agent_token)])

_HIGH_SEVERITIES = ("high", "critical")


def _count(session: Session, model, *filters) -> int:
    stmt = select(func.count()).select_from(model)
    if filters:
        stmt = stmt.where(*filters)
    return session.execute(stmt).scalar_one()


@router.get("/status", response_model=StatusResponse)
def get_status(request: Request, session: Session = Depends(get_db)) -> StatusResponse:
    websites_scanned = _count(session, Website)
    websites_blocked = _count(session, Website, Website.action == "block")
    threats_detected = _count(session, Alert, Alert.severity.in_(_HIGH_SEVERITIES))
    suspicious_processes = _count(session, ProcessRecord, ProcessRecord.severity.in_(_HIGH_SEVERITIES))
    network_events = _count(session, NetworkConnection)
    recent_alerts = _count(session, Alert, Alert.status == "open")

    return StatusResponse(
        protection_status="active",
        uptime_seconds=time.monotonic() - request.app.state.started_monotonic,
        websites_scanned=websites_scanned,
        websites_blocked=websites_blocked,
        threats_detected=threats_detected,
        suspicious_processes=suspicious_processes,
        network_events=network_events,
        recent_alerts=recent_alerts,
    )
