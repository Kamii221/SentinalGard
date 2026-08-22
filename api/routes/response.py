"""Response action endpoints: kill process, quarantine/restore a
file, disable persistence, export an incident, mark false positive.

Block/Allow/Allow-once for URLs live in api/routes/websites.py
(Phase 4/5) -- already implemented before this phase.

Every destructive action here (kill-process, quarantine-file,
disable-persistence) requires an explicit ``confirm: true`` in the
request body; without it the agent 400s and performs nothing. This is
the API-level enforcement of the spec's "require confirmation before
destructive actions" -- a future GUI confirmation dialog is expected
to be what sets it. Every successful action is logged as an admin
action (agent/audit.py) and recorded in the events table so it's
visible in the same unified stream as everything else.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.audit import log_admin_action
from api.deps import get_db, get_settings_dep
from api.schemas import (
    DisablePersistenceRequest,
    DisablePersistenceResponse,
    FalsePositiveResponse,
    KillProcessRequest,
    KillProcessResponse,
    QuarantineFileRequest,
    QuarantineFileResponse,
    RestoreQuarantineRequest,
    RestoreQuarantineResponse,
)
from api.security import require_agent_token
from config.settings import Settings, resolved_quarantine_dir
from database.models import Alert, Event, Incident, QuarantineItem
from response.actions import (
    ResponseActionError,
    disable_persistence_entry,
    kill_process,
    quarantine_file,
    restore_quarantined_file,
)

router = APIRouter(tags=["response"], dependencies=[Depends(require_agent_token)])


def _require_confirmation(confirm: bool) -> None:
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="This is a destructive action; resubmit with confirm=true to proceed",
        )


@router.post("/response/kill-process", response_model=KillProcessResponse)
def kill_process_endpoint(
    payload: KillProcessRequest, session: Session = Depends(get_db)
) -> KillProcessResponse:
    _require_confirmation(payload.confirm)
    try:
        result = kill_process(payload.pid)
    except ResponseActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_admin_action(session, "kill_process", details=result)
    session.add(
        Event(
            event_type="process_killed",
            source="response_action",
            process=result["name"],
            severity="informational",
            risk_score=0,
            details=result,
        )
    )
    session.commit()
    return KillProcessResponse(status="ok", pid=result["pid"], name=result["name"])


@router.post("/response/quarantine-file", response_model=QuarantineFileResponse)
def quarantine_file_endpoint(
    payload: QuarantineFileRequest,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> QuarantineFileResponse:
    _require_confirmation(payload.confirm)
    try:
        result = quarantine_file(
            payload.path,
            payload.reason,
            resolved_quarantine_dir(settings),
            settings.monitoring.file_hash_max_bytes,
        )
    except ResponseActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item = QuarantineItem(
        original_path=result["original_path"],
        quarantine_path=result["quarantine_path"],
        sha256=result["sha256"],
        reason=payload.reason or None,
    )
    session.add(item)
    session.flush()

    log_admin_action(session, "quarantine_file", details={**result, "quarantine_id": item.id})
    session.add(
        Event(
            event_type="file_quarantined",
            source="response_action",
            severity="informational",
            risk_score=0,
            details={**result, "quarantine_id": item.id},
        )
    )
    session.commit()

    return QuarantineFileResponse(
        status="ok",
        quarantine_id=item.id,
        original_path=result["original_path"],
        quarantine_path=result["quarantine_path"],
    )


@router.post("/response/restore-quarantine", response_model=RestoreQuarantineResponse)
def restore_quarantine_endpoint(
    payload: RestoreQuarantineRequest, session: Session = Depends(get_db)
) -> RestoreQuarantineResponse:
    _require_confirmation(payload.confirm)

    item = session.get(QuarantineItem, payload.quarantine_id)
    if item is None:
        raise HTTPException(status_code=404, detail="No quarantine item with that ID")
    if item.restored:
        raise HTTPException(status_code=400, detail="This item has already been restored")

    try:
        restore_quarantined_file(item.quarantine_path, item.original_path)
    except ResponseActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    item.restored = True
    item.restored_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

    log_admin_action(
        session, "restore_quarantine", details={"quarantine_id": item.id, "original_path": item.original_path}
    )
    session.add(
        Event(
            event_type="file_restored",
            source="response_action",
            severity="informational",
            risk_score=0,
            details={"quarantine_id": item.id, "original_path": item.original_path},
        )
    )
    session.commit()

    return RestoreQuarantineResponse(status="ok", original_path=item.original_path)


@router.post("/response/disable-persistence", response_model=DisablePersistenceResponse)
def disable_persistence_endpoint(
    payload: DisablePersistenceRequest,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> DisablePersistenceResponse:
    _require_confirmation(payload.confirm)
    try:
        result = disable_persistence_entry(
            payload.source_type,
            payload.location,
            payload.name,
            quarantine_dir=resolved_quarantine_dir(settings),
            hash_max_bytes=settings.monitoring.file_hash_max_bytes,
        )
    except ResponseActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    log_admin_action(session, "disable_persistence", details=result)
    session.add(
        Event(
            event_type="persistence_disabled",
            source="response_action",
            severity="informational",
            risk_score=0,
            details=result,
        )
    )
    session.commit()

    return DisablePersistenceResponse(status="ok", action=result["action"], details=result)


@router.get("/incidents/{incident_id}/export")
def export_incident(incident_id: int, session: Session = Depends(get_db)) -> dict:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="No incident with that ID")

    events = session.execute(
        select(Event).where(Event.id.in_(incident.related_event_ids or []))
    ).scalars().all()

    return {
        "incident": {
            "id": incident.id,
            "timestamp": incident.timestamp.isoformat(),
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
        },
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "host": e.host,
                "event_type": e.event_type,
                "source": e.source,
                "process": e.process,
                "user": e.user,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "details": e.details,
            }
            for e in events
        ],
    }


@router.post("/alerts/{alert_id}/false-positive", response_model=FalsePositiveResponse)
def mark_alert_false_positive(alert_id: int, session: Session = Depends(get_db)) -> FalsePositiveResponse:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="No alert with that ID")
    alert.status = "false_positive"
    log_admin_action(session, "mark_false_positive", details={"alert_id": alert_id})
    session.commit()
    return FalsePositiveResponse(status="ok", id=alert_id)


@router.post("/incidents/{incident_id}/false-positive", response_model=FalsePositiveResponse)
def mark_incident_false_positive(incident_id: int, session: Session = Depends(get_db)) -> FalsePositiveResponse:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="No incident with that ID")
    incident.status = "false_positive"
    log_admin_action(session, "mark_false_positive", details={"incident_id": incident_id})
    session.commit()
    return FalsePositiveResponse(status="ok", id=incident_id)
