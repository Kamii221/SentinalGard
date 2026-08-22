import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app import create_app
from api.security import TOKEN_HEADER_NAME
from config.settings import load_settings, resolved_quarantine_dir
from database.models import Alert, Event, Incident, QuarantineItem


@pytest.fixture()
def app_settings(tmp_path: Path):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.monitoring.enabled = False
    return settings


@pytest.fixture()
def app(app_settings):
    return create_app(app_settings)


@pytest.fixture()
def client(app) -> TestClient:
    return TestClient(app, client=("127.0.0.1", 12345))


@pytest.fixture()
def token(client: TestClient, app_settings) -> str:
    return app_settings.data.resolved_data_dir().joinpath("agent_token").read_text().strip()


@pytest.fixture()
def auth_headers(token: str) -> dict[str, str]:
    return {TOKEN_HEADER_NAME: token}


# --- kill-process ------------------------------------------------------


def test_kill_process_requires_confirmation(client: TestClient, auth_headers) -> None:
    resp = client.post("/api/v1/response/kill-process", json={"pid": 123456789}, headers=auth_headers)
    assert resp.status_code == 400
    assert "confirm" in resp.json()["detail"].lower()


def test_kill_process_requires_token(client: TestClient) -> None:
    resp = client.post("/api/v1/response/kill-process", json={"pid": 123, "confirm": True})
    assert resp.status_code == 401


def test_kill_process_unknown_pid_returns_400(client: TestClient, auth_headers) -> None:
    resp = client.post(
        "/api/v1/response/kill-process", json={"pid": 999999999, "confirm": True}, headers=auth_headers
    )
    assert resp.status_code == 400


def test_kill_process_real_subprocess_and_logs_event(client: TestClient, auth_headers, app) -> None:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.3)
        resp = client.post(
            "/api/v1/response/kill-process", json={"pid": proc.pid, "confirm": True}, headers=auth_headers
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["pid"] == proc.pid

        proc.wait(timeout=5)

        with app.state.session_factory() as session:
            event = session.execute(select(Event).where(Event.event_type == "process_killed")).scalars().one()
            assert event.source == "response_action"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


# --- quarantine / restore ------------------------------------------------


def test_quarantine_requires_confirmation(client: TestClient, auth_headers) -> None:
    resp = client.post("/api/v1/response/quarantine-file", json={"path": "/tmp/x"}, headers=auth_headers)
    assert resp.status_code == 400


def test_quarantine_and_restore_round_trip(client: TestClient, auth_headers, app, tmp_path: Path) -> None:
    target = tmp_path / "suspicious.exe"
    target.write_bytes(b"MZ" + b"\x00" * 50)

    resp = client.post(
        "/api/v1/response/quarantine-file",
        json={"path": str(target), "reason": "test", "confirm": True},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert not target.exists()
    quarantine_id = body["quarantine_id"]

    with app.state.session_factory() as session:
        item = session.get(QuarantineItem, quarantine_id)
        assert item is not None
        assert item.restored is False

    restore_resp = client.post(
        "/api/v1/response/restore-quarantine",
        json={"quarantine_id": quarantine_id, "confirm": True},
        headers=auth_headers,
    )
    assert restore_resp.status_code == 200
    assert target.exists()

    with app.state.session_factory() as session:
        item = session.get(QuarantineItem, quarantine_id)
        assert item.restored is True
        assert item.restored_at is not None


def test_restore_unknown_id_returns_404(client: TestClient, auth_headers) -> None:
    resp = client.post(
        "/api/v1/response/restore-quarantine", json={"quarantine_id": 99999, "confirm": True}, headers=auth_headers
    )
    assert resp.status_code == 404


def test_quarantine_missing_file_returns_400(client: TestClient, auth_headers, tmp_path: Path) -> None:
    resp = client.post(
        "/api/v1/response/quarantine-file",
        json={"path": str(tmp_path / "nope.exe"), "confirm": True},
        headers=auth_headers,
    )
    assert resp.status_code == 400


def test_quarantine_uses_configured_quarantine_dir(client: TestClient, auth_headers, app, app_settings, tmp_path: Path) -> None:
    target = tmp_path / "malware.exe"
    target.write_bytes(b"MZ")
    resp = client.post(
        "/api/v1/response/quarantine-file", json={"path": str(target), "confirm": True}, headers=auth_headers
    )
    assert resp.status_code == 200
    quarantine_path = Path(resp.json()["quarantine_path"])
    assert quarantine_path.parent == resolved_quarantine_dir(app_settings)


# --- disable-persistence --------------------------------------------------


def test_disable_persistence_requires_confirmation(client: TestClient, auth_headers) -> None:
    resp = client.post(
        "/api/v1/response/disable-persistence",
        json={"source_type": "service", "location": "Services", "name": "Foo"},
        headers=auth_headers,
    )
    assert resp.status_code == 400


def test_disable_persistence_startup_folder(client: TestClient, auth_headers, tmp_path: Path) -> None:
    startup_dir = tmp_path / "Startup"
    startup_dir.mkdir()
    (startup_dir / "updater.exe").write_bytes(b"MZ")

    resp = client.post(
        "/api/v1/response/disable-persistence",
        json={
            "source_type": "startup_folder",
            "location": str(startup_dir),
            "name": "updater.exe",
            "confirm": True,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["action"] == "quarantined"
    assert not (startup_dir / "updater.exe").exists()


def test_disable_persistence_invalid_source_type_is_rejected_by_schema(client: TestClient, auth_headers) -> None:
    resp = client.post(
        "/api/v1/response/disable-persistence",
        json={"source_type": "not_a_real_type", "location": "x", "name": "y", "confirm": True},
        headers=auth_headers,
    )
    assert resp.status_code == 422


# --- export incident / false positive ------------------------------------


def test_export_unknown_incident_returns_404(client: TestClient, auth_headers) -> None:
    resp = client.get("/api/v1/incidents/99999/export", headers=auth_headers)
    assert resp.status_code == 404


def test_export_incident_includes_related_events(client: TestClient, auth_headers, app) -> None:
    with app.state.session_factory() as session:
        event = Event(event_type="process_create", source="process_monitor", severity="high", risk_score=70)
        session.add(event)
        session.commit()
        session.refresh(event)

        incident = Incident(
            title="Test incident", description="desc", severity="high", risk_score=70, related_event_ids=[event.id]
        )
        session.add(incident)
        session.commit()
        incident_id = incident.id

    resp = client.get(f"/api/v1/incidents/{incident_id}/export", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident"]["title"] == "Test incident"
    assert len(body["events"]) == 1
    assert body["events"][0]["event_type"] == "process_create"


def test_mark_alert_false_positive(client: TestClient, auth_headers, app) -> None:
    with app.state.session_factory() as session:
        alert = Alert(title="Test alert", severity="high", risk_score=70)
        session.add(alert)
        session.commit()
        alert_id = alert.id

    resp = client.post(f"/api/v1/alerts/{alert_id}/false-positive", headers=auth_headers)
    assert resp.status_code == 200

    with app.state.session_factory() as session:
        alert = session.get(Alert, alert_id)
        assert alert.status == "false_positive"


def test_mark_alert_false_positive_unknown_id_404(client: TestClient, auth_headers) -> None:
    resp = client.post("/api/v1/alerts/99999/false-positive", headers=auth_headers)
    assert resp.status_code == 404


def test_mark_incident_false_positive(client: TestClient, auth_headers, app) -> None:
    with app.state.session_factory() as session:
        incident = Incident(title="Test incident", severity="high", risk_score=70, related_event_ids=[])
        session.add(incident)
        session.commit()
        incident_id = incident.id

    resp = client.post(f"/api/v1/incidents/{incident_id}/false-positive", headers=auth_headers)
    assert resp.status_code == 200

    with app.state.session_factory() as session:
        incident = session.get(Incident, incident_id)
        assert incident.status == "false_positive"
