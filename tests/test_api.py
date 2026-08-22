from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.security import TOKEN_HEADER_NAME
from config.settings import load_settings


@pytest.fixture()
def app_settings(tmp_path: Path):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    return settings


@pytest.fixture()
def client(app_settings) -> TestClient:
    app = create_app(app_settings)
    # httpx's ASGITransport defaults the simulated peer to "testclient";
    # override it to a loopback address so LoopbackOnlyMiddleware behaves
    # the same as it would against a real local client.
    return TestClient(app, client=("127.0.0.1", 12345))


@pytest.fixture()
def token(client: TestClient, app_settings) -> str:
    # Depends on `client` so the app (and thus the token file) exists.
    return app_settings.data.resolved_data_dir().joinpath("agent_token").read_text().strip()


def test_health_is_unauthenticated(client: TestClient) -> None:
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["app"] == "SentinelGuard"


def test_status_requires_token(client: TestClient) -> None:
    resp = client.get("/api/v1/status")
    assert resp.status_code == 401


def test_status_rejects_wrong_token(client: TestClient) -> None:
    resp = client.get("/api/v1/status", headers={TOKEN_HEADER_NAME: "not-the-real-token"})
    assert resp.status_code == 401


def test_status_accepts_valid_token(client: TestClient, token: str) -> None:
    resp = client.get("/api/v1/status", headers={TOKEN_HEADER_NAME: token})
    assert resp.status_code == 200
    body = resp.json()
    assert body["protection_status"] == "active"
    assert body["websites_scanned"] == 0
    assert body["uptime_seconds"] >= 0


def test_token_rotation_invalidates_old_token(client: TestClient, token: str) -> None:
    resp = client.post("/api/v1/auth/rotate-token", headers={TOKEN_HEADER_NAME: token})
    assert resp.status_code == 200
    new_token = resp.json()["new_token"]
    assert new_token != token

    # Old token no longer works.
    stale = client.get("/api/v1/status", headers={TOKEN_HEADER_NAME: token})
    assert stale.status_code == 401

    # New token works.
    fresh = client.get("/api/v1/status", headers={TOKEN_HEADER_NAME: new_token})
    assert fresh.status_code == 200


def test_rotate_token_requires_current_token(client: TestClient) -> None:
    resp = client.post("/api/v1/auth/rotate-token")
    assert resp.status_code == 401


def test_token_file_has_restricted_permissions(app_settings, token: str) -> None:
    import stat
    import sys

    token_path = app_settings.data.resolved_data_dir() / "agent_token"
    if sys.platform != "win32":
        mode = stat.S_IMODE(token_path.stat().st_mode)
        assert mode == stat.S_IRUSR | stat.S_IWUSR


def test_non_loopback_client_is_rejected(app_settings) -> None:
    app = create_app(app_settings)
    remote_client = TestClient(app, client=("203.0.113.5", 54321))
    resp = remote_client.get("/api/v1/health")
    assert resp.status_code == 403
