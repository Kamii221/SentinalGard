import datetime as dt
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app import create_app
from api.security import TOKEN_HEADER_NAME
from config.settings import load_settings
from database.models import AllowlistEntry, BlocklistEntry


@pytest.fixture()
def app_settings(tmp_path: Path):
    settings = load_settings()
    settings.data.data_dir = tmp_path
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


def _status(client: TestClient, auth_headers: dict[str, str]) -> dict:
    return client.get("/api/v1/status", headers=auth_headers).json()


def test_check_requires_token(client: TestClient) -> None:
    resp = client.post("/api/v1/websites/check", json={"url": "https://example.com", "browser": "chrome"})
    assert resp.status_code == 401


def test_check_default_allow_no_detection(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.post(
        "/api/v1/websites/check",
        json={"url": "https://Example.COM/page", "browser": "chrome"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"action": "allow", "risk": 0, "reason": "No detection"}


def test_check_persists_website_and_increments_status(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    before = _status(client, auth_headers)
    client.post(
        "/api/v1/websites/check",
        json={"url": "https://example.com", "browser": "firefox"},
        headers=auth_headers,
    )
    after = _status(client, auth_headers)
    assert after["websites_scanned"] == before["websites_scanned"] + 1


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "javascript:alert(1)",
        "not a url",
        "http://",
    ],
)
def test_check_rejects_invalid_urls(client: TestClient, auth_headers: dict[str, str], url: str) -> None:
    resp = client.post("/api/v1/websites/check", json={"url": url, "browser": "chrome"}, headers=auth_headers)
    assert resp.status_code == 422


def test_check_rejects_invalid_browser(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.post(
        "/api/v1/websites/check",
        json={"url": "https://example.com", "browser": "safari"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_lookup_does_not_log_a_website(client: TestClient, auth_headers: dict[str, str]) -> None:
    before = _status(client, auth_headers)
    for _ in range(3):
        resp = client.get(
            "/api/v1/websites/lookup",
            params={"url": "https://example.com"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
    after = _status(client, auth_headers)
    assert after["websites_scanned"] == before["websites_scanned"]


def test_lookup_rejects_invalid_url(client: TestClient, auth_headers: dict[str, str]) -> None:
    resp = client.get("/api/v1/websites/lookup", params={"url": "ftp://bad"}, headers=auth_headers)
    assert resp.status_code == 422


def test_always_block_then_check_returns_block(client: TestClient, auth_headers: dict[str, str]) -> None:
    decision_resp = client.post(
        "/api/v1/websites/decision",
        json={"url": "https://evil.example", "browser": "chrome", "decision": "always_block"},
        headers=auth_headers,
    )
    assert decision_resp.status_code == 200
    assert "evil.example" in decision_resp.json()["applied"]

    check_resp = client.post(
        "/api/v1/websites/check",
        json={"url": "https://evil.example/path", "browser": "chrome"},
        headers=auth_headers,
    )
    body = check_resp.json()
    assert body["action"] == "block"
    assert body["risk"] == 95


def test_always_allow_overrides_always_block(client: TestClient, app, auth_headers: dict[str, str]) -> None:
    client.post(
        "/api/v1/websites/decision",
        json={"url": "https://flip.example", "browser": "chrome", "decision": "always_block"},
        headers=auth_headers,
    )
    client.post(
        "/api/v1/websites/decision",
        json={"url": "https://flip.example", "browser": "chrome", "decision": "always_allow"},
        headers=auth_headers,
    )

    check_resp = client.post(
        "/api/v1/websites/check",
        json={"url": "https://flip.example", "browser": "chrome"},
        headers=auth_headers,
    )
    assert check_resp.json()["action"] == "allow"

    with app.state.session_factory() as session:
        assert session.execute(
            select(BlocklistEntry).where(BlocklistEntry.value == "flip.example")
        ).scalars().first() is None
        assert session.execute(
            select(AllowlistEntry).where(AllowlistEntry.value == "flip.example")
        ).scalars().first() is not None


def test_allow_once_expires(client: TestClient, app, auth_headers: dict[str, str]) -> None:
    client.post(
        "/api/v1/websites/decision",
        json={"url": "https://temp.example", "browser": "chrome", "decision": "allow_once"},
        headers=auth_headers,
    )

    fresh_check = client.post(
        "/api/v1/websites/check",
        json={"url": "https://temp.example", "browser": "chrome"},
        headers=auth_headers,
    )
    assert fresh_check.json()["action"] == "allow_once"

    # Force the grant into the past to simulate expiry.
    with app.state.session_factory() as session:
        entry = session.execute(
            select(AllowlistEntry).where(AllowlistEntry.value == "temp.example")
        ).scalars().one()
        entry.expires_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(minutes=1)
        session.commit()

    expired_check = client.post(
        "/api/v1/websites/check",
        json={"url": "https://temp.example", "browser": "chrome"},
        headers=auth_headers,
    )
    assert expired_check.json() == {"action": "allow", "risk": 0, "reason": "No detection"}


def test_block_decision_does_not_create_list_entry(
    client: TestClient, app, auth_headers: dict[str, str]
) -> None:
    resp = client.post(
        "/api/v1/websites/decision",
        json={"url": "https://oneoff.example", "browser": "chrome", "decision": "block"},
        headers=auth_headers,
    )
    assert resp.status_code == 200

    with app.state.session_factory() as session:
        assert session.execute(
            select(BlocklistEntry).where(BlocklistEntry.value == "oneoff.example")
        ).scalars().first() is None
        assert session.execute(
            select(AllowlistEntry).where(AllowlistEntry.value == "oneoff.example")
        ).scalars().first() is None
