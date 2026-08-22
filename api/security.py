"""Shared-secret authentication between the agent and its local clients
(browser extensions, the GUI).

SentinelGuard is not a multi-user service — every process on the machine
can reach 127.0.0.1 — so the agent requires a per-install bearer token
generated on first run and stored with restrictive file permissions.
Clients send it via the ``X-SentinelGuard-Token`` header.
"""

from __future__ import annotations

import secrets
import stat
from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

TOKEN_HEADER_NAME = "X-SentinelGuard-Token"
_TOKEN_BYTES = 32

_api_key_header = APIKeyHeader(name=TOKEN_HEADER_NAME, auto_error=False)


class TokenStore:
    """Owns the on-disk agent token: creation, loading, and rotation."""

    def __init__(self, token_path: Path):
        self._path = token_path

    @property
    def path(self) -> Path:
        return self._path

    def load_or_create(self) -> str:
        if self._path.exists():
            token = self._path.read_text(encoding="utf-8").strip()
            if token:
                return token
        return self._generate_and_store()

    def rotate(self) -> str:
        return self._generate_and_store()

    def verify(self, candidate: str | None) -> bool:
        if not candidate:
            return False
        current = self.load_or_create()
        return secrets.compare_digest(candidate, current)

    def _generate_and_store(self) -> str:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(token, encoding="utf-8")
        try:
            # Owner read/write only. Best-effort: Windows ACLs differ from
            # POSIX mode bits, but this still helps on POSIX dev/test hosts
            # and is a harmless no-op on Windows.
            self._path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return token


def get_token_store(request: Request) -> TokenStore:
    """Dependency: fetch the app-wide TokenStore set up in create_app()."""
    return request.app.state.token_store


def require_agent_token(
    candidate: str | None = Depends(_api_key_header),
    token_store: TokenStore = Depends(get_token_store),
) -> None:
    """Dependency that 401s unless a valid agent token was presented."""
    if not token_store.verify(candidate):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid agent token",
        )
