"""Thin HTTP client the GUI uses to talk to the local agent.

Deliberately does not touch the SQLite file directly: the agent is the
single writer, and going through its API keeps the GUI on the same
contract browser extensions use, with no risk of a second process
opening conflicting SQLite connections.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from api.security import TOKEN_HEADER_NAME
from config.settings import Settings


class AgentClientError(RuntimeError):
    """Raised when the agent is unreachable or rejects a request."""


class AgentClient:
    def __init__(self, settings: Settings, timeout: float = 3.0) -> None:
        self._base_url = f"http://{settings.api.host}:{settings.api.port}/api/v1"
        self._token_path: Path = settings.data.resolved_data_dir() / "agent_token"
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        try:
            token = self._token_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AgentClientError(f"Agent token not found at {self._token_path}") from exc
        return {TOKEN_HEADER_NAME: token}

    def health(self) -> dict[str, Any]:
        try:
            resp = httpx.get(f"{self._base_url}/health", timeout=self._timeout)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AgentClientError(str(exc)) from exc
        return resp.json()

    def status(self) -> dict[str, Any]:
        try:
            resp = httpx.get(
                f"{self._base_url}/status", headers=self._headers(), timeout=self._timeout
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise AgentClientError(str(exc)) from exc
        return resp.json()
