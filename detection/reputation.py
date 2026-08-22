"""Pluggable reputation provider interface.

No provider is active by default -- SentinelGuard works fully offline
out of the box, and per the privacy requirement it must never upload
browsing data without explicit user configuration. A provider (e.g. a
threat-intel API) can be added later by implementing this Protocol and
wiring it into ``get_reputation_provider``; until then
``NullReputationProvider`` always returns "no data" and never makes a
network call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ReputationResult:
    known_malicious: bool
    score_contribution: int  # 0-100, added to the local heuristic score
    reason: str
    provider: str


class ReputationProvider(Protocol):
    name: str

    def lookup(self, domain: str) -> ReputationResult | None:
        """Return a result, or None if the provider has no data for this domain."""
        ...


class NullReputationProvider:
    """Default provider: always offline, always returns no data."""

    name = "none"

    def lookup(self, domain: str) -> ReputationResult | None:
        return None


def get_reputation_provider() -> ReputationProvider:
    """Return the active reputation provider.

    Always the offline null provider for now; a future phase can make
    this configurable once a real provider exists to plug in.
    """
    return NullReputationProvider()
