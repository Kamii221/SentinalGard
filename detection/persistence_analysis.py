"""Local, offline persistence-entry heuristics.

Mirrors the other detection/*_analysis.py modules: independent
signals each contribute points to an explainable 0-100 score. There's
no exact-match blocklist short-circuit here the way there is for a
domain/hash/IP -- a persistence entry doesn't have one obvious unique
key to look up -- so this always runs the full heuristic combination.
"""

from __future__ import annotations

from dataclasses import dataclass

from config.settings import RiskConfig
from detection.lolbins import LOLBIN_PROCESS_NAMES, SUSPICIOUS_CMDLINE_KEYWORDS
from detection.risk import Severity, severity_for_risk

_SUSPICIOUS_PATH_FRAGMENTS = (
    "\\temp\\", "\\tmp\\", "/tmp/", "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\",
)


@dataclass(frozen=True)
class PersistenceFinding:
    points: int
    reason: str


def check_lolbin_command(command: str | None) -> PersistenceFinding | None:
    if not command:
        return None
    lowered = command.lower()
    for name in LOLBIN_PROCESS_NAMES:
        if name in lowered:
            return PersistenceFinding(25, f"Persistence entry runs '{name}', a commonly abused Windows utility")
    return None


def check_suspicious_command_keywords(command: str | None) -> PersistenceFinding | None:
    if not command:
        return None
    lowered = command.lower()
    hits = [kw.strip() for kw in SUSPICIOUS_CMDLINE_KEYWORDS if kw in lowered]
    if hits:
        return PersistenceFinding(30, f"Command contains suspicious indicators ({', '.join(hits)})")
    return None


def check_suspicious_location(command: str | None) -> PersistenceFinding | None:
    if not command:
        return None
    lowered = command.lower()
    for fragment in _SUSPICIOUS_PATH_FRAGMENTS:
        if fragment in lowered:
            return PersistenceFinding(
                20, "Persistence entry runs from a commonly-abused temporary/downloads location"
            )
    return None


def check_missing_target(target_exists: bool | None) -> PersistenceFinding | None:
    if target_exists is False:
        return PersistenceFinding(10, "Target executable referenced by this entry no longer exists on disk")
    return None


@dataclass(frozen=True)
class PersistenceAnalysis:
    risk: int
    severity: Severity
    reasons: list[str]


def analyze_persistence_entry(
    *, command: str | None, target_exists: bool | None, risk_config: RiskConfig
) -> PersistenceAnalysis:
    score = 0
    reasons: list[str] = []

    for finding in (
        check_lolbin_command(command),
        check_suspicious_command_keywords(command),
        check_suspicious_location(command),
        check_missing_target(target_exists),
    ):
        if finding is not None:
            score += finding.points
            reasons.append(finding.reason)

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No detection")

    return PersistenceAnalysis(risk=score, severity=severity_for_risk(score, risk_config), reasons=reasons)
