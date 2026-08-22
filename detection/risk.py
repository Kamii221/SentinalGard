"""Risk score -> severity band mapping.

::

    0-20   Informational
    21-40  Low
    41-60  Medium
    61-80  High
    81-100 Critical

The full URL/behavior heuristics that *produce* a risk score land in
Phase 5+; this module only defines the score-to-band mapping shared by
every part of the app that stores a severity.
"""

from __future__ import annotations

from typing import Literal

from config.settings import RiskConfig

Severity = Literal["informational", "low", "medium", "high", "critical"]


def severity_for_risk(risk: int, risk_config: RiskConfig) -> Severity:
    if risk <= risk_config.informational_max:
        return "informational"
    if risk <= risk_config.low_max:
        return "low"
    if risk <= risk_config.medium_max:
        return "medium"
    if risk <= risk_config.high_max:
        return "high"
    return "critical"


def severity_floor(severity: Severity, risk_config: RiskConfig) -> int:
    """The minimum risk score consistent with a severity band -- the
    inverse of severity_for_risk. Used when a YAML rule/scenario
    declares a severity directly and that needs to become a risk
    score floor for the resulting Alert/Incident."""
    if severity == "informational":
        return 0
    if severity == "low":
        return risk_config.informational_max + 1
    if severity == "medium":
        return risk_config.low_max + 1
    if severity == "high":
        return risk_config.medium_max + 1
    return risk_config.high_max + 1  # critical
