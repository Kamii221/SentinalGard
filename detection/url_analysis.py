"""Combine local heuristics (+ an optional reputation provider) into a
single explainable risk score.

Nothing here ever claims a URL is malicious from one weak signal --
each indicator only contributes points, and the final severity band
comes from the shared thresholds in detection/risk.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from config.settings import RiskConfig
from detection.indicators import ALL_INDICATORS
from detection.reputation import ReputationProvider, get_reputation_provider
from detection.risk import Severity, severity_for_risk


@dataclass(frozen=True)
class UrlAnalysis:
    risk: int
    severity: Severity
    reasons: list[str]


def analyze_url(
    url: str, risk_config: RiskConfig, reputation_provider: ReputationProvider | None = None
) -> UrlAnalysis:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    score = 0
    reasons: list[str] = []

    for indicator_fn in ALL_INDICATORS:
        finding = indicator_fn(url, parsed, hostname)
        if finding is not None:
            score += finding.points
            reasons.append(finding.reason)

    provider = reputation_provider or get_reputation_provider()
    rep_result = provider.lookup(hostname) if hostname else None
    if rep_result is not None:
        score += rep_result.score_contribution
        reasons.append(f"{rep_result.reason} (source: {rep_result.provider})")

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No detection")

    return UrlAnalysis(risk=score, severity=severity_for_risk(score, risk_config), reasons=reasons)
