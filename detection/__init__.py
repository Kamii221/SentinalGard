"""URL/behavior detection engine.

* detection/risk.py -- risk score -> severity band mapping (Phase 4).
* detection/indicators.py -- individual local URL heuristics (Phase 5).
* detection/url_analysis.py -- combines indicators + reputation into
  one explainable score (Phase 5).
* detection/reputation.py -- pluggable reputation provider interface,
  offline by default (Phase 5).
"""

from detection.reputation import NullReputationProvider, ReputationProvider, get_reputation_provider
from detection.risk import severity_for_risk
from detection.url_analysis import UrlAnalysis, analyze_url

__all__ = [
    "severity_for_risk",
    "analyze_url",
    "UrlAnalysis",
    "ReputationProvider",
    "NullReputationProvider",
    "get_reputation_provider",
]
