"""URL/behavior detection engine.

Phase 4 adds the risk-score -> severity mapping (detection/risk.py).
The URL heuristics themselves (domain/IP blocklists, TLD/homograph/
redirect checks, a pluggable reputation provider) land in Phase 5.
"""

from detection.risk import severity_for_risk

__all__ = ["severity_for_risk"]
