"""Local, offline network-connection heuristics.

Mirrors detection/url_analysis.py and detection/file_analysis.py's
design: independent signals each contribute points to an explainable
0-100 score. A known-malicious-IP blocklist match short-circuits
straight to a high score -- same precedence pattern used for domains
and file hashes (the same blocklist table, entry_type="ip").

Deliberately does NOT score "no reverse DNS record" as suspicious: a
large fraction of legitimate internet destinations (CDNs, cloud
providers, ...) have no PTR record, so that would be pure noise, not
an explainable signal -- exactly the kind of weak heuristic the spec
warns against overclaiming from.
"""

from __future__ import annotations

from dataclasses import dataclass

from config.settings import RiskConfig
from detection.lolbins import LOLBIN_PROCESS_NAMES
from detection.risk import Severity, severity_for_risk

# Ports historically associated with common malware/backdoor/C2
# tooling defaults (e.g. Metasploit's 4444). Not exhaustive, and
# plenty of legitimate traffic can use high ports too -- this only
# ever contributes points, never a verdict on its own.
_SUSPICIOUS_PORTS = frozenset({4444, 1337, 6666, 6667, 31337, 12345, 54321})


@dataclass(frozen=True)
class NetworkFinding:
    points: int
    reason: str


def check_lolbin_network_activity(process_name: str | None) -> NetworkFinding | None:
    if process_name and process_name.lower() in LOLBIN_PROCESS_NAMES:
        return NetworkFinding(
            35,
            f"'{process_name}' is a commonly abused Windows utility making an outbound network "
            "connection -- unusual for legitimate use",
        )
    return None


def check_suspicious_port(port: int | None) -> NetworkFinding | None:
    if port in _SUSPICIOUS_PORTS:
        return NetworkFinding(25, f"Destination port {port} is commonly associated with malware C2/backdoors")
    return None


@dataclass(frozen=True)
class NetworkAnalysis:
    risk: int
    severity: Severity
    reasons: list[str]
    known_malicious: bool


def analyze_connection(
    *,
    process_name: str | None,
    remote_port: int | None,
    domain: str | None,
    known_malicious_ip: bool,
    risk_config: RiskConfig,
) -> NetworkAnalysis:
    if known_malicious_ip:
        risk = 95
        reasons = ["Destination IP is on your blocklist"]
        return NetworkAnalysis(
            risk=risk, severity=severity_for_risk(risk, risk_config), reasons=reasons, known_malicious=True
        )

    score = 0
    reasons: list[str] = []

    for finding in (
        check_lolbin_network_activity(process_name),
        check_suspicious_port(remote_port),
    ):
        if finding is not None:
            score += finding.points
            reasons.append(finding.reason)

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No detection")

    return NetworkAnalysis(
        risk=score, severity=severity_for_risk(score, risk_config), reasons=reasons, known_malicious=False
    )
