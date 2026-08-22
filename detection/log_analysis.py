"""Classification/scoring for normalized Windows Event Log records.

Each supported (channel, Event ID) pair maps to a classifier that
turns the event's raw field dict into the common normalized shape
(process/user/severity/risk/reasons). Mirrors the other
detection/*_analysis.py modules: independent, explainable signals.
The one exception to "never claim malicious from a weak heuristic" is
Windows Defender's own detections (1116/1117) -- that's already a
vendor AV engine's verdict, not a local heuristic guess, so it's
scored high directly.

Correlating these events with everything else (the "PowerShell ->
network -> persistence" example from the spec) is Phase 11's job, not
this module's -- this only classifies one event at a time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from config.settings import RiskConfig
from detection.lolbins import SUSPICIOUS_CMDLINE_KEYWORDS
from detection.risk import Severity, severity_for_risk

# channel -> event IDs this analyzer knows how to classify.
CHANNEL_EVENT_IDS: dict[str, tuple[int, ...]] = {
    "Security": (4688, 4625, 4672, 4720, 4732),
    "System": (7045, 7040),
    "Microsoft-Windows-PowerShell/Operational": (4104,),
    "Microsoft-Windows-Windows Defender/Operational": (1116, 1117),
}


@dataclass(frozen=True)
class LogEventClassification:
    event_type: str
    process: str | None
    user: str | None
    risk: int
    severity: Severity
    reasons: list[str]


def _suspicious_keyword_hits(text: str) -> list[str]:
    lowered = text.lower()
    return [kw.strip() for kw in SUSPICIOUS_CMDLINE_KEYWORDS if kw in lowered]


def classify_process_creation_4688(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    process = fields.get("NewProcessName")
    user = fields.get("SubjectUserName")
    cmdline = fields.get("ProcessCommandLine") or ""

    risk = 0
    reasons: list[str] = []
    hits = _suspicious_keyword_hits(cmdline)
    if hits:
        risk += 30
        reasons.append(f"Command line contains suspicious indicators ({', '.join(hits)})")
    if not reasons:
        reasons.append("No detection")

    return LogEventClassification(
        "security_process_creation", process, user, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_logon_failed_4625(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    user = fields.get("TargetUserName")
    risk = 10
    reasons = ["Failed logon attempt"]
    return LogEventClassification(
        "security_logon_failed", None, user, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_privileged_logon_4672(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    user = fields.get("SubjectUserName")
    risk = 15
    reasons = ["Logon was assigned special/administrative privileges"]
    return LogEventClassification(
        "security_privileged_logon", None, user, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_account_created_4720(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    user = fields.get("TargetUserName")
    risk = 25
    reasons = ["A new user account was created"]
    return LogEventClassification(
        "security_account_created", None, user, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_group_membership_change_4732(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    member = fields.get("MemberName")
    group = fields.get("TargetUserName") or "a security group"
    risk = 25
    reasons = [f"Account added to '{group}' -- a security-sensitive group membership change"]
    return LogEventClassification(
        "security_group_membership_change", None, member, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_service_installed_7045(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    process = fields.get("ImagePath")
    name = fields.get("ServiceName", "unknown")
    risk = 20
    reasons = [f"A new service was installed ('{name}')"]
    return LogEventClassification(
        "system_service_installed", process, None, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_service_start_type_changed_7040(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    risk = 10
    reasons = ["A service's start type was changed"]
    return LogEventClassification(
        "system_service_start_type_changed", None, None, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_powershell_script_block_4104(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    script = fields.get("ScriptBlockText") or ""
    risk = 0
    reasons: list[str] = []
    hits = _suspicious_keyword_hits(script)
    if hits:
        risk = 40
        reasons.append(f"Script block contains suspicious indicators ({', '.join(hits)})")
    if not reasons:
        reasons.append("No detection")
    return LogEventClassification(
        "powershell_script_block", "powershell.exe", None, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_defender_threat_detected_1116(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    threat = fields.get("Threat Name") or fields.get("ThreatName") or "unknown threat"
    risk = 85
    reasons = [f"Windows Defender detected a threat: {threat}"]
    return LogEventClassification(
        "defender_threat_detected", None, None, risk, severity_for_risk(risk, risk_config), reasons
    )


def classify_defender_threat_action_1117(fields: dict, risk_config: RiskConfig) -> LogEventClassification:
    threat = fields.get("Threat Name") or fields.get("ThreatName") or "unknown threat"
    action = fields.get("Action Name") or fields.get("ActionName") or "unknown action"
    risk = 80
    reasons = [f"Windows Defender took action on a threat: {threat} ({action})"]
    return LogEventClassification(
        "defender_threat_action", None, None, risk, severity_for_risk(risk, risk_config), reasons
    )


_CLASSIFIERS: dict[int, Callable[[dict, RiskConfig], LogEventClassification]] = {
    4688: classify_process_creation_4688,
    4625: classify_logon_failed_4625,
    4672: classify_privileged_logon_4672,
    4720: classify_account_created_4720,
    4732: classify_group_membership_change_4732,
    7045: classify_service_installed_7045,
    7040: classify_service_start_type_changed_7040,
    4104: classify_powershell_script_block_4104,
    1116: classify_defender_threat_detected_1116,
    1117: classify_defender_threat_action_1117,
}


def classify_log_event(event_id: int, fields: dict, risk_config: RiskConfig) -> LogEventClassification | None:
    """None means this event ID isn't one we know how to classify."""
    classifier = _CLASSIFIERS.get(event_id)
    if classifier is None:
        return None
    return classifier(fields, risk_config)
