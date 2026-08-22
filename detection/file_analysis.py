"""Local, offline file heuristics for newly observed executable/script/DLL files.

Mirrors detection/url_analysis.py's design: independent signals each
contribute points to an explainable 0-100 score. A known-malicious-hash
match short-circuits straight to a high score -- same precedence
pattern as the website blocklist: an explicit match is decisive and
skips the rest of the heuristics.

Callers are expected to have already filtered to TRACKED_EXTENSIONS
before invoking analyze_file -- this module never scans/reads a file
itself, it only scores metadata and a caller-supplied content sample.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from config.settings import RiskConfig
from detection.entropy import shannon_entropy
from detection.risk import Severity, severity_for_risk

EXECUTABLE_EXTENSIONS = frozenset({".exe", ".msi", ".scr", ".jar", ".apk"})
SCRIPT_EXTENSIONS = frozenset({".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".wsf", ".hta"})
DLL_EXTENSIONS = frozenset({".dll"})
TRACKED_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | DLL_EXTENSIONS

_DOCUMENT_LOOKALIKE_EXTENSIONS = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip"}
)
_DOUBLE_EXTENSION_TRIGGERS = frozenset(
    {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".msi"}
)

_HIGH_ENTROPY_THRESHOLD = 7.5

_CATEGORY_BASE_POINTS = {"executable": 10, "script": 10, "dll": 5}


def file_category(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in EXECUTABLE_EXTENSIONS:
        return "executable"
    if suffix in SCRIPT_EXTENSIONS:
        return "script"
    if suffix in DLL_EXTENSIONS:
        return "dll"
    return None


@dataclass(frozen=True)
class FileFinding:
    points: int
    reason: str


def check_double_extension(path: Path) -> FileFinding | None:
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) < 2:
        return None
    if suffixes[-1] not in _DOUBLE_EXTENSION_TRIGGERS:
        return None
    if suffixes[-2] not in _DOCUMENT_LOOKALIKE_EXTENSIONS:
        return None
    return FileFinding(
        20,
        f"Filename disguises itself as a document but is really an executable "
        f"('{path.name}') -- a common malware delivery trick",
    )


def check_high_entropy(sample: bytes) -> FileFinding | None:
    if not sample:
        return None
    entropy = shannon_entropy(sample)
    if entropy < _HIGH_ENTROPY_THRESHOLD:
        return None
    return FileFinding(
        20,
        f"File content has very high entropy ({entropy:.2f}/8.0) -- consistent with packed, "
        "encrypted, or obfuscated code",
    )


@dataclass(frozen=True)
class FileAnalysis:
    risk: int
    severity: Severity
    reasons: list[str]
    known_malicious: bool


def analyze_file(
    *,
    path: Path,
    event_type: str,  # "created" | "modified"
    sample: bytes | None,
    known_malicious_hash: bool,
    risk_config: RiskConfig,
) -> FileAnalysis:
    if known_malicious_hash:
        risk = 95
        reasons = ["File hash matches a known-malicious entry on your blocklist"]
        return FileAnalysis(
            risk=risk, severity=severity_for_risk(risk, risk_config), reasons=reasons, known_malicious=True
        )

    score = 0
    reasons: list[str] = []

    category = file_category(path)
    if category is not None:
        verb = "created" if event_type == "created" else "modified"
        score += _CATEGORY_BASE_POINTS[category]
        reasons.append(f"New {category} file {verb} in a monitored location ({path.name})")

    if event_type == "modified":
        score += 15
        reasons.append(
            "An existing tracked file was modified -- unexpected changes to executables/scripts are unusual"
        )

    finding = check_double_extension(path)
    if finding is not None:
        score += finding.points
        reasons.append(finding.reason)

    if sample is not None:
        finding = check_high_entropy(sample)
        if finding is not None:
            score += finding.points
            reasons.append(finding.reason)

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No detection")

    return FileAnalysis(
        risk=score, severity=severity_for_risk(score, risk_config), reasons=reasons, known_malicious=False
    )
