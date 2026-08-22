"""URL/file/network/persistence/log/behavior detection engine.

* detection/risk.py -- risk score -> severity band mapping (Phase 4).
* detection/entropy.py -- shared Shannon entropy helper (Phase 5/7).
* detection/lolbins.py -- shared LOLBin process names + suspicious
  command-line keywords (Phase 6/8/9/10).
* detection/indicators.py -- individual local URL heuristics (Phase 5).
* detection/url_analysis.py -- combines URL indicators + reputation
  into one explainable score (Phase 5).
* detection/reputation.py -- pluggable reputation provider interface,
  offline by default (Phase 5).
* detection/file_analysis.py -- local file heuristics: double
  extensions, high-entropy content, known-malicious-hash lookup
  (Phase 7).
* detection/yara_engine.py -- compiles and runs YARA rules from
  yara/, degrading gracefully if unavailable (Phase 7).
* detection/network_analysis.py -- local network-connection
  heuristics: LOLBin network activity, suspicious C2 ports,
  known-malicious-IP lookup (Phase 8).
* detection/persistence_analysis.py -- local persistence-entry
  heuristics: LOLBin commands, suspicious keywords/locations, missing
  targets (Phase 9).
* detection/log_analysis.py -- classification/scoring for normalized
  Windows Event Log records (Phase 10).
"""

from detection.file_analysis import FileAnalysis, analyze_file
from detection.log_analysis import LogEventClassification, classify_log_event
from detection.network_analysis import NetworkAnalysis, analyze_connection
from detection.persistence_analysis import PersistenceAnalysis, analyze_persistence_entry
from detection.reputation import NullReputationProvider, ReputationProvider, get_reputation_provider
from detection.risk import severity_for_risk
from detection.url_analysis import UrlAnalysis, analyze_url
from detection.yara_engine import YaraEngine, YaraMatch

__all__ = [
    "severity_for_risk",
    "analyze_url",
    "UrlAnalysis",
    "analyze_file",
    "FileAnalysis",
    "analyze_connection",
    "NetworkAnalysis",
    "analyze_persistence_entry",
    "PersistenceAnalysis",
    "classify_log_event",
    "LogEventClassification",
    "ReputationProvider",
    "NullReputationProvider",
    "get_reputation_provider",
    "YaraEngine",
    "YaraMatch",
]
