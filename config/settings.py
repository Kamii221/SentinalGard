"""Typed configuration loading for SentinelGuard.

Configuration is a YAML file validated through Pydantic models. The
packaged ``default_config.yaml`` supplies defaults; an optional user
config file (or explicit path) is deep-merged on top of it.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_CONFIG_PATH = _PACKAGE_DIR / "default_config.yaml"


def default_data_dir() -> Path:
    """Return the platform-appropriate default data directory.

    Windows: %APPDATA%\\SentinelGuard
    Other platforms (dev/test): ~/.sentinelguard
    """
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "SentinelGuard"
    return Path.home() / ".sentinelguard"


class AppConfig(BaseModel):
    name: str = "SentinelGuard"
    version: str = "0.1.0"
    environment: str = "production"


class DataConfig(BaseModel):
    data_dir: Optional[Path] = None
    db_filename: str = "sentinelguard.db"
    log_dir: Optional[Path] = None

    def resolved_data_dir(self) -> Path:
        return self.data_dir or default_data_dir()

    def resolved_log_dir(self) -> Path:
        return self.log_dir or (self.resolved_data_dir() / "logs")

    def resolved_db_path(self) -> Path:
        return self.resolved_data_dir() / self.db_filename


class LoggingConfig(BaseModel):
    level: str = "INFO"
    max_bytes: int = Field(default=5_242_880, gt=0)
    backup_count: int = Field(default=5, ge=0)
    console: bool = True

    @field_validator("level")
    @classmethod
    def _valid_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"logging.level must be one of {sorted(allowed)}")
        return upper


class ApiConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _localhost_only(cls, v: str) -> str:
        if v not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(
                "api.host must be a loopback address; SentinelGuard's agent "
                "must never be exposed to the LAN"
            )
        return v


class RetentionConfig(BaseModel):
    events_days: int = Field(default=30, ge=1)
    alerts_days: int = Field(default=90, ge=1)
    network_connections_days: int = Field(default=14, ge=1)
    processes_days: int = Field(default=14, ge=1)
    files_days: int = Field(default=30, ge=1)
    incidents_days: int = Field(default=180, ge=1)


class RiskConfig(BaseModel):
    informational_max: int = Field(default=20, ge=0, le=100)
    low_max: int = Field(default=40, ge=0, le=100)
    medium_max: int = Field(default=60, ge=0, le=100)
    high_max: int = Field(default=80, ge=0, le=100)

    @field_validator("high_max")
    @classmethod
    def _ordered(cls, v: int, info: Any) -> int:
        data = info.data
        thresholds = [
            data.get("informational_max"),
            data.get("low_max"),
            data.get("medium_max"),
            v,
        ]
        if any(t is None for t in thresholds):
            return v
        if thresholds != sorted(thresholds):
            raise ValueError(
                "risk thresholds must be strictly increasing: "
                "informational_max < low_max < medium_max < high_max"
            )
        return v


class MonitoringConfig(BaseModel):
    enabled: bool = True
    process_poll_interval_seconds: float = Field(default=2.0, gt=0)
    # New-process executables larger than this are never hashed (avoids
    # stalling the writer thread on huge binaries).
    process_hash_max_bytes: int = Field(default=25_000_000, gt=0)
    # Same cap, applied to newly observed files in watched directories.
    file_hash_max_bytes: int = Field(default=25_000_000, gt=0)
    # Bytes sampled from the start of a file for entropy scoring --
    # never read the whole file just to estimate entropy.
    file_entropy_sample_bytes: int = Field(default=1_000_000, gt=0)
    # None => auto-detect security-sensitive locations (Downloads,
    # Desktop, Temp, Startup, ...). Set explicitly to override/restrict.
    file_watch_paths: list[str] | None = None
    network_poll_interval_seconds: float = Field(default=3.0, gt=0)
    # Bounded wait for a single reverse-DNS lookup; results are cached
    # by IP so the same destination is never looked up twice.
    network_reverse_dns_timeout_seconds: float = Field(default=1.5, gt=0)
    # Persistence entries (Run keys, services, scheduled tasks, ...)
    # change far less often than processes/connections, so a much
    # longer poll interval is appropriate.
    persistence_poll_interval_seconds: float = Field(default=30.0, gt=0)
    # Windows Event Log channels aren't as time-critical as live
    # process/network activity but are more so than persistence.
    log_poll_interval_seconds: float = Field(default=15.0, gt=0)
    # How often the rule/correlation engine re-scans recent events.
    correlation_poll_interval_seconds: float = Field(default=10.0, gt=0)
    # How far back correlation scenarios look for their steps to have
    # all occurred -- a rolling window, not a fixed lookback from now.
    correlation_window_minutes: float = Field(default=15.0, gt=0)
    # Retention pruning (database/retention.py) is cheap and doesn't
    # need to run often -- once a day is plenty for a personal machine.
    retention_prune_interval_hours: float = Field(default=24.0, gt=0)


class ResponseConfig(BaseModel):
    # None => <data_dir>/quarantine. See config.settings.resolved_quarantine_dir.
    quarantine_dir: Optional[str] = None


def resolved_quarantine_dir(settings: "Settings") -> Path:
    if settings.response.quarantine_dir:
        return Path(settings.response.quarantine_dir)
    return settings.data.resolved_data_dir() / "quarantine"


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    data: DataConfig = Field(default_factory=DataConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)


__all__ = [
    "AppConfig",
    "DataConfig",
    "LoggingConfig",
    "ApiConfig",
    "RetentionConfig",
    "RiskConfig",
    "MonitoringConfig",
    "ResponseConfig",
    "Settings",
    "default_data_dir",
    "resolved_quarantine_dir",
    "load_settings",
    "get_settings",
]


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data or {}


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """Load settings from the packaged defaults, merged with an optional
    user config file.

    Resolution order for the user config file when ``config_path`` is not
    given: ``%APPDATA%/SentinelGuard/config.yaml`` (or
    ``~/.sentinelguard/config.yaml``) if it exists, otherwise defaults only.
    """
    merged = _load_yaml(_DEFAULT_CONFIG_PATH)

    user_path = config_path or (default_data_dir() / "config.yaml")
    if user_path.exists():
        merged = _deep_merge(merged, _load_yaml(user_path))

    return Settings.model_validate(merged)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached process-wide settings singleton."""
    return load_settings()
