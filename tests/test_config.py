from pathlib import Path

import pytest

from config.settings import Settings, default_data_dir, load_settings


def test_default_settings_load() -> None:
    settings = load_settings()
    assert settings.app.name == "SentinelGuard"
    assert settings.api.host == "127.0.0.1"
    assert settings.api.port == 8765


def test_api_host_rejects_non_loopback() -> None:
    with pytest.raises(ValueError):
        Settings.model_validate({"api": {"host": "0.0.0.0"}})


def test_risk_thresholds_must_be_increasing() -> None:
    with pytest.raises(ValueError):
        Settings.model_validate(
            {"risk": {"informational_max": 50, "low_max": 40, "medium_max": 60, "high_max": 80}}
        )


def test_user_config_overrides_defaults(tmp_path: Path) -> None:
    user_config = tmp_path / "config.yaml"
    user_config.write_text("api:\n  port: 9999\n", encoding="utf-8")

    settings = load_settings(user_config)

    assert settings.api.port == 9999
    # Untouched sections still come from the packaged defaults.
    assert settings.app.name == "SentinelGuard"


def test_resolved_paths_are_absolute(tmp_path: Path) -> None:
    settings = load_settings()
    settings.data.data_dir = tmp_path
    assert settings.data.resolved_db_path() == tmp_path / "sentinelguard.db"
    assert settings.data.resolved_log_dir() == tmp_path / "logs"


def test_default_data_dir_is_nonempty() -> None:
    assert str(default_data_dir())
