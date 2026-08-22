from pathlib import Path

import pytest

import main
from config.settings import load_settings


def test_parse_args_defaults() -> None:
    args = main.parse_args([])
    assert args.config is None
    assert args.serve is False
    assert args.gui is False


def test_parse_args_serve() -> None:
    args = main.parse_args(["--serve"])
    assert args.serve is True
    assert args.gui is False


def test_parse_args_gui() -> None:
    args = main.parse_args(["--gui"])
    assert args.gui is True
    assert args.serve is False


def test_parse_args_config_path() -> None:
    args = main.parse_args(["--config", "/tmp/custom.yaml"])
    assert args.config == Path("/tmp/custom.yaml")


def test_parse_args_rejects_serve_and_gui_together() -> None:
    # --serve and --gui are mutually exclusive: bootstrap only knows how
    # to run one mode at a time.
    with pytest.raises(SystemExit):
        main.parse_args(["--serve", "--gui"])


@pytest.fixture()
def stub_settings(tmp_path: Path, monkeypatch):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.monitoring.enabled = False

    def _load_settings(config_path=None):
        return settings

    monkeypatch.setattr(main, "load_settings", _load_settings)
    return settings


def test_bootstrap_without_serve_or_gui_just_initializes(stub_settings) -> None:
    result = main.bootstrap()
    assert result == 0
    # Bootstrap-only mode should have created the schema without starting
    # the agent or the GUI.
    assert stub_settings.data.resolved_db_path().exists()


def test_bootstrap_serve_runs_the_agent(stub_settings, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(main, "run_agent", lambda settings: calls.append(settings))

    result = main.bootstrap(serve=True)

    assert result == 0
    assert calls == [stub_settings]


def test_bootstrap_gui_runs_the_gui_and_returns_its_exit_code(stub_settings, monkeypatch) -> None:
    calls = []

    def _run_gui(settings):
        calls.append(settings)
        return 7

    # bootstrap() imports gui.app lazily inside the function body, so the
    # patch target is the real module, not main's namespace.
    monkeypatch.setattr("gui.app.run_gui", _run_gui)

    result = main.bootstrap(gui=True)

    assert result == 7
    assert calls == [stub_settings]


def test_main_dispatches_parsed_args_to_bootstrap(monkeypatch) -> None:
    captured = {}

    def _bootstrap(config_path, serve, gui):
        captured["args"] = (config_path, serve, gui)
        return 0

    monkeypatch.setattr(main, "bootstrap", _bootstrap)

    result = main.main(["--serve"])

    assert result == 0
    assert captured["args"] == (None, True, False)
