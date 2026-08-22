"""SentinelGuard entrypoint.

Bootstraps configuration, logging, and the SQLite schema. Pass --serve
to start the local FastAPI agent (loopback only) in the foreground, or
--gui to launch the desktop app (which starts the agent on a background
thread and connects to it like any other local client).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent.logging_setup import get_logger, setup_logging
from agent.server import run_agent
from config.settings import load_settings
from database.engine import init_db


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="sentinelguard", description="SentinelGuard")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to a YAML config file (defaults to the platform config location)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--serve",
        action="store_true",
        help="Start the local FastAPI agent (loopback only) after bootstrapping",
    )
    mode.add_argument(
        "--gui",
        action="store_true",
        help="Launch the desktop GUI (also starts the local agent in the background)",
    )
    return parser.parse_args(argv)


def bootstrap(config_path: Path | None = None, serve: bool = False, gui: bool = False) -> int:
    settings = load_settings(config_path)
    setup_logging(settings)
    log = get_logger("main")

    log.info("Starting %s v%s", settings.app.name, settings.app.version)
    log.info("Data directory: %s", settings.data.resolved_data_dir())
    log.info("Database path: %s", settings.data.resolved_db_path())

    init_db(settings)
    log.info("Database schema initialized")

    if gui:
        # Imported lazily so `--serve`/bootstrap-only usage never requires
        # PySide6 to be installed.
        from gui.app import run_gui

        return run_gui(settings)

    if serve:
        run_agent(settings)
    else:
        log.info(
            "Bootstrap complete. Pass --serve to start the local agent, "
            "or --gui to launch the desktop app."
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return bootstrap(args.config, args.serve, args.gui)


if __name__ == "__main__":
    sys.exit(main())
