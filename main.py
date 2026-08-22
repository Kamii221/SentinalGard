"""SentinelGuard entrypoint.

Phase 1 responsibilities only: load configuration, set up logging, and
initialize the SQLite schema. The FastAPI agent and PySide6 GUI are
wired in from Phase 2 onward.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent.logging_setup import get_logger, setup_logging
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
    return parser.parse_args(argv)


def bootstrap(config_path: Path | None = None) -> int:
    settings = load_settings(config_path)
    logger = setup_logging(settings)
    log = get_logger("main")

    log.info("Starting %s v%s", settings.app.name, settings.app.version)
    log.info("Data directory: %s", settings.data.resolved_data_dir())
    log.info("Database path: %s", settings.data.resolved_db_path())

    init_db(settings)
    log.info("Database schema initialized")

    log.info(
        "Phase 1 bootstrap complete. API/GUI are not started yet "
        "(implemented in later phases)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return bootstrap(args.config)


if __name__ == "__main__":
    sys.exit(main())
