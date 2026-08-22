"""Logging configuration for SentinelGuard.

All application logging goes through the ``sentinelguard`` logger
hierarchy so it can be configured once here and used via
``logging.getLogger(__name__)`` everywhere else.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config.settings import Settings

LOGGER_NAME = "sentinelguard"

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(settings: Settings) -> logging.Logger:
    """Configure and return the root SentinelGuard logger.

    Idempotent: calling this more than once replaces existing handlers
    instead of stacking duplicates.
    """
    log_dir = settings.data.resolved_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "sentinelguard.log"

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(settings.logging.level)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=settings.logging.max_bytes,
        backupCount=settings.logging.backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if settings.logging.console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``sentinelguard`` hierarchy."""
    if name == LOGGER_NAME or name.startswith(f"{LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")
