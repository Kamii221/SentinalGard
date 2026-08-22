"""Shared file hashing/sampling helpers for monitors.

Never hashes a file larger than ``max_bytes``, and never raises -- I/O
errors (permission denied, file vanished mid-read, etc.) just result
in ``None``, which is the correct behavior for best-effort monitoring.
"""

from __future__ import annotations

import hashlib
import os


def hash_file(path: str, max_bytes: int) -> str | None:
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def read_sample(path: str, max_bytes: int) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return None
