"""Regenerate assets/icon.ico from gui/icon.py's drawn shield.

Run this after changing the shield's design in gui/icon.py -- the
window/taskbar/tray icon picks up gui.icon.build_app_icon() directly at
runtime, but the .exe's own icon (baked in by sentinelguard.spec) and
the installer's icon (installer/sentinelguard.iss) are static files
that need to be regenerated and re-committed.

Needs Pillow (not a runtime dependency of the app itself -- only this
one-off build step needs it):
    pip install Pillow
    python scripts/generate_icon.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.icon import render_icon_pixmap  # noqa: E402

_SIZES = (16, 24, 32, 48, 64, 128, 256)
_OUTPUT = Path(__file__).resolve().parent.parent / "assets" / "icon.ico"


def main() -> None:
    QApplication.instance() or QApplication([])

    with tempfile.TemporaryDirectory() as tmp:
        png_paths = []
        for size in _SIZES:
            path = Path(tmp) / f"icon_{size}.png"
            render_icon_pixmap(size).save(str(path), "PNG")
            png_paths.append(path)

        images = [Image.open(p) for p in png_paths]
        largest = images[-1]
        _OUTPUT.parent.mkdir(exist_ok=True)
        largest.save(_OUTPUT, format="ICO", sizes=[(s, s) for s in _SIZES], append_images=images[:-1])

    print(f"Wrote {_OUTPUT}")


if __name__ == "__main__":
    main()
