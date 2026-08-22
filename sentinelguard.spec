# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for SentinelGuard (Phase 13).

Builds a onedir bundle (a folder of an .exe plus its dependencies,
rather than a single self-extracting file) -- the standard choice for
an app that runs a background agent thread and a GUI together, since
onefile's per-launch extraction-to-temp-dir cost isn't a good fit for
something meant to run continuously.

Usage:
    pyinstaller sentinelguard.spec

Output lands in dist/SentinelGuard/. On Windows that's
dist/SentinelGuard/SentinelGuard.exe; this has also been smoke-tested
building on Linux (see README's Packaging section) to confirm the
packaging mechanics -- data files, hidden imports -- work, though the
resulting binary can only really be exercised on Windows, where the
persistence/log-analysis backends this app depends on actually run.
"""

import sys

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# watchdog picks its filesystem-events backend at import time based on
# the platform (inotify/kqueue/ReadDirectoryChangesW/polling); PyInstaller's
# static analysis can't see that branch, so pull in every backend module
# explicitly rather than relying on auto-detection.
hidden_imports = collect_submodules("watchdog.observers")

# pywin32's COM/timezone glue is imported by name at runtime (not via a
# regular `import` statement PyInstaller's analysis can trace). It's a
# Windows-only dependency (requirements.txt marks it
# `sys_platform == "win32"`), so only ask PyInstaller to resolve it when
# building on Windows -- doing so unconditionally breaks a build run on
# any other platform, since the package won't be installed there at all.
if sys.platform == "win32":
    hidden_imports += [
        "win32timezone",
        "win32com.shell",
    ]

datas = [
    ("config/default_config.yaml", "config"),
    ("rules", "rules"),
    ("yara", "yara"),
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Also what Explorer, the taskbar, and Alt-Tab show before the
    # window paints (and thus sets its own icon via
    # gui/main_window.py's setWindowIcon) -- see scripts/generate_icon.py
    # for how this file is produced.
    icon="assets/icon.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SentinelGuard",
)
