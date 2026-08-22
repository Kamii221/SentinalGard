import os

# Must be set before PySide6.QtWidgets is imported anywhere, so this lives
# in conftest.py to run at collection time, ahead of any test module import.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
