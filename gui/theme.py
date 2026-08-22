"""Dark stylesheet for the SentinelGuard desktop GUI."""

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #11151c;
    color: #e6e9ef;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QListWidget#sidebar {
    background-color: #0b0e13;
    border: none;
    border-right: 1px solid #1c2531;
    padding-top: 12px;
    outline: none;
}

QListWidget#sidebar::item {
    padding: 10px 16px;
    color: #9aa4b2;
    border-left: 3px solid transparent;
}

QListWidget#sidebar::item:selected {
    background-color: #1c2531;
    color: #ffffff;
    border-left: 3px solid #4f8cff;
}

QListWidget#sidebar::item:hover:!selected {
    background-color: #161b24;
}

QFrame#statCard {
    background-color: #1a212c;
    border: 1px solid #232c3a;
    border-radius: 8px;
}

QLabel#statTitle {
    color: #9aa4b2;
    font-size: 12px;
}

QLabel#statValue {
    color: #ffffff;
    font-size: 26px;
    font-weight: 600;
}

QLabel#protectionStatus {
    font-size: 16px;
    font-weight: 600;
    color: #4fd1a5;
    padding-bottom: 8px;
}

QLabel#placeholderTitle {
    font-size: 20px;
    font-weight: 600;
    color: #e6e9ef;
}

QLabel#placeholderNote {
    color: #9aa4b2;
}

QStatusBar {
    background-color: #0b0e13;
    color: #9aa4b2;
    border-top: 1px solid #1c2531;
}
"""
