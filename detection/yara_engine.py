"""YARA-based file scanning.

Compiles every ``.yar``/``.yara`` rule file found in a rules directory
once at construction time (never per-scan) and matches newly observed
files against them. A match is a strong, self-documenting signal --
the matched rule's name and ``description``/``severity`` metadata
become the reason directly.

Degrades gracefully rather than breaking file monitoring: if
yara-python isn't installed, or no rule files exist, or a rule file
fails to compile, YaraEngine.scan_file simply returns an empty list
(logging a warning once at startup) instead of raising.
"""

from __future__ import annotations

from pathlib import Path

from agent.logging_setup import get_logger

_log = get_logger("detection.yara")

try:
    import yara  # type: ignore[import-untyped]

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when yara-python is absent
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False


class YaraMatch:
    __slots__ = ("rule", "description", "severity")

    def __init__(self, rule: str, description: str, severity: str) -> None:
        self.rule = rule
        self.description = description
        self.severity = severity


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "yara"


class YaraEngine:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or default_rules_dir()
        self._compiled = None
        if not _YARA_AVAILABLE:
            _log.warning("yara-python is not installed; YARA scanning is disabled")
            return
        self._compiled = self._compile_rules()

    def _compile_rules(self):
        if not self._rules_dir.is_dir():
            _log.info("YARA rules directory %s does not exist; no rules loaded", self._rules_dir)
            return None

        rule_files = sorted(self._rules_dir.glob("*.yar")) + sorted(self._rules_dir.glob("*.yara"))
        if not rule_files:
            _log.info("No YARA rule files found in %s; no rules loaded", self._rules_dir)
            return None

        sources: dict[str, str] = {}
        for path in rule_files:
            try:
                # Validate each file individually so one bad rule doesn't
                # take down every other rule.
                yara.compile(filepath=str(path))
                sources[path.stem] = str(path)
            except yara.Error as exc:
                _log.warning("Skipping invalid YARA rule file %s: %s", path, exc)

        if not sources:
            return None
        try:
            return yara.compile(filepaths=sources)
        except yara.Error as exc:
            _log.warning("Failed to compile combined YARA ruleset: %s", exc)
            return None

    @property
    def available(self) -> bool:
        return self._compiled is not None

    def scan_file(self, path: str) -> list[YaraMatch]:
        if self._compiled is None:
            return []
        try:
            matches = self._compiled.match(filepath=path, timeout=5)
        except yara.Error:
            return []

        results = []
        for m in matches:
            meta = m.meta or {}
            results.append(
                YaraMatch(
                    rule=m.rule,
                    description=str(meta.get("description", m.rule)),
                    severity=str(meta.get("severity", "high")),
                )
            )
        return results
