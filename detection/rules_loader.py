"""Loads YAML detection rules from a rules directory.

Two rule shapes live side by side in the same directory, told apart by
which top-level key is present:

* ``conditions:`` -- a single-event condition rule (the spec's own
  example format, unchanged):

  .. code-block:: yaml

      name: Suspicious PowerShell
      severity: high
      conditions:
        process: powershell.exe
        indicators:
          - encodedcommand
          - downloadstring
          - invoke-webrequest

  ``conditions`` fields double as the spec's process/command-line/
  file/network/URL/persistence "rule types": which domain a rule
  covers is expressed by ``event_type`` (e.g. ``process_create``,
  ``file_created``, ``network_connection``, ``website_check``,
  ``persistence_new``) plus ``process``/``indicators``, not by a
  separate schema per type.

* ``steps:`` -- a multi-event correlation scenario (the spec's
  "Event correlation" rule type):

  .. code-block:: yaml

      name: Office document spawns PowerShell, then persists
      severity: critical
      window_minutes: 15
      steps:
        - event_types: [process_create]
          process_contains: [winword.exe, excel.exe, outlook.exe]
        - event_types: [process_create]
          process_contains: [powershell.exe, pwsh.exe]
        - event_types: [network_connection]
        - event_types: [persistence_new]

Every rule file is validated independently; an invalid file is
skipped with a logged warning rather than breaking every other rule --
same defensive pattern as Phase 7's YARA rule loading.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

from agent.logging_setup import get_logger

_log = get_logger("detection.rules")

Severity = Literal["informational", "low", "medium", "high", "critical"]


class AutoResponseAction(BaseModel):
    """Opt-in automatic remediation for a condition rule match.

    Off by default at two levels, deliberately: this field is absent
    unless a rule author explicitly adds it, *and*
    ``response.auto_response_enabled`` (config/settings.py) has to be
    turned on globally before any rule's ``auto_response`` block does
    anything -- a rule file alone can never make the agent start taking
    destructive action. ``min_severity`` is an extra gate on top of the
    rule's own severity, so a rule can fire (and alert) at a lower bar
    than the one that triggers automatic remediation.
    """

    action: Literal["kill_process", "quarantine_file", "disable_persistence"]
    min_severity: Severity = "critical"


class ConditionRule(BaseModel):
    name: str
    severity: Severity = "medium"
    enabled: bool = True
    conditions: "RuleConditions"
    # Purely informational tag (e.g. "T1059.001") surfaced in the
    # resulting Alert's details -- not matched against, just carried
    # through for analyst-facing categorization.
    mitre_technique: str | None = None
    auto_response: AutoResponseAction | None = None
    source_file: str = ""


class RuleConditions(BaseModel):
    event_type: list[str] | str | None = None
    process: str | None = None
    indicators: list[str] = Field(default_factory=list)
    min_risk: int = Field(default=0, ge=0, le=100)

    def event_types(self) -> list[str] | None:
        if self.event_type is None:
            return None
        return [self.event_type] if isinstance(self.event_type, str) else self.event_type


ConditionRule.model_rebuild()


class CorrelationStep(BaseModel):
    event_types: list[str] = Field(min_length=1)
    process_contains: list[str] = Field(default_factory=list)
    # Opt-in tightening beyond time-window + name-substring matching
    # (see detection/correlation_engine.py's module docstring for why
    # that's the scenario-wide default): when true, this step's
    # candidate event must be the *same process lineage* as the first
    # require_lineage step in the scenario -- the same process, or a
    # descendant of it, per real PID/PPID ancestry -- not just "some
    # event of the right type and name, anywhere in the time window."
    # Only meaningful for event types that carry a `pid` in their
    # details (process_create, network_connection currently); a step
    # requiring lineage can never match an event with no pid.
    require_lineage: bool = False


class CorrelationScenario(BaseModel):
    name: str
    severity: Severity = "high"
    enabled: bool = True
    window_minutes: float = Field(default=15.0, gt=0)
    steps: list[CorrelationStep] = Field(min_length=1)
    mitre_technique: str | None = None
    source_file: str = ""


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def load_rules(rules_dir: Path | None = None) -> tuple[list[ConditionRule], list[CorrelationScenario]]:
    """Load and validate every .yaml/.yml file in rules_dir.

    Returns (condition_rules, correlation_scenarios), each filtered to
    only the enabled ones. Missing directory or no rule files -> two
    empty lists, not an error.
    """
    directory = rules_dir or default_rules_dir()
    if not directory.is_dir():
        _log.info("Rules directory %s does not exist; no rules loaded", directory)
        return [], []

    condition_rules: list[ConditionRule] = []
    scenarios: list[CorrelationScenario] = []

    rule_files = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
    for path in rule_files:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            _log.warning("Skipping invalid YAML in rule file %s: %s", path, exc)
            continue
        if not isinstance(raw, dict):
            _log.warning("Skipping rule file %s: expected a YAML mapping at the top level", path)
            continue

        try:
            if "steps" in raw:
                scenario = CorrelationScenario.model_validate({**raw, "source_file": path.name})
                if scenario.enabled:
                    scenarios.append(scenario)
            elif "conditions" in raw:
                rule = ConditionRule.model_validate({**raw, "source_file": path.name})
                if rule.enabled:
                    condition_rules.append(rule)
            else:
                _log.warning("Skipping rule file %s: has neither 'conditions' nor 'steps'", path)
        except ValidationError as exc:
            _log.warning("Skipping invalid rule file %s: %s", path, exc)

    return condition_rules, scenarios
