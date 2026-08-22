"""Matches single events against user-editable YAML condition rules.

A rule's ``conditions`` are ANDed together: every condition present on
the rule must match for the rule to fire. All matching is a pure
function of an event's already-normalized fields (event_type,
process, risk_score, details) -- no DB access here, which keeps this
trivially unit-testable and reusable from both the correlation monitor
and tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from detection.rules_loader import ConditionRule


def _flatten_text(details: dict[str, Any]) -> str:
    """Flatten every string value in a details dict (including nested
    dicts/lists, e.g. a log event's `fields`) into one lowercase blob
    for substring matching."""
    parts: list[str] = []

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _walk(v)

    _walk(details)
    return " ".join(parts).lower()


@dataclass(frozen=True)
class RuleMatch:
    rule: ConditionRule
    reason: str


def evaluate_condition_rule(
    rule: ConditionRule,
    *,
    event_type: str,
    process: str | None,
    risk_score: int,
    details: dict[str, Any],
) -> RuleMatch | None:
    conditions = rule.conditions

    event_types = conditions.event_types()
    if event_types is not None and event_type not in event_types:
        return None

    if conditions.process is not None:
        if not process or conditions.process.lower() not in process.lower():
            return None

    if risk_score < conditions.min_risk:
        return None

    matched_indicators: list[str] = []
    if conditions.indicators:
        blob = _flatten_text(details)
        matched_indicators = [ind for ind in conditions.indicators if ind.lower() in blob]
        if not matched_indicators:
            return None

    reason_parts = [f"Matched rule '{rule.name}'"]
    if conditions.process is not None:
        reason_parts.append(f"process contains '{conditions.process}'")
    if matched_indicators:
        reason_parts.append(f"indicators found: {', '.join(matched_indicators)}")
    reason = "; ".join(reason_parts)

    return RuleMatch(rule=rule, reason=reason)


def evaluate_condition_rules(
    rules: list[ConditionRule],
    *,
    event_type: str,
    process: str | None,
    risk_score: int,
    details: dict[str, Any],
) -> list[RuleMatch]:
    matches = []
    for rule in rules:
        match = evaluate_condition_rule(
            rule, event_type=event_type, process=process, risk_score=risk_score, details=details
        )
        if match is not None:
            matches.append(match)
    return matches
