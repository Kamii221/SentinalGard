"""Time-window correlation across multiple events into incidents.

Honestly scoped as time-window + (optional) process-name-substring
correlation, **not** strict PID/causal lineage tracing: true
process-to-file/persistence causality needs deeper OS instrumentation
(a filesystem minifilter driver, ETW process-correlated file events)
that's out of scope for a dependency-light v1. Each scenario step asks
"did an event of this type (optionally naming a process) occur at or
after the previous step's matched event, within the scenario's
window?" A match bundles the matched events into one incident instead
of raising N separate alerts -- implementing the spec's own "Office ->
PowerShell -> network -> executable -> persistence = one incident"
example.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from detection.rules_loader import CorrelationScenario, CorrelationStep


@dataclass(frozen=True)
class CorrelationEvent:
    id: int
    event_type: str
    process: str | None
    timestamp: dt.datetime


@dataclass(frozen=True)
class ScenarioMatch:
    scenario: CorrelationScenario
    matched_event_ids: list[int]
    reason: str


def _step_matches(step: CorrelationStep, event: CorrelationEvent) -> bool:
    if event.event_type not in step.event_types:
        return False
    if step.process_contains:
        if not event.process:
            return False
        lowered = event.process.lower()
        if not any(p.lower() in lowered for p in step.process_contains):
            return False
    return True


def _find_scenario_match(scenario: CorrelationScenario, events_sorted: list[CorrelationEvent]) -> ScenarioMatch | None:
    """Greedy earliest-match: for each step in order, take the
    earliest not-yet-used event (at or after the previous step's
    matched timestamp) satisfying that step. All steps must match, and
    the full chain must fit within the scenario's window."""
    used_ids: set[int] = set()
    matched: list[CorrelationEvent] = []
    cursor_time: dt.datetime | None = None

    for step in scenario.steps:
        found = None
        for event in events_sorted:
            if event.id in used_ids:
                continue
            if cursor_time is not None and event.timestamp < cursor_time:
                continue
            if _step_matches(step, event):
                found = event
                break
        if found is None:
            return None
        matched.append(found)
        used_ids.add(found.id)
        cursor_time = found.timestamp

    window = dt.timedelta(minutes=scenario.window_minutes)
    if matched[-1].timestamp - matched[0].timestamp > window:
        return None

    chain = " -> ".join(f"{e.event_type}" + (f" ({e.process})" if e.process else "") for e in matched)
    reason = f"Matched correlation scenario '{scenario.name}': {chain}"
    return ScenarioMatch(scenario=scenario, matched_event_ids=[e.id for e in matched], reason=reason)


def find_scenario_matches(
    scenarios: list[CorrelationScenario],
    events: list[CorrelationEvent],
    already_correlated_ids: set[int] | None = None,
) -> list[ScenarioMatch]:
    """At most one match per scenario per call -- once an event is
    used by a match (in this call or a prior one, via
    already_correlated_ids), it's never reused by another match."""
    already = already_correlated_ids or set()
    available = sorted((e for e in events if e.id not in already), key=lambda e: e.timestamp)

    matches: list[ScenarioMatch] = []
    used: set[int] = set()
    for scenario in scenarios:
        candidates = [e for e in available if e.id not in used]
        match = _find_scenario_match(scenario, candidates)
        if match is not None:
            matches.append(match)
            used.update(match.matched_event_ids)
    return matches
