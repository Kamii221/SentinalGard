"""Time-window correlation across multiple events into incidents.

Baseline matching is time-window + (optional) process-name-substring,
**not** strict PID/causal lineage tracing: true process-to-file/
persistence causality generally needs deeper OS instrumentation (a
filesystem minifilter driver, ETW process-correlated file events)
that's out of scope for a dependency-light v1. Each scenario step asks
"did an event of this type (optionally naming a process) occur at or
after the previous step's matched event, within the scenario's
window?" A match bundles the matched events into one incident instead
of raising N separate alerts -- implementing the spec's own "Office ->
PowerShell -> network -> executable -> persistence = one incident"
example.

A scenario step can opt into something stronger where it's actually
possible: ``require_lineage`` (detection/rules_loader.py). Process
creation and network-connection events both carry a real OS `pid` (see
monitors/process_monitor.py and monitors/network_monitor.py), and
process creation also carries `ppid` -- enough to walk real ancestry
for those two event types, without the deeper instrumentation the
general case would need. A lineage-required step's candidate event
must be the process anchored by the scenario's first lineage step, or
a descendant of it, per that PID/PPID chain -- not just "any event of
the right type and name, anywhere in the window."
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from detection.rules_loader import CorrelationScenario, CorrelationStep

# Hard ceiling on ancestry-chain walking so a corrupted or cyclic
# pid->ppid map (never expected, but this reads directly from
# OS-reported data) can't spin forever.
_MAX_ANCESTRY_DEPTH = 64


@dataclass(frozen=True)
class CorrelationEvent:
    id: int
    event_type: str
    process: str | None
    timestamp: dt.datetime
    # None for event types that don't carry an owning process id
    # (e.g. file_created, persistence_new) -- such events can never
    # satisfy a require_lineage step.
    pid: int | None = None


def is_descendant(pid: int, root_pid: int, ancestry: dict[int, int | None]) -> bool:
    """True if `pid` is `root_pid` itself, or reachable from it by
    walking child -> parent (`ancestry`: pid -> ppid) links."""
    current: int | None = pid
    seen: set[int] = set()
    for _ in range(_MAX_ANCESTRY_DEPTH):
        if current is None:
            return False
        if current == root_pid:
            return True
        if current in seen:
            return False  # cycle in the reported data -- bail out safely
        seen.add(current)
        current = ancestry.get(current)
    return False


@dataclass(frozen=True)
class ScenarioMatch:
    scenario: CorrelationScenario
    matched_event_ids: list[int]
    reason: str


def _step_matches(
    step: CorrelationStep,
    event: CorrelationEvent,
    lineage_root_pid: int | None,
    ancestry: dict[int, int | None],
) -> bool:
    if event.event_type not in step.event_types:
        return False
    if step.process_contains:
        if not event.process:
            return False
        lowered = event.process.lower()
        if not any(p.lower() in lowered for p in step.process_contains):
            return False
    if step.require_lineage:
        if event.pid is None:
            return False
        # The first require_lineage step in the scenario has no root
        # yet -- it *establishes* one (any pid-carrying event that
        # otherwise matches becomes the anchor). Every later
        # require_lineage step must descend from that anchor.
        if lineage_root_pid is not None and not is_descendant(event.pid, lineage_root_pid, ancestry):
            return False
    return True


def _find_scenario_match(
    scenario: CorrelationScenario,
    events_sorted: list[CorrelationEvent],
    ancestry: dict[int, int | None],
) -> ScenarioMatch | None:
    """Greedy earliest-match: for each step in order, take the
    earliest not-yet-used event (at or after the previous step's
    matched timestamp) satisfying that step. All steps must match, and
    the full chain must fit within the scenario's window."""
    used_ids: set[int] = set()
    matched: list[CorrelationEvent] = []
    cursor_time: dt.datetime | None = None
    lineage_root_pid: int | None = None

    for step in scenario.steps:
        found = None
        for event in events_sorted:
            if event.id in used_ids:
                continue
            if cursor_time is not None and event.timestamp < cursor_time:
                continue
            if _step_matches(step, event, lineage_root_pid, ancestry):
                found = event
                break
        if found is None:
            return None
        matched.append(found)
        used_ids.add(found.id)
        cursor_time = found.timestamp
        if step.require_lineage and lineage_root_pid is None:
            lineage_root_pid = found.pid

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
    ancestry: dict[int, int | None] | None = None,
) -> list[ScenarioMatch]:
    """At most one match per scenario per call -- once an event is
    used by a match (in this call or a prior one, via
    already_correlated_ids), it's never reused by another match.

    `ancestry` (pid -> ppid) is only consulted by scenarios with a
    require_lineage step; omit it when none of the loaded scenarios
    use that feature.
    """
    already = already_correlated_ids or set()
    ancestry = ancestry or {}
    available = sorted((e for e in events if e.id not in already), key=lambda e: e.timestamp)

    matches: list[ScenarioMatch] = []
    used: set[int] = set()
    for scenario in scenarios:
        candidates = [e for e in available if e.id not in used]
        match = _find_scenario_match(scenario, candidates, ancestry)
        if match is not None:
            matches.append(match)
            used.update(match.matched_event_ids)
    return matches
