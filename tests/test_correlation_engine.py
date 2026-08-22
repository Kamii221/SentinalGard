import datetime as dt

from detection.correlation_engine import CorrelationEvent, find_scenario_matches
from detection.rules_loader import CorrelationScenario, CorrelationStep

_T0 = dt.datetime(2026, 8, 22, 13, 0, 0)


def _minutes(n: int) -> dt.datetime:
    return _T0 + dt.timedelta(minutes=n)


def _office_powershell_scenario(window_minutes: float = 15.0) -> CorrelationScenario:
    return CorrelationScenario(
        name="Office -> PowerShell -> network -> file -> persistence",
        severity="critical",
        window_minutes=window_minutes,
        steps=[
            CorrelationStep(event_types=["process_create"], process_contains=["winword.exe"]),
            CorrelationStep(event_types=["process_create"], process_contains=["powershell.exe"]),
            CorrelationStep(event_types=["network_connection"]),
            CorrelationStep(event_types=["file_created"]),
            CorrelationStep(event_types=["persistence_new"]),
        ],
    )


def test_full_chain_matches_the_spec_example() -> None:
    events = [
        CorrelationEvent(1, "process_create", "WINWORD.EXE", _minutes(0)),
        CorrelationEvent(2, "process_create", "powershell.exe", _minutes(1)),
        CorrelationEvent(3, "network_connection", "powershell.exe", _minutes(2)),
        CorrelationEvent(4, "file_created", None, _minutes(3)),
        CorrelationEvent(5, "persistence_new", None, _minutes(4)),
    ]
    matches = find_scenario_matches([_office_powershell_scenario()], events)
    assert len(matches) == 1
    assert matches[0].matched_event_ids == [1, 2, 3, 4, 5]
    assert "Office" in matches[0].scenario.name


def test_missing_a_step_does_not_match() -> None:
    events = [
        CorrelationEvent(1, "process_create", "WINWORD.EXE", _minutes(0)),
        CorrelationEvent(2, "process_create", "powershell.exe", _minutes(1)),
        CorrelationEvent(3, "network_connection", "powershell.exe", _minutes(2)),
        # no file_created, no persistence_new
    ]
    matches = find_scenario_matches([_office_powershell_scenario()], events)
    assert matches == []


def test_steps_out_of_order_do_not_match() -> None:
    events = [
        CorrelationEvent(1, "network_connection", "powershell.exe", _minutes(0)),
        CorrelationEvent(2, "process_create", "WINWORD.EXE", _minutes(1)),
        CorrelationEvent(3, "process_create", "powershell.exe", _minutes(2)),
        CorrelationEvent(4, "file_created", None, _minutes(3)),
        CorrelationEvent(5, "persistence_new", None, _minutes(4)),
    ]
    # The network connection happens *before* Word and PowerShell even
    # start -- not a valid instance of this chain.
    matches = find_scenario_matches([_office_powershell_scenario()], events)
    assert matches == []


def test_chain_spanning_longer_than_window_does_not_match() -> None:
    events = [
        CorrelationEvent(1, "process_create", "WINWORD.EXE", _minutes(0)),
        CorrelationEvent(2, "process_create", "powershell.exe", _minutes(1)),
        CorrelationEvent(3, "network_connection", "powershell.exe", _minutes(2)),
        CorrelationEvent(4, "file_created", None, _minutes(3)),
        CorrelationEvent(5, "persistence_new", None, _minutes(20)),  # 20 min later
    ]
    matches = find_scenario_matches([_office_powershell_scenario(window_minutes=15.0)], events)
    assert matches == []


def test_unrelated_events_are_ignored() -> None:
    events = [
        CorrelationEvent(1, "process_create", "notepad.exe", _minutes(0)),
        CorrelationEvent(2, "website_check", None, _minutes(1)),
        CorrelationEvent(3, "process_create", "WINWORD.EXE", _minutes(2)),
        CorrelationEvent(4, "process_create", "powershell.exe", _minutes(3)),
        CorrelationEvent(5, "network_connection", "powershell.exe", _minutes(4)),
        CorrelationEvent(6, "file_created", None, _minutes(5)),
        CorrelationEvent(7, "persistence_new", None, _minutes(6)),
    ]
    matches = find_scenario_matches([_office_powershell_scenario()], events)
    assert len(matches) == 1
    assert matches[0].matched_event_ids == [3, 4, 5, 6, 7]


def test_already_correlated_events_are_never_reused() -> None:
    events = [
        CorrelationEvent(1, "process_create", "WINWORD.EXE", _minutes(0)),
        CorrelationEvent(2, "process_create", "powershell.exe", _minutes(1)),
        CorrelationEvent(3, "network_connection", "powershell.exe", _minutes(2)),
        CorrelationEvent(4, "file_created", None, _minutes(3)),
        CorrelationEvent(5, "persistence_new", None, _minutes(4)),
    ]
    # Simulate that event 3 was already consumed by an earlier match.
    matches = find_scenario_matches([_office_powershell_scenario()], events, already_correlated_ids={3})
    assert matches == []


def test_process_contains_is_case_insensitive() -> None:
    scenario = CorrelationScenario(
        name="case test",
        steps=[CorrelationStep(event_types=["process_create"], process_contains=["powershell.exe"])],
    )
    events = [CorrelationEvent(1, "process_create", "POWERSHELL.EXE", _minutes(0))]
    matches = find_scenario_matches([scenario], events)
    assert len(matches) == 1


def test_step_without_process_contains_matches_any_process() -> None:
    scenario = CorrelationScenario(name="any process", steps=[CorrelationStep(event_types=["network_connection"])])
    events = [CorrelationEvent(1, "network_connection", "totally_unrelated.exe", _minutes(0))]
    matches = find_scenario_matches([scenario], events)
    assert len(matches) == 1


def test_multiple_scenarios_do_not_double_use_the_same_event() -> None:
    shared_event = CorrelationEvent(1, "network_connection", "powershell.exe", _minutes(0))
    scenario_a = CorrelationScenario(name="A", steps=[CorrelationStep(event_types=["network_connection"])])
    scenario_b = CorrelationScenario(name="B", steps=[CorrelationStep(event_types=["network_connection"])])

    matches = find_scenario_matches([scenario_a, scenario_b], [shared_event])
    assert len(matches) == 1  # only the first scenario gets the single available event
