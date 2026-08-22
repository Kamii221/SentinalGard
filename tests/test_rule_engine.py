from pathlib import Path

from detection.rule_engine import evaluate_condition_rule, evaluate_condition_rules
from detection.rules_loader import ConditionRule, RuleConditions, load_rules


# --- Loader ---------------------------------------------------------------


def test_load_rules_finds_bundled_starter_rules() -> None:
    rules, scenarios = load_rules()
    assert len(rules) >= 4
    assert len(scenarios) >= 1
    names = {r.name for r in rules}
    assert "Suspicious PowerShell" in names


def test_load_rules_empty_directory_returns_empty_lists(tmp_path: Path) -> None:
    rules, scenarios = load_rules(tmp_path)
    assert rules == []
    assert scenarios == []


def test_load_rules_missing_directory_returns_empty_lists(tmp_path: Path) -> None:
    rules, scenarios = load_rules(tmp_path / "does_not_exist")
    assert rules == []
    assert scenarios == []


def test_load_rules_skips_invalid_yaml(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("not: valid: yaml: [", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        "name: Good Rule\nseverity: low\nconditions:\n  process: cmd.exe\n", encoding="utf-8"
    )
    rules, scenarios = load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].name == "Good Rule"


def test_load_rules_skips_file_missing_required_fields(tmp_path: Path) -> None:
    (tmp_path / "incomplete.yaml").write_text("name: No Conditions Or Steps\nseverity: low\n", encoding="utf-8")
    rules, scenarios = load_rules(tmp_path)
    assert rules == []
    assert scenarios == []


def test_load_rules_skips_disabled_rule(tmp_path: Path) -> None:
    (tmp_path / "disabled.yaml").write_text(
        "name: Disabled Rule\nseverity: low\nenabled: false\nconditions:\n  process: cmd.exe\n", encoding="utf-8"
    )
    rules, scenarios = load_rules(tmp_path)
    assert rules == []


def test_load_rules_distinguishes_scenarios_from_condition_rules(tmp_path: Path) -> None:
    (tmp_path / "scenario.yaml").write_text(
        "name: A Chain\nseverity: high\nsteps:\n  - event_types: [process_create]\n", encoding="utf-8"
    )
    rules, scenarios = load_rules(tmp_path)
    assert rules == []
    assert len(scenarios) == 1
    assert scenarios[0].name == "A Chain"


# --- Condition rule matching -----------------------------------------------


def _rule(**conditions_kwargs) -> ConditionRule:
    return ConditionRule(name="test rule", severity="high", conditions=RuleConditions(**conditions_kwargs))


def test_matches_on_event_type_and_process() -> None:
    rule = _rule(event_type="process_create", process="powershell.exe")
    match = evaluate_condition_rule(
        rule, event_type="process_create", process="powershell.exe", risk_score=0, details={}
    )
    assert match is not None
    assert "test rule" in match.reason


def test_does_not_match_wrong_event_type() -> None:
    rule = _rule(event_type="process_create", process="powershell.exe")
    match = evaluate_condition_rule(
        rule, event_type="network_connection", process="powershell.exe", risk_score=0, details={}
    )
    assert match is None


def test_does_not_match_wrong_process() -> None:
    rule = _rule(process="powershell.exe")
    match = evaluate_condition_rule(rule, event_type="process_create", process="cmd.exe", risk_score=0, details={})
    assert match is None


def test_process_match_is_case_insensitive_substring() -> None:
    rule = _rule(process="powershell.exe")
    match = evaluate_condition_rule(
        rule,
        event_type="process_create",
        process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE",
        risk_score=0,
        details={},
    )
    assert match is not None


def test_indicators_require_at_least_one_hit_in_flattened_details() -> None:
    rule = _rule(indicators=["encodedcommand", "downloadstring"])
    no_match = evaluate_condition_rule(
        rule, event_type="process_create", process=None, risk_score=0, details={"command_line": "notepad.exe"}
    )
    assert no_match is None

    match = evaluate_condition_rule(
        rule,
        event_type="process_create",
        process=None,
        risk_score=0,
        details={"command_line": "powershell -EncodedCommand abc"},
    )
    assert match is not None
    assert "encodedcommand" in match.reason.lower()


def test_indicators_search_nested_details() -> None:
    # Mirrors a real log event's nested `fields` dict.
    rule = _rule(indicators=["downloadstring"])
    match = evaluate_condition_rule(
        rule,
        event_type="powershell_script_block",
        process=None,
        risk_score=0,
        details={"fields": {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString(...)"}},
    )
    assert match is not None


def test_min_risk_gate() -> None:
    rule = _rule(min_risk=50)
    assert evaluate_condition_rule(rule, event_type="x", process=None, risk_score=10, details={}) is None
    assert evaluate_condition_rule(rule, event_type="x", process=None, risk_score=50, details={}) is not None


def test_rule_with_no_conditions_at_all_matches_everything() -> None:
    rule = _rule()
    match = evaluate_condition_rule(rule, event_type="anything", process=None, risk_score=0, details={})
    assert match is not None


def test_evaluate_condition_rules_returns_all_matching_rules() -> None:
    rule_a = ConditionRule(name="rule A", severity="low", conditions=RuleConditions(event_type="process_create"))
    rule_b = ConditionRule(
        name="rule B",
        severity="low",
        conditions=RuleConditions(event_type="process_create", process="powershell.exe"),
    )
    rule_c = ConditionRule(
        name="rule C", severity="low", conditions=RuleConditions(event_type="network_connection")
    )

    matches = evaluate_condition_rules(
        [rule_a, rule_b, rule_c],
        event_type="process_create",
        process="powershell.exe",
        risk_score=0,
        details={},
    )
    assert {m.rule.name for m in matches} == {"rule A", "rule B"}
