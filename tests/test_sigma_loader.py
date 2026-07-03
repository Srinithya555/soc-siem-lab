import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engine.sigma_loader import load_rule, evaluate_rule

SIMPLE_RULE_YAML = """
title: Test Rule
id: test-1
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: 'whoami'
  condition: selection
level: medium
tags:
  - attack.t1059.003
"""

OR_RULE_YAML = """
title: OR Test Rule
id: test-2
logsource:
  category: process_creation
detection:
  block_a:
    CommandLine|contains: 'foo'
  block_b:
    CommandLine|contains: 'bar'
  condition: block_a or block_b
level: low
"""

NOT_RULE_YAML = """
title: NOT Test Rule
id: test-3
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'powershell'
  filter:
    CommandLine|contains: 'Get-Help'
  condition: selection and not filter
level: low
"""

LIST_VALUE_RULE_YAML = """
title: List Value Test
id: test-4
logsource:
  category: process_creation
detection:
  selection:
    ParentImage:
      - 'explorer.exe'
      - 'cmd.exe'
  condition: selection
level: low
"""


class TestRuleLoading:
    def test_loads_title_and_id(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        assert rule.title == "Test Rule"
        assert rule.id == "test-1"

    def test_extracts_mitre_technique_from_tags(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        assert rule.mitre_techniques == ["T1059.003"]

    def test_condition_string_extracted(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        assert rule.condition == "selection"

    def test_detection_blocks_exclude_condition_key(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        assert "condition" not in rule.detection
        assert "selection" in rule.detection


class TestFieldMatching:
    def test_endswith_and_contains_and_condition(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        match_event = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c whoami"}
        no_match_event = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c dir"}
        assert evaluate_rule(rule, match_event) is True
        assert evaluate_rule(rule, no_match_event) is False

    def test_missing_field_does_not_match(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        assert evaluate_rule(rule, {"Image": r"C:\cmd.exe"}) is False  # no CommandLine field at all

    def test_list_value_or_semantics(self):
        rule = load_rule(LIST_VALUE_RULE_YAML)
        assert evaluate_rule(rule, {"ParentImage": "explorer.exe"}) is True
        assert evaluate_rule(rule, {"ParentImage": "cmd.exe"}) is True
        assert evaluate_rule(rule, {"ParentImage": "svchost.exe"}) is False

    def test_case_insensitive_matching(self):
        rule = load_rule(SIMPLE_RULE_YAML)
        event = {"Image": r"C:\CMD.EXE", "CommandLine": "CMD.EXE /c WHOAMI"}
        assert evaluate_rule(rule, event) is True


class TestConditionLogic:
    def test_or_condition(self):
        rule = load_rule(OR_RULE_YAML)
        assert evaluate_rule(rule, {"CommandLine": "run foo now"}) is True
        assert evaluate_rule(rule, {"CommandLine": "run bar now"}) is True
        assert evaluate_rule(rule, {"CommandLine": "run baz now"}) is False

    def test_and_not_condition(self):
        rule = load_rule(NOT_RULE_YAML)
        assert evaluate_rule(rule, {"CommandLine": "powershell.exe -Command Get-Process"}) is True
        assert evaluate_rule(rule, {"CommandLine": "powershell.exe Get-Help"}) is False  # excluded by filter
        assert evaluate_rule(rule, {"CommandLine": "cmd.exe /c dir"}) is False  # doesn't match selection at all

    def test_unknown_block_name_in_condition_raises(self):
        bad_yaml = """
title: Bad Rule
id: bad-1
detection:
  selection:
    Foo: bar
  condition: selection and nonexistent_block
"""
        rule = load_rule(bad_yaml)
        try:
            evaluate_rule(rule, {"Foo": "bar"})
            assert False, "expected ValueError for unknown block name"
        except ValueError:
            pass
