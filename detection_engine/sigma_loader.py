"""
Loads and evaluates Sigma detection rules against normalized log events.

Sigma (https://github.com/SigmaHQ/sigma) is the real, widely-used
generic signature format for SIEM detections — rules written in Sigma
get compiled to Splunk SPL, Elastic KQL/EQL, Wazuh rules, etc. via the
`sigma-cli`/`pySigma` toolchain. This module implements a genuine,
documented SUBSET of Sigma's detection logic directly in Python — useful
for fast local testing of rule logic without needing a full SIEM backend
running, same "test the logic in isolation" philosophy as every other
project in this portfolio.

WHAT'S SUPPORTED (real Sigma subset):
  - detection.<blockname>: field-value selection blocks
  - field: value                      (exact match)
  - field: [v1, v2]                   (OR match against a list)
  - field|contains: substring
  - field|startswith: prefix
  - field|endswith: suffix
  - field|re: regex
  - detection.condition: boolean expression over block names using
    "and", "or", "not", and parentheses, e.g. "selection and not filter"

WHAT'S NOT SUPPORTED (real Sigma features intentionally out of scope):
  - Aggregation functions (count() by, near, timeframe)
  - "1 of selection*" / "all of them" wildcard block references
  - Field name modifiers beyond contains/startswith/endswith/re
  - Correlation rules (Sigma's newer multi-rule correlation format)

This is documented honestly rather than claiming full Sigma
compatibility — see README "Known limitations." For production use, the
actual `pySigma` library (with backends for your real SIEM) is what you'd
compile these rules with; this evaluator exists for fast local rule-logic
testing during rule development.
"""
import re
import yaml
from dataclasses import dataclass


@dataclass
class SigmaRule:
    id: str
    title: str
    description: str
    logsource: dict
    detection: dict
    condition: str
    level: str
    mitre_techniques: list
    raw: dict


def load_rule(yaml_text: str) -> SigmaRule:
    data = yaml.safe_load(yaml_text)
    tags = data.get("tags", [])
    mitre_techniques = [
        t.replace("attack.", "").upper()
        for t in tags if t.startswith("attack.t")
    ]
    detection = data.get("detection", {})
    condition = detection.get("condition", "")
    return SigmaRule(
        id=data.get("id", ""),
        title=data.get("title", ""),
        description=data.get("description", ""),
        logsource=data.get("logsource", {}),
        detection={k: v for k, v in detection.items() if k != "condition"},
        condition=condition,
        level=data.get("level", "medium"),
        mitre_techniques=mitre_techniques,
        raw=data,
    )


def load_rules_from_directory(rules: list) -> list:
    """Takes a list of raw YAML strings (one per rule) and returns SigmaRule objects."""
    return [load_rule(text) for text in rules]


def _field_matches(event: dict, field_spec: str, expected) -> bool:
    if "|" in field_spec:
        field, modifier = field_spec.split("|", 1)
    else:
        field, modifier = field_spec, None

    actual = event.get(field)
    if actual is None:
        return False
    actual_str = str(actual)

    if modifier == "contains":
        return _match_any(expected, lambda v: str(v).lower() in actual_str.lower())
    if modifier == "startswith":
        return _match_any(expected, lambda v: actual_str.lower().startswith(str(v).lower()))
    if modifier == "endswith":
        return _match_any(expected, lambda v: actual_str.lower().endswith(str(v).lower()))
    if modifier == "re":
        return _match_any(expected, lambda v: re.search(str(v), actual_str) is not None)

    # Plain equality (or OR-match against a list)
    return _match_any(expected, lambda v: str(v).lower() == actual_str.lower())


def _match_any(expected, predicate) -> bool:
    if isinstance(expected, list):
        return any(predicate(v) for v in expected)
    return predicate(expected)


def _evaluate_selection_block(event: dict, block: dict) -> bool:
    """All field specs within one selection block are AND-ed together —
    this matches real Sigma semantics for a single mapping block."""
    return all(_field_matches(event, field_spec, expected) for field_spec, expected in block.items())


def _evaluate_condition(condition: str, block_results: dict) -> bool:
    """
    Evaluates a Sigma condition string like "selection and not filter"
    against a dict of {block_name: bool}. Implemented as a restricted,
    safe expression evaluation: block names are substituted with their
    boolean values, then only 'and'/'or'/'not'/parentheses are permitted
    — no arbitrary code execution risk, since the only tokens accepted
    are boolean literals and logical keywords.
    """
    tokens = re.findall(r"\(|\)|\bnot\b|\band\b|\bor\b|[A-Za-z_][A-Za-z0-9_]*", condition)
    substituted = []
    allowed_keywords = {"and", "or", "not", "(", ")"}
    for tok in tokens:
        if tok in allowed_keywords:
            substituted.append(tok)
        elif tok in block_results:
            substituted.append("True" if block_results[tok] else "False")
        else:
            raise ValueError(f"Unknown block name '{tok}' in condition '{condition}'")
    expr = " ".join(substituted)
    # Safe: expr contains only True/False/and/or/not/parentheses by this point.
    return eval(expr, {"__builtins__": {}}, {})


def evaluate_rule(rule: SigmaRule, event: dict) -> bool:
    block_results = {
        name: _evaluate_selection_block(event, block)
        for name, block in rule.detection.items()
    }
    return _evaluate_condition(rule.condition, block_results)


def run_rules(rules: list, events: list) -> list:
    """Returns a list of {rule, event} matches."""
    matches = []
    for event in events:
        for rule in rules:
            if evaluate_rule(rule, event):
                matches.append({"rule": rule, "event": event})
    return matches
