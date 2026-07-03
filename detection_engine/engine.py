import os
from detection_engine.sigma_loader import load_rule, evaluate_rule
from detection_engine.mitre_mapping import describe

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma-rules")


def load_all_rules(rules_dir: str = RULES_DIR) -> list:
    rules = []
    for fname in sorted(os.listdir(rules_dir)):
        if fname.endswith((".yml", ".yaml")):
            with open(os.path.join(rules_dir, fname)) as f:
                rules.append(load_rule(f.read()))
    return rules


def run_detection(rules: list, events: list) -> list:
    """
    Returns a list of alert dicts, one per (rule, event) match, enriched
    with MITRE ATT&CK context.
    """
    alerts = []
    for event in events:
        for rule in rules:
            if evaluate_rule(rule, event):
                mitre_context = [
                    {**describe(t), "technique_id": t} for t in rule.mitre_techniques
                ]
                alerts.append({
                    "rule_title": rule.title,
                    "rule_id": rule.id,
                    "level": rule.level,
                    "mitre": mitre_context,
                    "event": event,
                })
    return alerts
