"""
Run: python scripts/run_detection_demo.py
Loads all Sigma rules, runs them against the synthetic event set, and
prints alerts with MITRE ATT&CK context.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engine.engine import load_all_rules, run_detection
from detection_engine.log_simulator import get_sample_events


def main():
    rules = load_all_rules()
    events = get_sample_events()
    alerts = run_detection(rules, events)

    print(f"Loaded {len(rules)} Sigma rules, evaluated against {len(events)} events.\n")
    print(f"{len(alerts)} alert(s) generated:\n")

    for a in alerts:
        print(f"[{a['level'].upper()}] {a['rule_title']}")
        for m in a["mitre"]:
            print(f"    MITRE ATT&CK: {m['technique_id']} — {m['name']} (Tactic: {m['tactic']})")
        print(f"    Triggering event: {a['event']}\n")


if __name__ == "__main__":
    main()
