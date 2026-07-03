import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engine.engine import load_all_rules, run_detection
from detection_engine.log_simulator import get_sample_events


class TestEngineIntegration:
    def test_loads_all_five_rule_files(self):
        rules = load_all_rules()
        assert len(rules) == 5

    def test_every_malicious_sample_event_is_detected(self):
        """
        This is the coverage guarantee: every event in log_simulator.py
        labeled 'malicious' must be caught by its expected rule. If this
        test ever fails after a rule edit, it means a real rule
        regression — a detection that used to fire no longer does.
        """
        rules = load_all_rules()
        events = get_sample_events()
        alerts = run_detection(rules, events)
        detected_titles = {a["rule_title"] for a in alerts}

        malicious_events = [e for e in events if e.get("_label") == "malicious"]
        for e in malicious_events:
            assert e["_expected_rule"] in detected_titles, \
                f"Expected detection '{e['_expected_rule']}' did not fire for event: {e}"

    def test_no_false_positives_on_benign_events(self):
        """
        Equally important as catching attacks: a detection engine that
        fires on legitimate activity trains analysts to ignore alerts.
        """
        rules = load_all_rules()
        events = get_sample_events()
        alerts = run_detection(rules, events)

        benign_events = [e for e in events if e.get("_label") == "benign"]
        for alert in alerts:
            assert alert["event"] not in benign_events, \
                f"False positive: '{alert['rule_title']}' fired on a benign event"

    def test_alerts_include_mitre_context(self):
        rules = load_all_rules()
        events = get_sample_events()
        alerts = run_detection(rules, events)
        assert len(alerts) > 0
        for alert in alerts:
            assert len(alert["mitre"]) > 0
            for m in alert["mitre"]:
                assert m["technique_id"].startswith("T")
                assert m["tactic"] != "Unknown"  # every rule here maps to a real, known technique

    def test_alert_count_is_stable(self):
        """Pins the expected alert count — catches accidental rule regressions."""
        rules = load_all_rules()
        events = get_sample_events()
        alerts = run_detection(rules, events)
        assert len(alerts) == 6
