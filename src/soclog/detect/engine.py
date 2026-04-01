"""
DetectionEngine

This module runs detection rules on normalized log events.
It decides whether any activity looks suspicious and creates alerts.
"""

from soclog.detect.rules import get_execution_rules


class DetectionEngine:
    def run(self, events, config):
        print("[DetectionEngine] run() called")
        print(f"[DetectionEngine] Events analyzed: {len(events)}")

        rules = self._select_rules(config)
        alerts = []

        for event in events:
            for rule in rules:
                alert = rule.match(event)
                if alert is not None:
                    alerts.append(alert)

        print(f"[DetectionEngine] Rules loaded: {len(rules)}")
        print(f"[DetectionEngine] Alerts generated: {len(alerts)}\n")

        return alerts

    def _select_rules(self, config):
        rule_pack = config.get("rule_pack", "").strip().lower()

        if rule_pack == "execution":
            return get_execution_rules()

        return []