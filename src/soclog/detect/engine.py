"""
DetectionEngine

This module runs detection rules on normalized log events.
It decides whether any activity looks suspicious and creates alerts.
"""

from sys import platform

from soclog import config
from soclog.detect.rules import get_windows_rules, get_linux_rules

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
        platform = config.get("platform", "").strip().lower()
        rule_pack = config.get("rule_pack", "").strip().lower()

        # New logic (Linux / Windows split)
        if platform == "windows":
            return get_windows_rules()

        if platform == "linux":
            return get_linux_rules()

        # Set for tests right now, need to properly separate Windows vs Linux rule packs in the future
        if rule_pack == "windows":
            return get_windows_rules()

        if rule_pack == "execution":
            return get_windows_rules()
        
        if rule_pack == "credential_access":
            return get_windows_rules()
        
        if rule_pack == "persistence":
            return get_windows_rules()

        if rule_pack == "linux":
            return get_linux_rules()
        
        if rule_pack == "defense_evasion":
            return get_linux_rules()

        if rule_pack == "discovery":
            return get_linux_rules()

        
        return []