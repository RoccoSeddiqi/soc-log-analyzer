"""
DetectionEngine

This module runs detection rules on normalized log events.
It decides whether any activity looks suspicious and creates alerts.
"""

class DetectionEngine:
    def run(self, events, config):
        print("[DetectionEngine] run() called")
        print(f"[DetectionEngine] Events analyzed: {len(events)}")
        print("[DetectionEngine] (demo) detection completed\n")

        return ["ALERT_1", "ALERT_2"]
