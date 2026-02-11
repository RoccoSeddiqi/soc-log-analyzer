"""
ReportGenerator

This module takes all generated alerts and summarizes them.
It creates an easy-to-read report showing what was detected.
"""

class ReportGenerator:
    def generate_report(self, alerts):
        print("[ReportGenerator] generate_report() called")
        print(f"[ReportGenerator] Alerts received: {len(alerts)}")
        print("[ReportGenerator] (demo) summary report created\n")

        return {"total_alerts": len(alerts)}
