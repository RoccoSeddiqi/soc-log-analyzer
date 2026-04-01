"""
ReportGenerator

This module takes all generated alerts and summarizes them.
It creates an easy-to-read report showing what was detected.
"""

from collections import Counter


class ReportGenerator:
    def generate_report(self, alerts):
        severity_counts = Counter()
        category_counts = Counter()
        rule_counts = Counter()

        for alert in alerts:
            severity = (alert.get("severity") or "UNKNOWN").upper()
            category = (alert.get("category") or "unknown").lower()
            rule_name = alert.get("rule_name") or "unknown_rule"

            severity_counts[severity] += 1
            category_counts[category] += 1
            rule_counts[rule_name] += 1

        return {
            "total_alerts": len(alerts),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "rule_counts": dict(rule_counts),
            "alerts": alerts,
        }