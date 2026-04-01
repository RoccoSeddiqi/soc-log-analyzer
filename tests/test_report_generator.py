from soclog.report.report_generator import ReportGenerator


def test_generate_report_counts_alerts_correctly():
    reporter = ReportGenerator()

    alerts = [
        {"rule_name": "python_http_server_execution", "severity": "HIGH", "category": "execution"},
        {"rule_name": "python_http_server_execution", "severity": "HIGH", "category": "execution"},
        {"rule_name": "firewall_rule_modification", "severity": "MEDIUM", "category": "execution"},
    ]

    report = reporter.generate_report(alerts)

    assert report["total_alerts"] == 3
    assert report["severity_counts"]["HIGH"] == 2
    assert report["severity_counts"]["MEDIUM"] == 1
    assert report["category_counts"]["execution"] == 3
    assert report["rule_counts"]["python_http_server_execution"] == 2