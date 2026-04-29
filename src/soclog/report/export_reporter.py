from __future__ import annotations

import json
from pathlib import Path


class ExportReporter:
    def export_report(self, report, out_dir):
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        report_file = out_path / "summary_report.json"
        with report_file.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return str(report_file)

    def export_alerts(self, alerts, out_dir):
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        alerts_file = out_path / "alerts.json"
        with alerts_file.open("w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=str)

        return str(alerts_file)

    def export_normalized_events(self, events, out_dir):
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        dataset_file = out_path / "normalized_events.json"
        with dataset_file.open("w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, default=str)

        return str(dataset_file)