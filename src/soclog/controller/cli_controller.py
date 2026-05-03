import argparse
import json
import os
import subprocess
import sys
import time
import webbrowser

from soclog.io.log_loader import LogLoader, LogValidationError
from soclog.normalize.event_normalizer import EventNormalizer
from soclog.detect.engine import DetectionEngine
from soclog.report.report_generator import ReportGenerator
from soclog.report.export_reporter import ExportReporter


class CLIController:
    def run(self, args):
        parser = self._build_parser()
        ns = parser.parse_args(args)

        if ns.command == "wizard":
            self._wizard_flow(no_pause=ns.no_pause)
            return 0

        parser.print_help()
        return 0

    def _build_parser(self):
        parser = argparse.ArgumentParser(
            prog="soc-analyzer",
            description="SOC Log Analyzer - CLI Interface for Log Analysis and Detection",
        )
        sub = parser.add_subparsers(dest="command", required=True)

        p = sub.add_parser("wizard", help="Run the interactive wizard flow demonstrating the full analysis process")
        p.add_argument("--no-pause", action="store_true", help="Do not pause between screens")

        return parser
 

    # To run from root:
    # $env:PYTHONPATH="src"
    # python -m src.soclog.main wizard
    def _wizard_flow(self, no_pause=False):
        pause = not no_pause

        # Create component instances once
        loader = LogLoader()
        normalizer = EventNormalizer()
        engine = DetectionEngine()
        reporter = ReportGenerator()
        exporter = ExportReporter()


        # Import Logs
        self._header("Import Logs")

        while True:
            log_path = input("\nEnter path to log file: ").strip()
            source_type = input("Enter source type (Windows/Linux): ").strip()

            src = (source_type or "").strip().lower()
            if src in ("win", "windows"):
                src = "windows"
            elif src == "linux":
                src = "linux"
            else:
                src = source_type.strip()

            try:
                raw_events = list(loader.load(log_path))

                if not raw_events:
                    print("(CLI) No records found in file.\n")
                    retry = input("Try another file? (y/n): ").strip().lower()
                    if retry != "y":
                        return
                    continue

                break

            except LogValidationError as e:
                print(f"(CLI) Validation failed: {e}\n")
                retry = input("Try another file? (y/n): ").strip().lower()
                if retry != "y":
                    return

            except FileNotFoundError as e:
                print(f"(CLI) File error: {e}\n")
                retry = input("Try another file? (y/n): ").strip().lower()
                if retry != "y":
                    return

            except Exception as e:
                print(f"(CLI) Unexpected error: {e}\n")
                return

        print(f"(CLI) Captured: source='{src}', format='{'auto'}'")
        print(f"(CLI) Loaded records: {len(raw_events)}")
        print("(CLI) Status: OK\n")
        self._pause(pause)
        print("\n")


        # Normalization
        self._header("Normalization")

        normalize_mode = input("\nNormalize mode (default/basic/strict): ").strip() or "default"
        drop_missing_input = input("Drop missing fields? (y/n): ").strip().lower()
        drop_missing = drop_missing_input == "y"

        validation = normalizer.validate(raw_events, mode=normalize_mode)

        normalized_events, norm_summary = normalizer.normalize(
            raw_events,
            mode=normalize_mode,
            drop_missing=drop_missing,
            source=src,
            keep_raw=False
        )

        print(f"(CLI) Captured: normalize_mode='{normalize_mode}', drop_missing='{drop_missing}'")
        print(f"(CLI) Validation: total={validation.total_records}, valid={validation.valid_records}, warnings={validation.warnings}, errors={validation.errors}")

        print("(CLI) Normalization Results:")
        print(f"- Total records: {norm_summary.total_records}")
        print(f"- Normalized: {norm_summary.normalized}")
        print(f"- Dropped: {norm_summary.dropped}")
        print(f"- Warnings: {norm_summary.warnings}")
        print(f"- Errors: {norm_summary.errors}\n")

        if norm_summary.issues:
            print("(CLI) Sample issues:")
            for issue in norm_summary.issues[:5]:
                field = f" field={issue.field}" if issue.field else ""
                print(f"  - [{issue.level.upper()}] {issue.code}{field} @event#{issue.event_index}: {issue.message}")
            print()

        # Show example normalized output for testing purposes
        count = min(2, len(normalized_events))

        for i in range(count):
            print(f"(CLI) Raw event #{i} (before normalization):")
            print(json.dumps(raw_events[i], indent=2, default=str))
            print()

            print(f"(CLI) Normalized event #{i} (after normalization):")
            print(json.dumps(normalized_events[i], indent=2, default=str))
            print()
        # Show example normalized output for testing purposes

        self._pause(pause)
        print("\n")


        # Detection
        self._header("Detection Run")
        profile = input("Select profile (basic/extended): ").strip().lower() or "basic"

        if (src == "windows"):
            rule_pack = input("Select rule category (execution/credential_access/privilege_escalation): ").strip().lower() or "windows"
        else:
            rule_pack = input("Select rule category (defense_evasion/discovery): ").strip().lower() or "linux"

        config = {"profile": profile, "rule_pack": rule_pack}
        alerts = engine.run(normalized_events, config)

        print(f"(CLI) Captured: profile='{profile}', rule_pack='{rule_pack}'")
        print("(CLI) Detection Run Completed:")
        print(f"- Events analyzed: {len(normalized_events)}")
        print(f"- Alerts generated: {len(alerts)}")
        self._pause(pause)
        print("\n")

        
        # Alerts Review
        self._header("Alerts Review")

        if not alerts:
            print("No alerts generated.\n")
        else:
            for idx, alert in enumerate(alerts, start=1):
                print(f"A{idx:02d} | {alert['severity']:<6} | {alert['rule_name']}")

            print()
            action = input("Type 'show A01' to continue: ").strip().lower()

            if action.startswith("show"):
                try:
                    alert_num = int(action.split()[1][1:]) - 1
                    if 0 <= alert_num < len(alerts):
                        self._show_alert_details(alerts[alert_num], alert_num + 1)
                except (IndexError, ValueError):
                    print("Invalid alert selection.\n")

        self._pause(pause)
        print("\n")


        # Summary Report + Export
        self._header("Summary Report / Export")
        out_dir = input("Enter output folder: ").strip()
        export_report_choice = input("Export report? (y/n): ").strip().lower()
        export_alerts_choice = input("Export alerts? (y/n): ").strip().lower()

        report = reporter.generate_report(alerts)

        exported_report_path = None
        exported_alerts_path = None

        if export_report_choice == "y":
            exported_report_path = exporter.export_report(report, out_dir)

        if export_alerts_choice == "y":
            exported_alerts_path = exporter.export_alerts(alerts, out_dir)

        severity_counts = report.get("severity_counts", {})
        high_count = severity_counts.get("HIGH", 0)
        medium_count = severity_counts.get("MEDIUM", 0)
        low_count = severity_counts.get("LOW", 0)

        print(f"(CLI) Captured: out_dir='{out_dir}', export_report='{export_report_choice}', export_alerts='{export_alerts_choice}'")
        print("(CLI) Summary Report:")
        print(f"- Total alerts: {report.get('total_alerts', 0)}")
        print(f"- HIGH: {high_count} | MEDIUM: {medium_count} | LOW: {low_count}")

        if report.get("category_counts"):
            print("- Categories:")
            for category, count in report["category_counts"].items():
                print(f"  - {category}: {count}")

        if report.get("rule_counts"):
            print("- Rules:")
            for rule_name, count in report["rule_counts"].items():
                print(f"  - {rule_name}: {count}")

        if exported_report_path:
            print(f"- Exported report: {exported_report_path}")
        if exported_alerts_path:
            print(f"- Exported alerts: {exported_alerts_path}")
        if not exported_report_path and not exported_alerts_path:
            print("- No files exported.")

        print()
        self._pause(pause)
        print("\n")

        open_dashboard = input("Open dashboard? (y/n): ").strip().lower()

        if open_dashboard == "y":
            report_path = exporter.export_report(report, out_dir)
            dataset_path = exporter.export_normalized_events(normalized_events, out_dir)

            dashboard_script = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "dashboard", "dashboard.py")
            )

            url = "http://127.0.0.1:8050"

            subprocess.Popen([
                sys.executable,
                dashboard_script,
                report_path,
                dataset_path
            ])

            time.sleep(2)
            webbrowser.open(url)

            print(f"(CLI) Dashboard opened at: {url}")


        # Threshold Tuning
        self._header("Threshold Tuning")
        old_threshold = input("Old threshold (any value): ").strip()
        new_threshold = input("New threshold (any value): ").strip()
        time_window = input("Time window minutes (any value): ").strip()


        # No real tuning logic yet; just demonstrate the next step boundary
        print("[ConfigManager] (future) would load/update config here:")
        print(f"(CLI) Captured: old='{old_threshold}', new='{new_threshold}', window='{time_window}'")
        print("(CLI) Tuning Results:")
        print("- Before: 42 alerts")
        print("- After: 73 alerts\n\n")

        print("DONE: Wizard demo completed. Next step is implementing real logic in each component.")

    # UI Helper methods for consistent formatting
    def _header(self, title):
        print("=" * 60)
        print(title)
        print("=" * 60)

    def _pause(self, enabled):
        if enabled:
            input("Press Enter to continue...")

    def _show_alert_details(self, alert, alert_number):
        print("-" * 60)
        print(f"Alert Details (A{alert_number:02d})")
        print("-" * 60)
        print(f"Rule: {alert.get('rule_name')}")
        print(f"Severity: {alert.get('severity')}")
        print(f"Category: {alert.get('category')}")
        print(f"Summary: {alert.get('summary')}")
        print(f"Host: {alert.get('host')}")
        print(f"User: {alert.get('user')}")
        print(f"Matched Indicators: {', '.join(alert.get('matched_indicators', []))}")
        print("-" * 60)
        print()
    
    def save_report(report_data, output_path="output/report.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)