import argparse

from soclog.io.log_loader import LogLoader
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
    # cd src
    # python -m soclog.main wizard

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
        log_path = input("\nEnter path to log file: ").strip()
        source_type = input("Enter source type (Windows/Linux): ").strip()
        log_format = input("Enter format (CSV/JSON/JSONL): ").strip()

        # Call into LogLoader module
        raw_events = loader.load(log_path)

        print(f"(CLI) Captured: source='{source_type}', format='{log_format}'")
        print("(CLI) Status: OK\n")
        self._pause(pause)
        print("\n")

        # Normalization
        self._header("Normalization")
        normalize_mode = input("\nNormalize mode (default/basic/strict): ").strip()
        drop_missing = input("Drop missing fields? (y/n): ").strip()

        # Call into EventNormalizer module
        validation = normalizer.validate(raw_events)
        normalized_events = normalizer.normalize(raw_events)

        print(f"(CLI) Captured: normalize_mode='{normalize_mode}', drop_missing='{drop_missing}'")
        print(f"(CLI) Validation result: {validation}\n")
        print("(CLI) Normalization Results:")
        print("- Total records: 12,487")
        print("- Normalized: 12,120")
        print("- Warnings: 367\n")
        self._pause(pause)
        print("\n")


        # Detection
        self._header("Detection Run")
        profile = input("Select profile (basic/extended): ").strip()
        rule_pack = input("Select rule category (execution/credential_access/etc/): ").strip()

        # Call into DetectionEngine module (prints from detect/engine.py)
        # config is still placeholder for now
        config = {"profile": profile, "rule_pack": rule_pack}
        alerts = engine.run(normalized_events, config)

        print(f"(CLI) Captured: profile='{profile}', rule_pack='{rule_pack}'")
        print("(CLI) Detection Run Completed:")
        print("- Events analyzed: 12,120")
        print("- Rules applied: 6")
        print("- Alerts generated: 42\n")
        self._pause(pause)
        print("\n")

        # Alerts Review
        self._header("Alerts Review")
        print("Alerts (demo sample):")
        print("A01 | HIGH   | Brute Force Window")
        print("A02 | MEDIUM | Success After Failures")
        print("A03 | LOW    | Unusual Hour Login\n")

        action = input("Type 'show A01' to continue: ").strip()
        if action.lower().startswith("show"):
            self._alert_details_demo()

        self._pause(pause)
        print("\n")


        # Summary Report + Export
        self._header("Summary Report / Export")
        out_dir = input("Enter output folder: ").strip()
        export_report_choice = input("Export report? (y/n): ").strip()
        export_alerts_choice = input("Export alerts? (y/n): ").strip()

        # Call into ReportGenerator + ExportReporter modules
        report = reporter.generate_report(alerts)

        # In demo mode we "export" regardless of choice for now,
        # but we still capture what user typed.
        exporter.export(report, out_dir)

        print(f"(CLI) Captured: out_dir='{out_dir}', export_report='{export_report_choice}', export_alerts='{export_alerts_choice}'")
        print("(CLI) Summary Report:")
        print(f"- Total alerts: {report.get('total_alerts', 0)}")
        print("- HIGH: 5 | MEDIUM: 18 | LOW: 19")
        print("- Exported report: \n")
        self._pause(pause)
        print("\n")


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

    def _alert_details_demo(self):
        print("-" * 60)
        print("Alert Details (demo)")
        print("-" * 60)
        print("Alert ID: A01")
        print("Rule: Brute Force Window")
        print("Severity: HIGH")
        print("Host: WS-01")
        print("User: admin")
        print("Source IP: 10.0.0.200")
        print("Evidence: 12 failed logins within 2 minutes")
        print("-" * 60)
        print()
