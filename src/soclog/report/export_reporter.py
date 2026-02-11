"""
ExportReporter

This module saves reports to files such as JSON or CSV.
It handles writing report data to the filesystem.
"""

class ExportReporter:
    def export(self, report, out_path):
        print("[ExportReporter] export() called")
        print(f"[ExportReporter] Output path: {out_path}")
        print("[ExportReporter] (demo) export complete\n")
