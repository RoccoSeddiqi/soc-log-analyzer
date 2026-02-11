"""
LogLoader

This module is responsible for reading log files from disk.
It loads raw log data and passes it to the next stage of the system.
"""

class LogLoader:
    def load(self, path):
        print("[LogLoader] load() called")
        print(f"[LogLoader] Received path: {path}")
        print("[LogLoader] returning raw events\n")

        # demo placeholder
        return ["RAW_EVENT_1", "RAW_EVENT_2"]
