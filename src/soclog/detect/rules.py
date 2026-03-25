"""
DetectionRule

This file defines how detection rules work.
Each rule checks log events for specific suspicious patterns
and creates alerts when those patterns are found.
"""

class DetectionRule:
    name = "base_rule"
    severity = "LOW"
    category = "generic"

    def match(self, event):
        raise NotImplementedError("Subclasses must implement match()")


class PythonHTTPServerExecutionRule:
    name = "python_http_server_execution"
    severity = "HIGH"
    category = "execution"

    def match(self, event):
        # Only care about process creation events
        if event.get("event_id") != "4688":
            return None

        cmd = (event.get("command_line") or "").lower()
        process = (event.get("process_name") or "").lower()

        # Core detection
        if "python -m http.server" in cmd:
            return self._build_alert(event, "python http server started")

        # Optional broader detection (less strict)
        if "python.exe" in process and "http.server" in cmd:
            return self._build_alert(event, "python http server behavior")

        return None

    def _build_alert(self, event, reason):
        return {
            "rule_name": self.name,
            "severity": self.severity,
            "category": self.category,
            "summary": reason,
            "host": event.get("host"),
            "user": event.get("user"),
            "command_line": event.get("command_line"),
            "event_id": event.get("event_id"),
        }