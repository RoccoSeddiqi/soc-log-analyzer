"""
DetectionRule

This file defines how detection rules work.
Each rule checks log events for specific suspicious patterns
and creates alerts when suspicious behavior is found.
"""


class DetectionRule:
    name = "base_rule"
    severity = "LOW"
    category = "generic"

    def match(self, event):
        raise NotImplementedError("Subclasses must implement match()")

    def build_alert(self, event, reason, educational_note=None, recommended_action=None):
        return {
            "rule_name": self.name,
            "severity": self.severity,
            "category": self.category,
            "summary": reason,
            "reason": reason,
            "educational_note": educational_note or "This alert was generated because the event matched a suspicious behavior pattern. Review the command, user, host, and surrounding activity to determine whether it is expected or unauthorized.",
            "recommended_action": recommended_action or "Review the event details, verify whether the activity was authorized, and investigate related logs from the same user or host.",
            "host": event.get("host"),
            "user": event.get("user"),
            "command_line": event.get("command_line"),
            "event_id": event.get("event_id"),
        }


# Windows Rules
class PythonHTTPServerExecutionRule(DetectionRule):
    name = "python_http_server_execution"
    severity = "HIGH"
    category = "execution"

    def match(self, event):
        if event.get("event_id") != "4688":
            return None

        cmd = (event.get("command_line") or "").lower()
        process = (event.get("process_name") or "").lower()

        if "python -m http.server" in cmd:
            return self.build_alert(
            event,
            "python http server started",
            "Python's built-in HTTP server can quickly expose files from a folder over the network. In SOC analysis, this may indicate file staging, unauthorized file sharing, or attacker-controlled hosting.",
            "Verify whether the user intentionally started the server. Check the working directory, network connections, and surrounding process activity."
            )

        if "python.exe" in process and "http.server" in cmd:
            return self.build_alert(
            event,
            "python http server behavior",
            "A Python process using http.server may be legitimate for development, but it can also be used by attackers to host or transfer files during an intrusion.",
            "Confirm the business purpose of the process and review network activity from the host."
            )

        return None
    

# Linux Rules
class LinuxDdBinaryPaddingRule(DetectionRule):
    name = "linux_dd_binary_padding_hash_change"
    severity = "HIGH"
    category = "defense_evasion"

    def match(self, event):
        if event.get("source") != "linux":
            return None

        process_name = (event.get("process_name") or "").lower()
        command_line = (event.get("command_line") or "").lower()
        application = (event.get("application") or "").lower()
        message = (event.get("message") or "").lower()

        dd_detected = (
            process_name == "dd"
            or command_line.startswith("dd")
            or application.endswith("/dd")
            or 'comm="dd"' in message
        )

        padding_args_detected = (
            "if=" in command_line
            or "bs=" in command_line
            or "count=" in command_line
            or 'a1="if=' in message
            or 'a2="bs=' in message
            or 'a3="count=' in message
        )

        if dd_detected and padding_args_detected:
            return self.build_alert(
            event,
            "dd-based binary padding behavior detected",
            "The dd utility can copy or modify binary data. Attackers may use it to pad or alter files, which can change hashes and help evade simple file-based detection.",
            "Inspect the files referenced by the dd command and compare them against known-good versions or expected hashes."
            )

        # fallback: still detect dd execution (for test compatibility)
        if dd_detected:
            return self.build_alert(
            event,
            "dd-based execution detected",
            "The dd utility is powerful and legitimate, but unexpected dd execution may indicate file manipulation, disk copying, or defense evasion activity.",
            "Review the command arguments and determine whether this use of dd was expected for the user or system."
            )


        return None
    
class LinuxArpDiscoveryRule(DetectionRule):
    name = "linux_arp_discovery"
    severity = "MEDIUM"
    category = "discovery"

    def match(self, event):
        if event.get("source") != "linux":
            return None

        command_line = (event.get("command_line") or "").lower().strip()
        message = (event.get("message") or "").lower()

        if command_line == "arp -a" or 'a0="arp" a1="-a"' in message:
            return self.build_alert(
            event,
            "arp table enumeration detected",
            "The arp -a command lists nearby network devices. Attackers often perform this type of discovery after gaining access to understand the local network.",
            "Check whether the user normally performs network troubleshooting. Review nearby commands for additional discovery activity."
            )

        return None
    
class LinuxWhoamiDiscoveryRule(DetectionRule):
    name = "linux_whoami_discovery"
    severity = "LOW"
    category = "discovery"

    def match(self, event):
        if event.get("source") != "linux":
            return None

        command_line = (event.get("command_line") or "").lower().strip()
        process_name = (event.get("process_name") or "").lower()
        application = (event.get("application") or "").lower()
        message = (event.get("message") or "").lower()

        if (
            command_line == "whoami"
            or process_name == "whoami"
            or application.endswith("/whoami")
            or 'a0="whoami"' in message
            or 'comm="whoami"' in message
        ):
            return self.build_alert(
            event,
            "user context discovery via whoami detected",
            "The whoami command identifies the current user context. Attackers commonly run it after gaining access to learn what privileges they have.",
            "Look for follow-up commands such as hostname, ip addr, sudo, privilege checks, or lateral movement attempts."
            )

        return None


def get_windows_rules():
    return [
        PythonHTTPServerExecutionRule(),
    ]

def get_linux_rules():
    return [
        LinuxDdBinaryPaddingRule(),
        LinuxArpDiscoveryRule(),
        LinuxWhoamiDiscoveryRule(),
    ]