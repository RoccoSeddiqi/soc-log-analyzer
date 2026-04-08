from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from email.mime import message
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class Issue:
    level: str          # "warning" | "error"
    code: str
    message: str
    event_index: int
    field: Optional[str] = None


@dataclass
class ValidationSummary:
    total_records: int
    valid_records: int
    warnings: int
    errors: int
    issues: List[Issue]


@dataclass
class NormalizationSummary:
    total_records: int
    normalized: int
    dropped: int
    warnings: int
    errors: int
    issues: List[Issue]


@dataclass
class NormalizedEvent:
    # Canonical fields the DetectionEngine should rely on
    timestamp: str              # ISO-8601 UTC
    source: str                 # "windows"
    event_id: str               # Ex: "4688"
    event_type: str             # "auth" | "process" | "network" | "system" | "unknown"
    host: str
    user: str
    message: str

    # Optional enrichments
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None

    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    application: Optional[str] = None

    # Keep raw for traceability
    raw: Optional[Dict[str, Any]] = None


class EventNormalizer:
    """
    mode:
      - "default": coercions, missing fields often become warnings + "unknown"
      - "basic": fewer drops, less strict parsing
      - "strict": missing critical fields => errors + drop

    drop_missing:
      - if True: drop events missing required fields for that event type
    """

    # Windows export alias map based on your sample
    WINDOWS_ALIASES = {
        "timestamp": ["@timestamp", "TimeCreated"],
        "host": ["Hostname", "Computer", "ComputerName", "HostName"],
        "event_id": ["EventID"],
        "message": ["Message"],
        "user_subject": ["SubjectUserName"],
        "user_target": ["TargetUserName"],

        # network/WFP
        "src_ip": ["SourceAddress", "IpAddress"],
        "dest_ip": ["DestAddress", "DestinationAddress"],
        "src_port": ["SourcePort"],
        "dest_port": ["DestPort", "DestinationPort"],
        "protocol": ["Protocol"],
        "application": ["Application"],

        # process
        "process_name": ["NewProcessName", "ProcessName"],
        "parent_process_name": ["ParentProcessName"],
        "command_line": ["CommandLine"],
    }

    LINUX_ALIASES = {
        "timestamp": ["@timestamp", "timestamp", "time"],
        "host": ["host", "hostname", "computer"],
        "message": ["message", "msg"],
        "user": ["user", "username"],
        "process_name": ["process", "process_name", "program"],
        "application": ["application", "app"],
        "command_line": ["command_line", "cmdline", "cmd"],
    }

    # Event IDs we already have in sample (need to expand later for organizing for detection rules)
    PROCESS_EVENT_IDS = {"4688"}          # New process created
    NETWORK_EVENT_IDS = {"5156", "5158"}  # Network
    SYSTEM_EVENT_IDS = {"1102"}           # Audit log cleared (system-ish)

    def validate(self, raw_events: Iterable[Any], mode: str = "default", source: str = "windows") -> ValidationSummary:
        strict = (mode or "default").strip().lower() == "strict"
        source = (source or "windows").strip().lower()

        issues: List[Issue] = []
        total = valid = warn = err = 0

        for i, raw in enumerate(raw_events):
            total += 1

            if not isinstance(raw, dict):
                err += 1
                issues.append(self._issue("error", "INVALID_TYPE", f"Event is not a dict (got {type(raw).__name__}).", i))
                continue

            if source == "windows":
                event_id = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["event_id"])) or "unknown"
                event_type = self._event_type_from_event_id(event_id)

                ts_val = self._get_first(raw, self.WINDOWS_ALIASES["timestamp"])
                host_val = self._get_first(raw, self.WINDOWS_ALIASES["host"])
                user_val = self._pick_windows_user(raw)
                user_required = self._user_required(event_id, event_type)

            elif source == "linux":
                event_id = "unknown"
                message = self._to_str(self._get_first(raw, self.LINUX_ALIASES["message"])) or ""
                event_type = self._linux_event_type_from_message(message)

                ts_val = self._get_first(raw, self.LINUX_ALIASES["timestamp"])
                host_val = self._get_first(raw, self.LINUX_ALIASES["host"])
                user_val = self._get_first(raw, self.LINUX_ALIASES["user"])
                user_required = False

            else:
                err += 1
                issues.append(self._issue("error", "UNSUPPORTED_SOURCE", f"Unsupported source: {source}", i))
                continue

            ts_dt = self._parse_timestamp(ts_val)
            if ts_dt is None:
                if strict:
                    err += 1
                    issues.append(self._issue("error", "BAD_TIMESTAMP", f"Missing/unparseable timestamp: {ts_val!r}", i, "timestamp"))
                else:
                    warn += 1
                    issues.append(self._issue("warning", "BAD_TIMESTAMP", f"Missing/unparseable timestamp (set to now): {ts_val!r}", i, "timestamp"))

            if not self._to_str(host_val):
                if strict:
                    err += 1
                    issues.append(self._issue("error", "MISSING_FIELD", "Missing host.", i, "host"))
                else:
                    warn += 1
                    issues.append(self._issue("warning", "MISSING_FIELD", "Missing host (set to 'unknown').", i, "host"))

            if user_required and not self._to_str(user_val):
                if strict:
                    err += 1
                    issues.append(self._issue("error", "MISSING_FIELD", "Missing user.", i, "user"))
                else:
                    warn += 1
                    issues.append(self._issue("warning", "MISSING_FIELD", "Missing user (set to 'unknown').", i, "user"))

            if strict:
                has_error = any(x.level == "error" and x.event_index == i for x in issues)
                if not has_error:
                    valid += 1
            else:
                valid += 1

        return ValidationSummary(total, valid, warn, err, issues)

    def normalize(
        self,
        raw_events: Iterable[Any],
        mode: str = "default",
        drop_missing: bool = False,
        source: str = "windows",
        keep_raw: bool = False,
    ) -> Tuple[List[Dict[str, Any]], NormalizationSummary]:

        mode_norm = (mode or "default").strip().lower()
        strict = mode_norm == "strict"
        basic = mode_norm == "basic"
        source = (source or "windows").strip().lower()

        issues: List[Issue] = []
        out: List[Dict[str, Any]] = []
        total = normalized = dropped = warn = err = 0

        for i, raw in enumerate(raw_events):
            total += 1

            if not isinstance(raw, dict):
                dropped += 1
                err += 1
                issues.append(self._issue("error", "INVALID_TYPE", f"Event is not a dict (got {type(raw).__name__}).", i))
                continue

            if source == "windows":
                event_id = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["event_id"])) or "unknown"
                event_type = self._event_type_from_event_id(event_id)

                ts_val = self._get_first(raw, self.WINDOWS_ALIASES["timestamp"])
                ts_dt = self._parse_timestamp(ts_val)
                if ts_dt is None:
                    if strict or (drop_missing and not basic):
                        dropped += 1
                        err += 1
                        issues.append(self._issue("error", "BAD_TIMESTAMP", f"Missing/unparseable timestamp: {ts_val!r}", i, "timestamp"))
                        continue
                    warn += 1
                    issues.append(self._issue("warning", "BAD_TIMESTAMP", f"Missing/unparseable timestamp (set to now): {ts_val!r}", i, "timestamp"))
                    ts_dt = datetime.now(timezone.utc)

                host_raw = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["host"]))
                user_raw = self._to_str(self._pick_windows_user(raw))

                host = host_raw or "unknown"
                user = user_raw or "unknown"
                message = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["message"])) or ""

                missing_required = False

                if not host_raw:
                    missing_required = True
                    issues.append(self._issue("warning", "MISSING_FIELD", "Missing host (set to 'unknown').", i, "host"))

                if self._user_required(event_id, event_type) and not user_raw:
                    missing_required = True
                    issues.append(self._issue("warning", "MISSING_FIELD", "Missing user (set to 'unknown').", i, "user"))

                if strict and missing_required:
                    dropped += 1
                    err += 1
                    continue

                if drop_missing and missing_required:
                    dropped += 1
                    err += 1
                    continue

                src_ip = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["src_ip"])) or None
                dest_ip = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["dest_ip"])) or None
                src_port = self._to_int(self._get_first(raw, self.WINDOWS_ALIASES["src_port"]))
                dest_port = self._to_int(self._get_first(raw, self.WINDOWS_ALIASES["dest_port"]))
                protocol = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["protocol"])) or None

                process_name = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["process_name"])) or None
                parent_process_name = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["parent_process_name"])) or None
                command_line = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["command_line"])) or None
                application = self._to_str(self._get_first(raw, self.WINDOWS_ALIASES["application"])) or None

                evt = NormalizedEvent(
                    timestamp=ts_dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    source="windows",
                    event_id=event_id,
                    event_type=event_type,
                    host=host,
                    user=user,
                    message=message,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    src_port=src_port,
                    dest_port=dest_port,
                    protocol=protocol,
                    process_name=process_name,
                    parent_process_name=parent_process_name,
                    command_line=command_line,
                    application=application,
                    raw=raw if keep_raw else None,
                )

                out.append(asdict(evt))
                normalized += 1
                continue

            if source == "linux":
                ts_val = self._get_first(raw, self.LINUX_ALIASES["timestamp"])
                ts_dt = self._parse_timestamp(ts_val)
                if ts_dt is None:
                    if strict or (drop_missing and not basic):
                        dropped += 1
                        err += 1
                        issues.append(self._issue("error", "BAD_TIMESTAMP", f"Missing/unparseable timestamp: {ts_val!r}", i, "timestamp"))
                        continue
                    warn += 1
                    issues.append(self._issue("warning", "BAD_TIMESTAMP", f"Missing/unparseable timestamp (set to now): {ts_val!r}", i, "timestamp"))
                    ts_dt = datetime.now(timezone.utc)

                host = self._to_str(self._get_first(raw, self.LINUX_ALIASES["host"])) or "unknown"
                message = self._to_str(self._get_first(raw, self.LINUX_ALIASES["message"])) or ""
                user = self._to_str(self._get_first(raw, self.LINUX_ALIASES["user"])) or "unknown"
                process_name = self._to_str(self._get_first(raw, self.LINUX_ALIASES["process_name"])) or None
                application = self._to_str(self._get_first(raw, self.LINUX_ALIASES["application"])) or None
                command_line = self._to_str(self._get_first(raw, self.LINUX_ALIASES["command_line"])) or None
                event_type = self._linux_event_type_from_message(message)

                evt = NormalizedEvent(
                    timestamp=ts_dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                    source="linux",
                    event_id="unknown",
                    event_type=event_type,
                    host=host,
                    user=user,
                    message=message,
                    process_name=process_name,
                    command_line=command_line,
                    application=application,
                    raw=raw if keep_raw else None,
                )

                out.append(asdict(evt))
                normalized += 1
                continue

            dropped += 1
            err += 1
            issues.append(self._issue("error", "UNSUPPORTED_SOURCE", f"Unsupported source: {source}", i))

        summary = NormalizationSummary(total, normalized, dropped, warn, err, issues)
        return out, summary


    # Windows helper methods for normalization logic
    def _pick_windows_user(self, raw: Dict[str, Any]) -> Any:
        """
        Prefer SubjectUserName for actor, fallback to TargetUserName.
        Your sample data uses these keys.
        """
        v = self._get_first(raw, self.WINDOWS_ALIASES["user_subject"])
        if self._to_str(v):
            return v
        return self._get_first(raw, self.WINDOWS_ALIASES["user_target"])

    def _event_type_from_event_id(self, event_id: str) -> str:
        if event_id in self.PROCESS_EVENT_IDS:
            return "process"
        if event_id in self.NETWORK_EVENT_IDS:
            return "network"
        if event_id in self.SYSTEM_EVENT_IDS:
            return "system"
        # We can add auth IDs later (4624/4625/etc.)
        return "unknown"

    def _user_required(self, event_id: str, event_type: str) -> bool:
        # Network WFP events often have no user -> don't require
        if event_id in self.NETWORK_EVENT_IDS or event_type == "network":
            return False
        # Process creation should have a SubjectUserName usually
        if event_id in self.PROCESS_EVENT_IDS or event_type == "process":
            return True
        # System events like 1102 do have SubjectUserName usually, but we can choose:
        if event_id in self.SYSTEM_EVENT_IDS:
            return True
        return False
    
    
    # Linux helper methods for normalization logic
    def _linux_event_type_from_message(self, message: str) -> str:
        msg = (message or "").lower()

        if "sshd" in msg or "failed password" in msg or "accepted password" in msg:
            return "auth"

        if "sudo" in msg:
            return "auth"

        return "unknown"


    # Helper methods for normalization
    def _issue(self, level: str, code: str, message: str, idx: int, field: Optional[str] = None) -> Issue:
        return Issue(level=level, code=code, message=message, event_index=idx, field=field)

    def _get_first(self, d: Dict[str, Any], keys: List[str]) -> Any:
        for k in keys:
            if k in d:
                return d.get(k)
        return None

    def _to_str(self, v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v.strip()
        return str(v).strip()

    def _to_int(self, v: Any) -> Optional[int]:
        if v is None:
            return None
        try:
            if isinstance(v, str):
                v = v.strip()
                if v == "":
                    return None
            return int(v)
        except Exception:
            return None

    def _parse_timestamp(self, v: Any) -> Optional[datetime]:
        if v is None:
            return None
        if isinstance(v, datetime):
            dt = v
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        s = str(v).strip()
        if not s:
            return None
        try:
            # Handles "...Z"
            if s.endswith("Z"):
                s = s.replace("Z", "+00:00")
            return datetime.fromisoformat(s).astimezone(timezone.utc)
        except Exception:
            return None