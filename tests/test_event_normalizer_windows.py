import pytest
from soclog.normalize.event_normalizer import EventNormalizer


@pytest.fixture()
def normalizer():
    return EventNormalizer()


@pytest.fixture()
def sample_events():
    return [
        {
            "EventID": 1102,
            "Hostname": "WORKSTATION5",
            "SubjectUserName": "wardog",
            "TimeCreated": "2020-10-29T12:16:07.900Z",
            "Message": "The audit log was cleared."
        },
        {
            "EventID": 5156,
            "Hostname": "WORKSTATION5",
            "TimeCreated": "2020-10-29T12:16:09.213Z",
            "SourceAddress": "192.168.2.5",
            "DestAddress": "168.63.129.16",
            "SourcePort": "65353",
            "DestPort": "80",
            "Protocol": "6",
            "Application": r"\device\harddiskvolume2\windowsazure\guestagent.exe",
            "Message": "The Windows Filtering Platform has permitted a connection."
        },
        {
            "EventID": 4688,
            "Hostname": "WORKSTATION5",
            "SubjectUserName": "wardog",
            "TimeCreated": "2020-10-29T12:16:09.914Z",
            "NewProcessName": r"C:\Windows\System32\netsh.exe",
            "ParentProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": r"\"C:\windows\system32\netsh.exe\" advfirewall firewall add rule name=python.exe",
            "Message": "A new process has been created."
        },
    ]


def test_validate_default_counts_and_no_errors(normalizer, sample_events):
    v = normalizer.validate(sample_events, mode="default")
    assert v.total_records == 3
    assert v.errors == 0
    assert v.warnings >= 0
    assert v.valid_records == 3


def test_normalize_extracts_core_fields(normalizer, sample_events):
    normalized, summary = normalizer.normalize(sample_events, mode="default", drop_missing=False, source="windows")
    assert summary.total_records == 3
    assert summary.normalized == 3
    assert summary.dropped == 0

    e0 = normalized[0]
    assert e0["source"] == "windows"
    assert e0["event_id"] == "1102"
    assert e0["host"] == "WORKSTATION5"
    assert e0["user"] == "wardog"
    assert e0["message"].startswith("The audit log was cleared")
    assert e0["timestamp"].endswith("Z")


def test_normalize_process_event_enrichment(normalizer, sample_events):
    normalized, _ = normalizer.normalize(sample_events, mode="default", drop_missing=False, source="windows")
    e = normalized[2]
    assert e["event_id"] == "4688"
    assert e["event_type"] == "process"
    assert "netsh.exe" in (e.get("process_name") or "")
    assert "advfirewall" in (e.get("command_line") or "")
    assert "powershell.exe" in (e.get("parent_process_name") or "")
    assert e["user"] == "wardog"


def test_normalize_network_event_enrichment_and_user_not_required(normalizer, sample_events):
    normalized, summary = normalizer.normalize(sample_events, mode="default", drop_missing=False, source="windows")
    e = normalized[1]
    assert e["event_id"] == "5156"
    assert e["event_type"] == "network"
    assert e["src_ip"] == "192.168.2.5"
    assert e["dest_ip"] == "168.63.129.16"
    assert e["src_port"] == 65353
    assert e["dest_port"] == 80
    assert e["protocol"] == "6"
    assert e["application"] is not None
    assert e["user"] == "unknown"
    assert summary.dropped == 0


def test_strict_mode_drops_missing_required_user(normalizer):
    events = [{
        "EventID": 4688,
        "Hostname": "WORKSTATION5",
        "TimeCreated": "2020-10-29T12:16:09.914Z",
        "NewProcessName": r"C:\Windows\System32\netsh.exe",
        "Message": "A new process has been created."
    }]

    normalized, summary = normalizer.normalize(events, mode="strict", drop_missing=False, source="windows")
    assert summary.total_records == 1
    assert summary.normalized == 0
    assert summary.dropped == 1
    assert summary.errors >= 1
    assert any(i.code == "MISSING_FIELD" and i.field == "user" for i in summary.issues)


def test_drop_missing_true_drops_missing_host_in_default(normalizer):
    events = [{
        "EventID": 1102,
        "SubjectUserName": "wardog",
        "TimeCreated": "2020-10-29T12:16:07.900Z",
        "Message": "The audit log was cleared."
    }]

    normalized, summary = normalizer.normalize(events, mode="default", drop_missing=True, source="windows")
    assert summary.total_records == 1
    assert summary.normalized == 0
    assert summary.dropped == 1


def test_timestamp_fallback_default_sets_now_on_bad_timestamp(normalizer):
    events = [{
        "EventID": 1102,
        "Hostname": "WORKSTATION5",
        "SubjectUserName": "wardog",
        "TimeCreated": "not-a-timestamp",
        "Message": "The audit log was cleared."
    }]

    normalized, summary = normalizer.normalize(events, mode="default", drop_missing=False, source="windows")
    assert summary.total_records == 1
    assert summary.normalized == 1
    assert summary.warnings >= 1
    assert normalized[0]["timestamp"].endswith("Z")


def test_host_from_hostname(normalizer):
    events = [{
        "EventID": 1102,
        "Hostname": "WORKSTATION5",
        "SubjectUserName": "wardog",
        "TimeCreated": "2020-10-29T12:16:07.900Z",
        "Message": "The audit log was cleared."
    }]
    normalized, summary = normalizer.normalize(events, mode="default", drop_missing=False, source="windows")
    assert summary.normalized == 1
    assert normalized[0]["host"] == "WORKSTATION5"


def test_user_prefers_subject_over_target(normalizer):
    events = [{
        "EventID": 4688,
        "Hostname": "WS1",
        "TimeCreated": "2020-10-29T12:16:09.914Z",
        "SubjectUserName": "actor",
        "TargetUserName": "victim",
        "Message": "A new process has been created."
    }]
    normalized, _ = normalizer.normalize(events, source="windows")
    assert normalized[0]["user"] == "actor"


def test_wfp_network_event_missing_user_is_allowed(normalizer):
    events = [{
        "EventID": 5156,
        "Hostname": "WORKSTATION5",
        "TimeCreated": "2020-10-29T12:16:09.213Z",
        "SourceAddress": "192.168.2.5",
        "DestAddress": "168.63.129.16",
        "SourcePort": "65353",
        "DestPort": "80",
        "Protocol": "6",
        "Message": "The Windows Filtering Platform has permitted a connection."
    }]
    normalized, summary = normalizer.normalize(events, mode="default", drop_missing=False, source="windows")
    assert summary.normalized == 1
    assert normalized[0]["event_type"] == "network"
    assert normalized[0]["user"] == "unknown"