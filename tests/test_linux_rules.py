from soclog.detect.rules import LinuxDdBinaryPaddingRule, LinuxArpDiscoveryRule, LinuxWhoamiDiscoveryRule


def test_linux_dd_rule_matches_command_line_event():
    rule = LinuxDdBinaryPaddingRule()

    event = {
        "source": "linux",
        "process_name": None,
        "command_line": "dd if=/dev/zero bs=1 count=1",
        "application": None,
        "message": 'type=EXECVE msg=audit(...): a0="dd" a1="if=/dev/zero" a2="bs=1" a3="count=1"',
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["rule_name"] == "linux_dd_binary_padding_hash_change"
    assert alert["severity"] == "HIGH"
    assert alert["category"] == "defense_evasion"
    assert "dd-based" in alert["reason"].lower()


def test_linux_dd_rule_matches_process_name_event():
    rule = LinuxDdBinaryPaddingRule()

    event = {
        "source": "linux",
        "process_name": "dd",
        "command_line": None,
        "application": "/bin/dd",
        "message": 'type=SYSCALL msg=audit(...): comm="dd" exe="/bin/dd"',
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["rule_name"] == "linux_dd_binary_padding_hash_change"


def test_linux_dd_rule_ignores_non_linux_event():
    rule = LinuxDdBinaryPaddingRule()

    event = {
        "source": "windows",
        "process_name": "dd",
        "command_line": "dd if=/dev/zero bs=1 count=1",
        "application": "/bin/dd",
        "message": 'comm="dd"',
    }

    assert rule.match(event) is None


def test_linux_dd_rule_ignores_unrelated_linux_event():
    rule = LinuxDdBinaryPaddingRule()

    event = {
        "source": "linux",
        "process_name": "bash",
        "command_line": "echo hello",
        "application": "/bin/bash",
        "message": 'type=EXECVE msg=audit(...): a0="echo" a1="hello"',
    }

    assert rule.match(event) is None


def test_linux_arp_rule_detects_arp_a():
    rule = LinuxArpDiscoveryRule()

    event = {
        "source": "linux",
        "process_name": "arp",
        "command_line": "arp -a",
        "application": "/usr/sbin/arp",
        "message": 'type=EXECVE msg=audit(...): a0="arp" a1="-a"',
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["rule_name"] == "linux_arp_discovery"


def test_linux_arp_rule_does_not_trigger_on_ls():
    rule = LinuxArpDiscoveryRule()

    event = {
        "source": "linux",
        "process_name": "ls",
        "command_line": "ls -la",
        "application": "/usr/bin/ls",
        "message": 'type=EXECVE msg=audit(...): a0="ls" a1="-la"',
    }

    alert = rule.match(event)

    assert alert is None


def test_linux_arp_rule_ignores_windows_events():
    rule = LinuxArpDiscoveryRule()

    event = {
        "source": "windows",
        "process_name": "arp.exe",
        "command_line": "arp -a",
        "application": r"C:\\Windows\\System32\\arp.exe",
        "message": "",
    }

    alert = rule.match(event)

    assert alert is None


def test_whoami_detection_basic():
    rule = LinuxWhoamiDiscoveryRule()

    event = {
        "source": "linux",
        "process_name": "whoami",
        "command_line": "whoami",
        "application": "/usr/bin/whoami",
        "message": 'type=EXECVE msg=audit(...): a0="whoami"',
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["rule_name"] == "linux_whoami_discovery"
    assert alert["severity"] == "LOW"
    assert alert["category"] == "discovery"


def test_whoami_not_triggered_on_other_commands():
    rule = LinuxWhoamiDiscoveryRule()

    event = {
        "source": "linux",
        "process_name": "ls",
        "command_line": "ls -la",
        "application": "/usr/bin/ls",
        "message": 'type=EXECVE msg=audit(...): a0="ls" a1="-la"',
    }

    alert = rule.match(event)

    assert alert is None