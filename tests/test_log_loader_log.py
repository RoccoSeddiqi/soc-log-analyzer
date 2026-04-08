from pathlib import Path

from soclog.io.log_loader import LogLoader


def test_load_log_yields_linux_events(tmp_path: Path):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        'type=SYSCALL msg=audit(1604996384.965:93777): comm="dd" exe="/bin/dd"\n'
        'type=EXECVE msg=audit(1604996384.965:93777): a0="dd" a1="if=/dev/zero"\n',
        encoding="utf-8",
    )

    loader = LogLoader()
    events = list(loader.load(str(log_file)))

    assert len(events) == 2
    assert events[0]["source"] == "linux"
    assert 'comm="dd"' in events[0]["message"]
    assert events[1]["source"] == "linux"
    assert 'a0="dd"' in events[1]["message"]


def test_load_log_skips_blank_lines(tmp_path: Path):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        '\n'
        'type=SYSCALL msg=audit(1604996384.965:93777): comm="arp" exe="/usr/sbin/arp"\n'
        '\n',
        encoding="utf-8",
    )

    loader = LogLoader()
    events = list(loader.load(str(log_file)))

    assert len(events) == 1
    assert events[0]["source"] == "linux"
    assert 'comm="arp"' in events[0]["message"]

from pathlib import Path

from soclog.io.log_loader import LogLoader


def test_load_log_extracts_dd_fields(tmp_path: Path):
    log_file = tmp_path / "dd.log"
    log_file.write_text(
        'type=SYSCALL msg=audit(1604996384.965:93777): comm="dd" exe="/bin/dd"\n'
        'type=EXECVE msg=audit(1604996384.965:93777): a0="dd" a1="if=/dev/zero" a2="bs=1" a3="count=1"\n',
        encoding="utf-8",
    )

    loader = LogLoader()
    events = list(loader.load(str(log_file)))

    assert events[0]["source"] == "linux"
    assert events[0]["timestamp"] == "2020-11-10T08:19:44.965000Z"
    assert events[0]["process_name"] == "dd"
    assert events[0]["application"] == "/bin/dd"

    assert events[1]["source"] == "linux"
    assert events[1]["timestamp"] == "2020-11-10T08:19:44.965000Z"
    assert events[1]["command_line"] == "dd if=/dev/zero bs=1 count=1"