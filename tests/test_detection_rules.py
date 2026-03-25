from soclog.detect.rules import PythonHTTPServerExecutionRule


def test_python_http_server_rule_matches_exact_command():
    rule = PythonHTTPServerExecutionRule()

    event = {
        "event_id": "4688",
        "event_type": "process",
        "host": "WS-01",
        "user": "admin",
        "process_name": r"C:\Python39\python.exe",
        "command_line": "python -m http.server 8000",
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["rule_name"] == "python_http_server_execution"
    assert alert["severity"] == "HIGH"


def test_python_http_server_rule_does_not_match_wrong_event_id():
    rule = PythonHTTPServerExecutionRule()

    event = {
        "event_id": "5156",
        "event_type": "network",
        "host": "WS-01",
        "user": "admin",
        "process_name": r"C:\Python39\python.exe",
        "command_line": "python -m http.server 8000",
    }

    alert = rule.match(event)

    assert alert is None


def test_python_http_server_rule_does_not_match_unrelated_process_event():
    rule = PythonHTTPServerExecutionRule()

    event = {
        "event_id": "4688",
        "event_type": "process",
        "host": "WS-01",
        "user": "admin",
        "process_name": r"C:\Windows\System32\cmd.exe",
        "command_line": "ipconfig /all",
    }

    alert = rule.match(event)

    assert alert is None


def test_python_http_server_rule_matches_pythonexe_with_httpserver():
    rule = PythonHTTPServerExecutionRule()

    event = {
        "event_id": "4688",
        "event_type": "process",
        "host": "WS-01",
        "user": "admin",
        "process_name": r"C:\Python39\python.exe",
        "command_line": r'C:\Python39\python.exe -m http.server 9000',
    }

    alert = rule.match(event)

    assert alert is not None
    assert alert["category"] == "execution"