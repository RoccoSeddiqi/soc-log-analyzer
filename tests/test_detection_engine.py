from soclog.detect.engine import DetectionEngine


def test_detection_engine_execution_pack_returns_alert():
    engine = DetectionEngine()

    events = [
        {
            "event_id": "4688",
            "event_type": "process",
            "host": "WS-01",
            "user": "admin",
            "process_name": r"C:\Python39\python.exe",
            "command_line": "python -m http.server 8000",
        }
    ]

    config = {
        "profile": "basic",
        "rule_pack": "execution",
    }

    alerts = engine.run(events, config)

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "python_http_server_execution"