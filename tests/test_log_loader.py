from pathlib import Path
import pytest

from soclog.io.log_loader import LogLoader

try:
    from soclog.io.log_loader import LogValidationError
except Exception:
    LogValidationError = Exception

FIX = Path(__file__).parent / "fixtures"


def test_load_valid_json():
    loader = LogLoader()
    events = list(loader.load(str(FIX / "valid.json")))
    assert len(events) == 2
    assert isinstance(events[0], dict)


def test_load_invalid_json_raises():
    loader = LogLoader()
    with pytest.raises(Exception):
        list(loader.load(str(FIX / "invalid.json")))


def test_load_valid_jsonl():
    loader = LogLoader()
    events = list(loader.load(str(FIX / "valid.jsonl")))
    assert len(events) == 2
    assert isinstance(events[0], dict)


def test_load_invalid_jsonl_raises():
    loader = LogLoader()
    with pytest.raises(Exception):
        list(loader.load(str(FIX / "invalid.jsonl")))


def test_load_valid_csv():
    loader = LogLoader()
    events = list(loader.load(str(FIX / "valid.csv")))
    assert len(events) == 2
    assert isinstance(events[0], dict)
    assert "timestamp" in events[0]


def test_load_invalid_csv_raises():
    loader = LogLoader()
    with pytest.raises(Exception):
        list(loader.load(str(FIX / "invalid.csv")))
