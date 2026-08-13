import json
from datetime import datetime, timedelta

from sshloganalyzer.detector import detect
from sshloganalyzer.report import build_report_data, render_json, render_text

from conftest import make_event


def _flagged_activities():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("9.9.9.9", base + timedelta(minutes=i), username="root") for i in range(6)]
    events += [make_event("9.9.9.9", base + timedelta(minutes=i), username="admin") for i in range(6, 8)]
    events += [make_event("2.2.2.2", base), make_event("2.2.2.2", base + timedelta(hours=3))]
    return detect(events, threshold=5, window_minutes=10)


def test_build_report_data_fields():
    activities = _flagged_activities()
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    assert data["metadata"]["log_file"] == "test.log"
    assert data["metadata"]["threshold"] == 5
    assert data["summary"]["unique_ips"] == 2
    assert data["summary"]["flagged_ip_count"] == 1
    assert data["flagged_ips"][0]["ip"] == "9.9.9.9"
    assert data["flagged_ips"][0]["total_attempts"] == 8
    assert data["flagged_ips"][0]["usernames"]["root"] == 6


def test_text_report_contains_expected_sections():
    activities = _flagged_activities()
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    text = render_text(data)
    assert "SSH Auth Log Analysis Report" in text
    assert "FLAGGED IPs (possible brute-force): 1" in text
    assert "9.9.9.9" in text
    assert "2.2.2.2" not in text
    assert "SUMMARY" in text


def test_text_report_no_flagged_ips_message():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("2.2.2.2", base), make_event("2.2.2.2", base + timedelta(hours=3))]
    activities = detect(events, threshold=5, window_minutes=10)
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    text = render_text(data)
    assert "No brute-force activity detected." in text
    assert "FLAGGED IPs" not in text


def test_json_report_is_valid_and_matches_schema():
    activities = _flagged_activities()
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    parsed = json.loads(render_json(data))
    assert set(parsed.keys()) == {"metadata", "summary", "flagged_ips"}
    assert parsed["flagged_ips"][0]["ip"] == "9.9.9.9"
    assert "peak_window" in parsed["flagged_ips"][0]
    assert {"count", "start", "end"} == set(parsed["flagged_ips"][0]["peak_window"].keys())


def test_text_and_json_report_consistency():
    activities = _flagged_activities()
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    text = render_text(data)
    parsed = json.loads(render_json(data))
    assert parsed["flagged_ips"][0]["ip"] in text
    assert str(parsed["flagged_ips"][0]["total_attempts"]) in text


def test_flagged_ips_sorted_by_peak_count_desc():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = []
    # Weaker attacker: exactly 5 in-window.
    events += [make_event("1.1.1.1", base + timedelta(minutes=i * 2)) for i in range(5)]
    # Stronger attacker: 8 in-window.
    events += [make_event("2.2.2.2", base + timedelta(minutes=i)) for i in range(8)]
    activities = detect(events, threshold=5, window_minutes=10)
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    ips_in_order = [entry["ip"] for entry in data["flagged_ips"]]
    assert ips_in_order == ["2.2.2.2", "1.1.1.1"]


def test_time_range_formatting():
    activities = _flagged_activities()
    data = build_report_data(
        activities, log_file="test.log", threshold=5, window_minutes=10, year_assumed=2024
    )
    assert data["summary"]["time_range"]["start"] == "2024-01-01T10:00:00"
