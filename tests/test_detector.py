from datetime import datetime, timedelta

from sshloganalyzer.detector import detect

from conftest import make_event


def test_exactly_at_threshold_is_flagged():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("1.2.3.4", base + timedelta(minutes=i * 2)) for i in range(5)]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is True
    assert results["1.2.3.4"].peak_window_count == 5


def test_just_under_threshold_is_not_flagged():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("1.2.3.4", base + timedelta(minutes=i * 2)) for i in range(4)]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is False
    assert results["1.2.3.4"].peak_window_count == 4


def test_inclusive_boundary_exactly_window_minutes_apart():
    base = datetime(2024, 1, 1, 10, 0, 0)
    # 5th event lands exactly 10 minutes after the 1st.
    events = [
        make_event("1.2.3.4", base),
        make_event("1.2.3.4", base + timedelta(minutes=2)),
        make_event("1.2.3.4", base + timedelta(minutes=4)),
        make_event("1.2.3.4", base + timedelta(minutes=6)),
        make_event("1.2.3.4", base + timedelta(minutes=10)),
    ]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is True
    assert results["1.2.3.4"].peak_window_count == 5


def test_one_second_over_window_is_not_flagged():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [
        make_event("1.2.3.4", base),
        make_event("1.2.3.4", base + timedelta(minutes=2)),
        make_event("1.2.3.4", base + timedelta(minutes=4)),
        make_event("1.2.3.4", base + timedelta(minutes=6)),
        make_event("1.2.3.4", base + timedelta(minutes=10, seconds=1)),
    ]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is False
    assert results["1.2.3.4"].peak_window_count == 4


def test_bucket_vs_sliding_window_straddle_case():
    """A naive fixed 10-minute bucket (e.g. floor to :00/:10) would split
    07,08,09 into one bucket and 11,12 into the next, missing the attack.
    The sliding window must still catch all 5 within a <=10min span."""
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [
        make_event("1.2.3.4", base + timedelta(minutes=7)),
        make_event("1.2.3.4", base + timedelta(minutes=8)),
        make_event("1.2.3.4", base + timedelta(minutes=9)),
        make_event("1.2.3.4", base + timedelta(minutes=11)),
        make_event("1.2.3.4", base + timedelta(minutes=12)),
    ]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is True
    assert results["1.2.3.4"].peak_window_count == 5


def test_multiple_ips_no_cross_contamination():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = []
    # Attacker: 6 rapid attempts.
    for i in range(6):
        events.append(make_event("1.1.1.1", base + timedelta(minutes=i)))
    # Legit-ish: 2 attempts far apart, interleaved in time with the attacker.
    events.append(make_event("2.2.2.2", base))
    events.append(make_event("2.2.2.2", base + timedelta(hours=2)))
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.1.1.1"].flagged is True
    assert results["1.1.1.1"].total_attempts == 6
    assert results["2.2.2.2"].flagged is False
    assert results["2.2.2.2"].total_attempts == 2


def test_empty_input():
    assert detect([], threshold=5, window_minutes=10) == {}


def test_single_event():
    base = datetime(2024, 1, 1, 10, 0, 0)
    results = detect([make_event("1.2.3.4", base)], threshold=5, window_minutes=10)
    assert results["1.2.3.4"].peak_window_count == 1
    assert results["1.2.3.4"].flagged is False


def test_unsorted_input_is_handled_correctly():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("1.2.3.4", base + timedelta(minutes=i * 2)) for i in range(5)]
    events.reverse()
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].flagged is True
    assert results["1.2.3.4"].timestamps == sorted(results["1.2.3.4"].timestamps)


def test_custom_threshold_and_window():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [make_event("1.2.3.4", base + timedelta(minutes=i)) for i in range(3)]
    results = detect(events, threshold=3, window_minutes=5)
    assert results["1.2.3.4"].flagged is True

    results_strict = detect(events, threshold=4, window_minutes=5)
    assert results_strict["1.2.3.4"].flagged is False


def test_username_counter_correctness():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [
        make_event("1.2.3.4", base, username="root"),
        make_event("1.2.3.4", base + timedelta(minutes=1), username="root"),
        make_event("1.2.3.4", base + timedelta(minutes=2), username="admin"),
    ]
    results = detect(events, threshold=5, window_minutes=10)
    assert results["1.2.3.4"].usernames["root"] == 2
    assert results["1.2.3.4"].usernames["admin"] == 1


def test_peak_window_bounds_correctness():
    base = datetime(2024, 1, 1, 10, 0, 0)
    events = [
        make_event("1.2.3.4", base),
        make_event("1.2.3.4", base + timedelta(minutes=3)),
        make_event("1.2.3.4", base + timedelta(minutes=6)),
        make_event("1.2.3.4", base + timedelta(minutes=9)),
        make_event("1.2.3.4", base + timedelta(minutes=25)),
    ]
    results = detect(events, threshold=4, window_minutes=10)
    activity = results["1.2.3.4"]
    assert activity.peak_window_count == 4
    assert activity.peak_window_start == base
    assert activity.peak_window_end == base + timedelta(minutes=9)
