from datetime import datetime

from sshloganalyzer.detector import detect
from sshloganalyzer.parser import parse_lines
from sshloganalyzer.sample_generator import generate_log

START = datetime(2024, 6, 1, 0, 0, 0)


def _generate(seed=42, **kwargs):
    return generate_log(seed=seed, start_time=START, duration_hours=24, **kwargs)


def test_same_seed_produces_identical_output():
    a = _generate(seed=1)
    b = _generate(seed=1)
    assert a.lines == b.lines
    assert a.attacker_ips == b.attacker_ips


def test_different_seed_produces_different_output():
    a = _generate(seed=1)
    b = _generate(seed=2)
    assert a.lines != b.lines


def test_every_line_parses_or_is_intentional_non_match():
    generated = _generate(seed=7)
    for line in generated.lines:
        # Every generated line is either a parseable failure or a recognized
        # non-failure sshd message (Accepted password) -- never garbage.
        event = next(parse_lines([line], year=START.year), None)
        if event is None:
            assert "Accepted password" in line


def test_attacker_ips_are_flagged_by_the_real_detector():
    generated = _generate(seed=3, num_attackers=3, num_near_miss=2)
    events = list(parse_lines(generated.lines, year=START.year))
    results = detect(events)
    for ip in generated.attacker_ips:
        assert results[ip].flagged is True, f"attacker {ip} was not flagged"


def test_legit_and_near_miss_ips_are_not_flagged():
    generated = _generate(seed=5, num_normal_users=15, num_near_miss=2)
    events = list(parse_lines(generated.lines, year=START.year))
    results = detect(events)
    for ip in generated.legit_ips:
        assert ip not in results or results[ip].flagged is False, f"legit {ip} was flagged"
    for ip in generated.near_miss_ips:
        assert ip not in results or results[ip].flagged is False, f"near-miss {ip} was flagged"


def test_output_lines_are_chronologically_sorted():
    generated = _generate(seed=9)
    events = list(parse_lines(generated.lines, year=START.year))
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


def test_ip_sets_are_disjoint():
    generated = _generate(seed=11)
    assert generated.attacker_ips.isdisjoint(generated.legit_ips)
    assert generated.attacker_ips.isdisjoint(generated.near_miss_ips)
    assert generated.legit_ips.isdisjoint(generated.near_miss_ips)
