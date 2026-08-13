from sshloganalyzer.parser import parse_line, parse_lines


def test_parses_invalid_user_variant():
    line = "Mar 15 10:23:45 hostA sshd[12341]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    event = parse_line(line, year=2024)
    assert event is not None
    assert event.username == "admin"
    assert event.invalid_user is True
    assert event.ip == "192.168.1.100"
    assert event.port == 54321
    assert event.timestamp.year == 2024
    assert event.timestamp.month == 3
    assert event.timestamp.day == 15
    assert event.timestamp.hour == 10
    assert event.timestamp.minute == 23
    assert event.timestamp.second == 45


def test_parses_known_user_variant():
    line = "Mar 15 10:24:02 hostA sshd[12342]: Failed password for root from 192.168.1.100 port 54322 ssh2"
    event = parse_line(line, year=2024)
    assert event is not None
    assert event.username == "root"
    assert event.invalid_user is False


def test_ignores_accepted_password():
    line = "Mar 15 10:23:41 hostA sshd[12340]: Accepted password for alice from 10.0.1.5 port 51234 ssh2"
    assert parse_line(line, year=2024) is None


def test_ignores_accepted_publickey():
    line = "Mar 15 10:23:41 hostA sshd[12340]: Accepted publickey for alice from 10.0.1.5 port 51234 ssh2"
    assert parse_line(line, year=2024) is None


def test_ignores_bare_invalid_user_line():
    line = "Mar 15 10:40:00 hostA sshd[12352]: Invalid user nosuchuser from 203.0.113.9"
    assert parse_line(line, year=2024) is None


def test_ignores_pam_line():
    line = "Mar 15 10:40:01 hostA sshd[12353]: PAM: Authentication failure for illegal user nosuchuser from 203.0.113.9"
    assert parse_line(line, year=2024) is None


def test_ignores_disconnect_line():
    line = "Mar 15 10:41:00 hostA sshd[12354]: Received disconnect from 203.0.113.9 port 33333:11: Bye Bye [preauth]"
    assert parse_line(line, year=2024) is None


def test_ignores_non_sshd_line():
    line = "Mar 15 10:23:45 hostA notsshd[12341]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_line(line, year=2024) is None


def test_ignores_blank_line():
    assert parse_line("", year=2024) is None
    assert parse_line("\n", year=2024) is None


def test_ignores_garbage_line_without_raising():
    assert parse_line("this is not a valid syslog line at all", year=2024) is None


def test_ignores_invalid_day_without_raising():
    line = "Mar 32 10:23:45 hostA sshd[12341]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_line(line, year=2024) is None


def test_ignores_non_numeric_port():
    line = "Mar 15 10:23:45 hostA sshd[12341]: Failed password for root from 1.2.3.4 port abc ssh2"
    assert parse_line(line, year=2024) is None


def test_single_digit_day_with_double_space_padding():
    line = "Mar  5 05:02:11 hostA sshd[12351]: Failed password for invalid user pi from 198.51.100.23 port 40010 ssh2"
    event = parse_line(line, year=2024)
    assert event is not None
    assert event.timestamp.day == 5
    assert event.timestamp.hour == 5


def test_parses_ipv6_source_address():
    line = "Mar 15 10:45:00 hostA sshd[12360]: Failed password for invalid user oracle from 2001:db8::1 port 42000 ssh2"
    event = parse_line(line, year=2024)
    assert event is not None
    assert event.ip == "2001:db8::1"


def test_year_is_applied_verbatim():
    line = "Mar 15 10:23:45 hostA sshd[12341]: Failed password for root from 1.2.3.4 port 22 ssh2"
    event = parse_line(line, year=1999)
    assert event.timestamp.year == 1999


def test_parse_lines_skips_none_and_never_raises(malformed_log_lines):
    events = list(parse_lines(malformed_log_lines, year=2024))
    assert events == []


def test_parse_lines_against_fixture_file(sample_auth_log_lines):
    events = list(parse_lines(sample_auth_log_lines, year=2024))
    # Only the "Failed password" lines in the fixture should parse.
    assert len(events) == 8
    ips = {e.ip for e in events}
    assert "192.168.1.100" in ips
    assert "2001:db8::1" in ips
