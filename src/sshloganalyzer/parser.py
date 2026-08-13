"""Parsing of sshd "Failed password" lines from standard syslog auth.log files.

Only failed-password authentication events are extracted. Everything else
(Accepted password/publickey, PAM messages, bare "Invalid user" lines without
a paired failure, disconnects, non-sshd lines, blank/malformed lines) is
silently skipped by returning None -- a corrupt line must never crash a run
over a large log file.

Syslog timestamps carry no year, so callers must supply one via `year`
(the CLI defaults this to the current year). Logs that cross a Dec->Jan
boundary need to be split and analyzed with two separate `--year` runs;
there is no auto-detection of the rollover.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

FAILED_PW_RE = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) "
    r"port (?P<port>\d+) ssh2$"
)


@dataclass
class FailedLoginEvent:
    timestamp: datetime
    ip: str
    username: str
    invalid_user: bool
    port: int
    raw_line: str


def parse_line(line: str, year: int) -> Optional[FailedLoginEvent]:
    """Parse a single auth.log line into a FailedLoginEvent, or None."""
    stripped = line.rstrip("\n")
    if not stripped:
        return None

    envelope = SYSLOG_RE.match(stripped)
    if envelope is None:
        return None

    body = FAILED_PW_RE.match(envelope.group("msg"))
    if body is None:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year} {envelope.group('month')} {envelope.group('day')} "
            f"{envelope.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    return FailedLoginEvent(
        timestamp=timestamp,
        ip=body.group("ip"),
        username=body.group("user"),
        invalid_user=body.group("invalid") is not None,
        port=int(body.group("port")),
        raw_line=stripped,
    )


def parse_lines(lines, year: int):
    """Parse an iterable of lines, yielding only successfully parsed events."""
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event
