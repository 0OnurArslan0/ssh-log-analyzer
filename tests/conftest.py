from datetime import datetime
from pathlib import Path

import pytest

from sshloganalyzer.parser import FailedLoginEvent

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_event(ip, ts, username="root", invalid=True, port=22):
    """Build a FailedLoginEvent directly, bypassing line parsing."""
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    return FailedLoginEvent(
        timestamp=ts,
        ip=ip,
        username=username,
        invalid_user=invalid,
        port=port,
        raw_line=f"<synthetic event for {ip}>",
    )


@pytest.fixture
def sample_auth_log_lines():
    return (FIXTURES_DIR / "sample_auth.log").read_text().splitlines()


@pytest.fixture
def malformed_log_lines():
    return (FIXTURES_DIR / "malformed_lines.log").read_text().splitlines()


@pytest.fixture
def tmp_auth_log(tmp_path):
    def _write(content: str):
        path = tmp_path / "auth.log"
        path.write_text(content)
        return path

    return _write
