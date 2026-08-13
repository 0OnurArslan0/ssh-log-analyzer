import io
import json
import subprocess
import sys
from datetime import datetime

from sshloganalyzer import cli
from sshloganalyzer.sample_generator import generate_log

START = datetime(2024, 6, 1, 0, 0, 0)


def _write_sample(tmp_path, seed=42, **kwargs):
    generated = generate_log(seed=seed, start_time=START, duration_hours=24, **kwargs)
    path = tmp_path / "auth.log"
    path.write_text("\n".join(generated.lines) + "\n")
    return path, generated


def test_end_to_end_flags_only_injected_attackers(tmp_path):
    path, generated = _write_sample(tmp_path, seed=42, num_attackers=3, num_near_miss=2)

    out = io.StringIO()
    exit_code = cli.main(
        [str(path), "--format", "json", "--year", str(START.year)], stdout=out
    )
    assert exit_code == 0

    report = json.loads(out.getvalue())
    flagged_ips = {entry["ip"] for entry in report["flagged_ips"]}

    assert flagged_ips == generated.attacker_ips
    assert flagged_ips.isdisjoint(generated.legit_ips)
    assert flagged_ips.isdisjoint(generated.near_miss_ips)


def test_stdin_variant(tmp_path, monkeypatch):
    path, generated = _write_sample(tmp_path, seed=7, num_attackers=2, num_near_miss=1)
    monkeypatch.setattr(sys, "stdin", io.StringIO(path.read_text()))

    out = io.StringIO()
    exit_code = cli.main(["-", "--format", "json", "--year", str(START.year)], stdout=out)
    assert exit_code == 0

    report = json.loads(out.getvalue())
    flagged_ips = {entry["ip"] for entry in report["flagged_ips"]}
    assert flagged_ips == generated.attacker_ips


def test_fail_on_detection_exit_code(tmp_path):
    path, _ = _write_sample(tmp_path, seed=3, num_attackers=1, num_near_miss=0)
    out = io.StringIO()
    exit_code = cli.main(
        [str(path), "--fail-on-detection", "--year", str(START.year)], stdout=out
    )
    assert exit_code == 2


def test_clean_log_exits_zero_even_with_fail_on_detection(tmp_path):
    path, _ = _write_sample(
        tmp_path, seed=99, num_attackers=0, num_near_miss=0, num_scanner_ips=5
    )
    out = io.StringIO()
    exit_code = cli.main(
        [str(path), "--fail-on-detection", "--year", str(START.year)], stdout=out
    )
    assert exit_code == 0


def test_installed_console_script_smoke_test(tmp_path):
    path, generated = _write_sample(tmp_path, seed=42, num_attackers=3, num_near_miss=2)
    result = subprocess.run(
        [
            sys.executable, "-m", "sshloganalyzer",
            str(path), "--format", "json", "--year", str(START.year),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(result.stdout)
    flagged_ips = {entry["ip"] for entry in report["flagged_ips"]}
    assert flagged_ips == generated.attacker_ips
