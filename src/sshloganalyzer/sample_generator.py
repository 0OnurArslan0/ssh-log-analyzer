"""Generates realistic sample auth.log data for testing the analyzer.

The output mixes:
  - legitimate users (mostly successful logins, occasionally 0-3 mistyped
    passwords spread far enough apart that they can never fall inside one
    detection window)
  - background internet scanner noise (many distinct IPs, one failed
    attempt each)
  - "near miss" IPs that cluster exactly threshold-1 attempts into one
    window, to prove the detector doesn't over-flag
  - attacker IPs with one or two dense bursts of failed attempts,
    deliberately spaced so the whole burst always fits inside one
    detection window regardless of random seed

All randomness goes through a local random.Random(seed) instance so runs
are fully reproducible without touching the global `random` module state.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Set

from .detector import DEFAULT_THRESHOLD, DEFAULT_WINDOW_MINUTES

LEGIT_USERNAMES = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "mallory", "oscar", "peggy", "trent", "victor",
    "wendy", "deploy", "ubuntu", "svc-backup", "jenkins",
]

ATTACK_USERNAMES = [
    "root", "admin", "test", "ubuntu", "oracle", "guest", "postgres",
    "ec2-user", "user", "pi", "git", "www-data", "mysql", "support", "backup",
]
VALID_ATTACK_USERNAMES = {"root", "admin", "ubuntu", "ec2-user"}

_PUBLIC_FIRST_OCTETS = [45, 61, 78, 91, 103, 118, 134, 156, 178, 185, 203]


@dataclass
class GeneratedLog:
    lines: List[str] = field(default_factory=list)
    attacker_ips: Set[str] = field(default_factory=set)
    legit_ips: Set[str] = field(default_factory=set)
    near_miss_ips: Set[str] = field(default_factory=set)


def _random_public_ip(rng: random.Random) -> str:
    first = rng.choice(_PUBLIC_FIRST_OCTETS)
    rest = [rng.randint(1, 254) for _ in range(3)]
    return ".".join(str(part) for part in [first] + rest)


def _random_private_ip(rng: random.Random) -> str:
    return f"10.0.{rng.randint(1, 30)}.{rng.randint(2, 254)}"


def _format_line(dt: datetime, host: str, pid: int, message: str) -> str:
    month = dt.strftime("%b")
    day = f"{dt.day:2d}"
    time_str = dt.strftime("%H:%M:%S")
    return f"{month} {day} {time_str} {host} sshd[{pid}]: {message}"


def _failed_message(user: str, ip: str, port: int, invalid: bool) -> str:
    if invalid:
        return f"Failed password for invalid user {user} from {ip} port {port} ssh2"
    return f"Failed password for {user} from {ip} port {port} ssh2"


def _accepted_message(user: str, ip: str, port: int) -> str:
    return f"Accepted password for {user} from {ip} port {port} ssh2"


def _random_offset(rng: random.Random, duration: timedelta) -> timedelta:
    return timedelta(seconds=rng.uniform(0, duration.total_seconds()))


def _burst_timestamps(
    rng: random.Random, start: datetime, count: int, window_minutes: float
) -> List[datetime]:
    window_seconds = window_minutes * 60
    gap = (window_seconds * 0.8) / max(count, 1)
    timestamps = []
    offset = 0.0
    for _ in range(count):
        timestamps.append(start + timedelta(seconds=offset))
        offset += rng.uniform(gap * 0.5, gap)
    return timestamps


def generate_log(
    seed: int,
    *,
    start_time: datetime,
    duration_hours: int = 24,
    num_normal_users: int = 15,
    num_attackers: int = 3,
    num_near_miss: int = 2,
    num_scanner_ips: int = 30,
    host: str = "server01",
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: float = DEFAULT_WINDOW_MINUTES,
) -> GeneratedLog:
    rng = random.Random(seed)
    duration = timedelta(hours=duration_hours)
    min_gap = timedelta(minutes=window_minutes * 3)

    events = []  # list of (timestamp, line_text)
    result = GeneratedLog()

    # 1. Legitimate users: mostly successful logins, 0-3 well-spaced typos.
    usernames = list(LEGIT_USERNAMES)
    rng.shuffle(usernames)
    for i in range(num_normal_users):
        user = usernames[i % len(usernames)]
        if i >= len(usernames):
            user = f"{user}{i}"
        ip = _random_private_ip(rng)
        result.legit_ips.add(ip)

        for _ in range(rng.randint(2, 6)):
            ts = start_time + _random_offset(rng, duration)
            port = rng.randint(1024, 65535)
            pid = rng.randint(1000, 32767)
            events.append((ts, _format_line(ts, host, pid, _accepted_message(user, ip, port))))

        failure_timestamps: List[datetime] = []
        for _ in range(rng.randint(0, 3)):
            for _attempt in range(10):
                candidate = start_time + _random_offset(rng, duration)
                if all(abs((candidate - existing).total_seconds()) >= min_gap.total_seconds()
                       for existing in failure_timestamps):
                    failure_timestamps.append(candidate)
                    break
        for ts in failure_timestamps:
            port = rng.randint(1024, 65535)
            pid = rng.randint(1000, 32767)
            events.append((ts, _format_line(ts, host, pid, _failed_message(user, ip, port, invalid=False))))

    # 2. Background scanner noise: one-off failed attempts from random IPs.
    for _ in range(num_scanner_ips):
        ip = _random_public_ip(rng)
        user = rng.choice(ATTACK_USERNAMES)
        ts = start_time + _random_offset(rng, duration)
        port = rng.randint(1024, 65535)
        pid = rng.randint(1000, 32767)
        invalid = user not in VALID_ATTACK_USERNAMES
        events.append((ts, _format_line(ts, host, pid, _failed_message(user, ip, port, invalid))))

    # 3. Near-miss IPs: exactly threshold - 1 attempts clustered in one window.
    near_miss_count = max(threshold - 1, 1)
    for _ in range(num_near_miss):
        ip = _random_public_ip(rng)
        result.near_miss_ips.add(ip)
        burst_start = start_time + _random_offset(rng, duration - timedelta(minutes=window_minutes))
        for ts in _burst_timestamps(rng, burst_start, near_miss_count, window_minutes):
            user = rng.choice(ATTACK_USERNAMES)
            port = rng.randint(1024, 65535)
            pid = rng.randint(1000, 32767)
            invalid = user not in VALID_ATTACK_USERNAMES
            events.append((ts, _format_line(ts, host, pid, _failed_message(user, ip, port, invalid))))

    # 4. Attackers: one or two dense bursts guaranteed to fit inside one window.
    for _ in range(num_attackers):
        ip = _random_public_ip(rng)
        result.attacker_ips.add(ip)
        num_bursts = rng.randint(1, 2)
        for burst_index in range(num_bursts):
            slot = duration / num_bursts
            slot_start = start_time + slot * burst_index
            safe_slot = slot - timedelta(minutes=window_minutes)
            if safe_slot.total_seconds() <= 0:
                burst_start = slot_start
            else:
                burst_start = slot_start + _random_offset(rng, safe_slot)
            count = rng.randint(threshold + 3, threshold + 30)
            for ts in _burst_timestamps(rng, burst_start, count, window_minutes):
                user = rng.choice(ATTACK_USERNAMES)
                port = rng.randint(1024, 65535)
                pid = rng.randint(1000, 32767)
                invalid = user not in VALID_ATTACK_USERNAMES
                events.append((ts, _format_line(ts, host, pid, _failed_message(user, ip, port, invalid))))

    events.sort(key=lambda pair: pair[0])
    result.lines = [line for _, line in events]
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-log-gen-sample",
        description="Generate a realistic sample auth.log file for testing ssh-log-analyzer.",
    )
    parser.add_argument("-o", "--output", default=None, help="Output path (default: stdout)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--duration-hours", type=int, default=24, dest="duration_hours")
    parser.add_argument("--num-normal-users", type=int, default=15, dest="num_normal_users")
    parser.add_argument("--num-attackers", type=int, default=3, dest="num_attackers")
    parser.add_argument("--num-near-miss", type=int, default=2, dest="num_near_miss")
    parser.add_argument("--num-scanner-ips", type=int, default=30, dest="num_scanner_ips")
    parser.add_argument(
        "--start-time",
        default=None,
        dest="start_time",
        help="ISO8601 start time (default: now minus --duration-hours)",
    )
    parser.add_argument("--host", default="server01", help="Hostname to use in log lines")
    parser.add_argument(
        "--manifest",
        default=None,
        help="Optional path to write a JSON manifest of injected attacker/legit/near-miss IPs",
    )
    return parser


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.start_time:
        start_time = datetime.fromisoformat(args.start_time)
    else:
        start_time = datetime.now() - timedelta(hours=args.duration_hours)

    generated = generate_log(
        seed=args.seed,
        start_time=start_time,
        duration_hours=args.duration_hours,
        num_normal_users=args.num_normal_users,
        num_attackers=args.num_attackers,
        num_near_miss=args.num_near_miss,
        num_scanner_ips=args.num_scanner_ips,
        host=args.host,
    )

    text = "\n".join(generated.lines) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)

    manifest = {
        "attacker_ips": sorted(generated.attacker_ips),
        "legit_ips": sorted(generated.legit_ips),
        "near_miss_ips": sorted(generated.near_miss_ips),
    }
    if args.manifest:
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
    else:
        print(json.dumps(manifest, indent=2), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
