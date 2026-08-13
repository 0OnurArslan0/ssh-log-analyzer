"""Builds a format-agnostic report data structure and renders it as text or JSON."""

from __future__ import annotations

import json
from typing import Dict

from .detector import IPActivity

ISO_FMT = "%Y-%m-%dT%H:%M:%S"


def _iso(dt) -> str:
    return dt.strftime(ISO_FMT)


def build_report_data(
    activities: Dict[str, IPActivity],
    log_file: str,
    threshold: int,
    window_minutes: float,
    year_assumed: int,
    top_usernames: int = 10,
) -> dict:
    total_attempts = sum(a.total_attempts for a in activities.values())
    unique_ips = len(activities)

    all_timestamps = [ts for a in activities.values() for ts in a.timestamps]
    time_range = None
    if all_timestamps:
        time_range = {
            "start": _iso(min(all_timestamps)),
            "end": _iso(max(all_timestamps)),
        }

    flagged = sorted(
        (a for a in activities.values() if a.flagged),
        key=lambda a: (a.peak_window_count, a.total_attempts),
        reverse=True,
    )
    flagged_attempts = sum(a.total_attempts for a in flagged)

    flagged_ips = [
        {
            "ip": a.ip,
            "total_attempts": a.total_attempts,
            "peak_window": {
                "count": a.peak_window_count,
                "start": _iso(a.peak_window_start),
                "end": _iso(a.peak_window_end),
            },
            "first_seen": _iso(min(a.timestamps)),
            "last_seen": _iso(max(a.timestamps)),
            "usernames": dict(a.usernames.most_common(top_usernames)),
        }
        for a in flagged
    ]

    return {
        "metadata": {
            "log_file": log_file,
            "threshold": threshold,
            "window_minutes": window_minutes,
            "year_assumed": year_assumed,
        },
        "summary": {
            "total_failed_attempts": total_attempts,
            "unique_ips": unique_ips,
            "flagged_ip_count": len(flagged),
            "flagged_attempts": flagged_attempts,
            "time_range": time_range,
        },
        "flagged_ips": flagged_ips,
    }


def render_text(data: dict) -> str:
    meta = data["metadata"]
    summary = data["summary"]
    lines = []

    lines.append("SSH Auth Log Analysis Report")
    lines.append("=" * 29)
    lines.append(f"Log file: {meta['log_file']}")
    if summary["time_range"]:
        lines.append(
            f"Time range analyzed: {summary['time_range']['start']} to "
            f"{summary['time_range']['end']}"
        )
    else:
        lines.append("Time range analyzed: (no events)")
    lines.append(f"Total failed login attempts: {summary['total_failed_attempts']}")
    lines.append(f"Unique source IPs (failed logins): {summary['unique_ips']}")
    lines.append(
        f"Detection parameters: threshold={meta['threshold']} attempts / "
        f"window={meta['window_minutes']} minutes"
    )
    lines.append("")

    if not data["flagged_ips"]:
        lines.append("No brute-force activity detected.")
        return "\n".join(lines)

    lines.append(f"FLAGGED IPs (possible brute-force): {len(data['flagged_ips'])}")
    lines.append("-" * 60)
    for entry in data["flagged_ips"]:
        lines.append(f"IP: {entry['ip']}")
        lines.append(f"  Total failed attempts: {entry['total_attempts']}")
        lines.append(
            f"  Peak burst: {entry['peak_window']['count']} attempts between "
            f"{entry['peak_window']['start']} and {entry['peak_window']['end']}"
        )
        lines.append(
            f"  First seen / Last seen: {entry['first_seen']} / {entry['last_seen']}"
        )
        usernames_str = ", ".join(
            f"{user}({count})" for user, count in entry["usernames"].items()
        )
        lines.append(f"  Usernames targeted: {usernames_str}")
        lines.append("-" * 60)

    lines.append("")
    lines.append("SUMMARY")
    lines.append("-------")
    lines.append(
        f"Flagged IPs: {summary['flagged_ip_count']} / {summary['unique_ips']}"
    )
    if summary["total_failed_attempts"]:
        pct = 100 * summary["flagged_attempts"] / summary["total_failed_attempts"]
    else:
        pct = 0.0
    lines.append(
        f"Attempts from flagged IPs: {summary['flagged_attempts']} / "
        f"{summary['total_failed_attempts']} ({pct:.1f}%)"
    )

    return "\n".join(lines)


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2)
