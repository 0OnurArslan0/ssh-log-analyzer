"""Sliding-window brute-force detection over parsed failed-login events.

For each source IP, we look at every window of `window_minutes` minutes and
find the maximum number of failed attempts that fall inside any single such
window (a true sliding window via two-pointer scan, not fixed clock-aligned
buckets -- a burst straddling a bucket boundary is still caught). An IP is
flagged when that peak count reaches `threshold`.

The window boundary is inclusive: two attempts exactly `window_minutes`
apart are still considered "within" the window.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List

from .parser import FailedLoginEvent

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10


@dataclass
class IPActivity:
    ip: str
    timestamps: List[datetime]
    usernames: Counter = field(default_factory=Counter)
    total_attempts: int = 0
    peak_window_count: int = 0
    peak_window_start: datetime = None
    peak_window_end: datetime = None
    flagged: bool = False


def detect(
    events: List[FailedLoginEvent],
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: float = DEFAULT_WINDOW_MINUTES,
) -> Dict[str, IPActivity]:
    window = timedelta(minutes=window_minutes)

    by_ip: Dict[str, List[FailedLoginEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        by_ip[event.ip].append(event)

    results: Dict[str, IPActivity] = {}
    for ip, ip_events in by_ip.items():
        timestamps = [e.timestamp for e in ip_events]

        left = 0
        peak_count = 1
        peak_lo = peak_hi = timestamps[0]
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count > peak_count:
                peak_count = count
                peak_lo = timestamps[left]
                peak_hi = timestamps[right]

        results[ip] = IPActivity(
            ip=ip,
            timestamps=timestamps,
            usernames=Counter(e.username for e in ip_events),
            total_attempts=len(ip_events),
            peak_window_count=peak_count,
            peak_window_start=peak_lo,
            peak_window_end=peak_hi,
            flagged=peak_count >= threshold,
        )

    return results
