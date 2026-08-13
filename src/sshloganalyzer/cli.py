"""Command-line entry point for ssh-log-analyzer."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import List, Optional, TextIO

from . import __version__
from .detector import DEFAULT_THRESHOLD, DEFAULT_WINDOW_MINUTES, detect
from .parser import parse_lines
from .report import build_report_data, render_json, render_text


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-log-analyzer",
        description="Detect SSH brute-force attempts in an auth.log file.",
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="-",
        help="Path to the auth.log file to analyze. Omit or pass '-' to read from stdin.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Failed attempts within the window required to flag an IP (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_WINDOW_MINUTES,
        help=f"Sliding window size in minutes (default: {DEFAULT_WINDOW_MINUTES})",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for timestamps (syslog lines have no year). Defaults to the current year.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Report output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write the report to this path instead of stdout.",
    )
    parser.add_argument(
        "--top-usernames",
        type=int,
        default=10,
        dest="top_usernames",
        help="Maximum number of usernames to list per flagged IP (default: 10)",
    )
    parser.add_argument(
        "--fail-on-detection",
        action="store_true",
        dest="fail_on_detection",
        help="Exit with status 2 if any IP is flagged.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None, stdout: Optional[TextIO] = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    args = build_arg_parser().parse_args(argv)
    year = args.year if args.year is not None else datetime.now().year

    try:
        if args.logfile == "-":
            lines = sys.stdin.readlines()
            log_label = "<stdin>"
        else:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            log_label = args.logfile
    except OSError as exc:
        print(f"error: could not read log file: {exc}", file=sys.stderr)
        return 1

    events = list(parse_lines(lines, year))
    activities = detect(events, threshold=args.threshold, window_minutes=args.window)
    data = build_report_data(
        activities,
        log_file=log_label,
        threshold=args.threshold,
        window_minutes=args.window,
        year_assumed=year,
        top_usernames=args.top_usernames,
    )

    report = render_json(data) if args.format == "json" else render_text(data)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report, file=stdout)

    if args.fail_on_detection and data["summary"]["flagged_ip_count"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
