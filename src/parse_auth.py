#!/usr/bin/env python3
"""Parse Linux SSH authentication logs and summarize failed-login activity."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

# Example:
# Nov  6 10:14:22 server sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2
SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
)

FAILED_PATTERNS = [
    re.compile(
        r"sshd\[\d+\]: Failed password for (?:invalid user )?"
        r"(?P<username>[A-Za-z0-9_.@-]+) from "
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)"
    ),
    re.compile(
        r"sshd\[\d+\]: Invalid user (?P<username>[A-Za-z0-9_.@-]+) from "
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)"
    ),
    re.compile(
        r"authentication failure;.*?user=(?P<username>\S*).*?"
        r"rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)"
    ),
]


def parse_line(line: str, year: int) -> dict | None:
    """Return one normalized failed-authentication event, or None."""
    prefix = SYSLOG_PREFIX.match(line)
    if not prefix:
        return None

    event_match = None
    for pattern in FAILED_PATTERNS:
        event_match = pattern.search(line)
        if event_match:
            break
    if not event_match:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year} {prefix.group('timestamp')}", "%Y %b %d %H:%M:%S"
        ).isoformat(sep=" ")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "host": prefix.group("host"),
        "source_ip": event_match.group("ip"),
        "username": event_match.group("username") or "unknown",
        "event_type": "failed_authentication",
        "raw_log": line.rstrip("\n"),
    }


def analyze_log(input_path: Path, output_dir: Path, year: int, top_n: int) -> dict:
    events = []
    with input_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            event = parse_line(line, year)
            if event:
                events.append(event)

    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / "auth_events.csv"
    fieldnames = ["timestamp", "host", "source_ip", "username", "event_type", "raw_log"]
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    ip_counts = Counter(event["source_ip"] for event in events)
    username_counts = Counter(event["username"] for event in events)
    ranked_ips = [
        {"source_ip": ip, "failed_attempts": count}
        for ip, count in ip_counts.most_common(top_n)
    ]

    report = {
        "source_file": str(input_path),
        "total_failed_events": len(events),
        "unique_source_ips": len(ip_counts),
        "unique_targeted_accounts": len(username_counts),
        "top_attacking_ips": ranked_ips,
        "targeted_accounts": [
            {"username": user, "attempts": count}
            for user, count in username_counts.most_common()
        ],
        "events": events,
    }

    json_path = output_dir / "failed_logins.json"
    with json_path.open("w", encoding="utf-8") as json_file:
        json.dump(report, json_file, indent=2)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract failed SSH authentication events and rank source IPs."
    )
    parser.add_argument(
        "--input", type=Path, default=Path("samples/auth.log"),
        help="Path to a Linux auth.log file (default: samples/auth.log)"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("output"),
        help="Directory for CSV and JSON reports (default: output)"
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year to attach to syslog timestamps (default: current year)"
    )
    parser.add_argument(
        "--top", type=int, default=10,
        help="Number of source IPs to show in the terminal summary (default: 10)"
    )
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")
    if not args.input.is_file():
        parser.error(f"Input log file not found: {args.input}")

    report = analyze_log(args.input, args.output_dir, args.year, args.top)

    print("\n=== AUTHENTICATION LOG ANALYSIS ===")
    print(f"Input file              : {args.input}")
    print(f"Failed events extracted : {report['total_failed_events']}")
    print(f"Unique source IPs       : {report['unique_source_ips']}")
    print(f"Targeted accounts       : {report['unique_targeted_accounts']}")
    print("\nTop source IPs:")
    if report["top_attacking_ips"]:
        for rank, item in enumerate(report["top_attacking_ips"], start=1):
            print(f"{rank:>2}. {item['source_ip']:<18} {item['failed_attempts']} attempts")
    else:
        print("No failed authentication events found.")
    print(f"\nCSV report : {args.output_dir / 'auth_events.csv'}")
    print(f"JSON report: {args.output_dir / 'failed_logins.json'}")


if __name__ == "__main__":
    main()
