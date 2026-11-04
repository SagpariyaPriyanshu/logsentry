"""LogSentry command-line entry point.

Usage:
    python main.py analyze sample_logs/auth.log
    python main.py --help
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

from logsentry.parsers.auth_log import parse_auth_file
from logsentry.parsers.web_log import parse_web_file
from logsentry.config import load_config
from logsentry.detectors import run_all_detectors


def analyze(args):
    """Parse a log file and print a summary. Returns 0 on success, 1 on error."""
    path = Path(args.logfile)
    if not path.exists():
        print(f"Error: file not found: {path}")
        return 1

    # if the args is web 
    if args.web:
        events, skipped = parse_web_file(path)
    else:
        events, skipped = parse_auth_file(path, year=args.year)

    print(f"Parsed {len(events):,} events, {skipped:,} lines skipped")

    if args.web:
        print("\nRequests by status code:")
        by_status = Counter(e.details["status"] for e in events)
        for status, count in sorted(by_status.items()):
            print(f"  {status:<15} {count:>5}")
    else:
        print("\nEvents by type:")
        by_type = Counter(e.event_type for e in events)
        for event_type, count in by_type.most_common():
            print(f"  {event_type:<15} {count:>5}")

    print("\nTop 5 IP addresses:")
    by_ip = Counter(e.ip for e in events if e.ip)
    for ip, count in by_ip.most_common(5):
        print(f"  {ip:<15} {count:>5}")

    alerts = run_all_detectors(events, load_config(args.config))
    print(f"\n{len(alerts)} alerts:")
    for alert in alerts:
        print(f"  [{alert.severity.upper():<6}] {alert.timestamp:%Y-%m-%d %H:%M}  "
              f"{alert.rule}: {alert.message}")

    return 0


def build_parser():
    """Describe every command and option LogSentry accepts."""
    parser = argparse.ArgumentParser(
        prog="logsentry",
        description="Mini SIEM: parse logs, detect threats, raise alerts.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = subcommands.add_parser("analyze", help="analyze a log file")
    analyze_cmd.add_argument("logfile", help="path to the log file")
    analyze_cmd.add_argument(
        "--year", type=int, default=None,
        help="year for auth.log timestamps (default: current year)",
    )
    analyze_cmd.add_argument(
        "--web", action="store_true",
        help="the file is a web server access log, not auth.log",
    )
    analyze_cmd.add_argument(
        "--config", default="config.yaml",
        help="path to the settings file (default: config.yaml)",
    )
    analyze_cmd.set_defaults(func=analyze)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()   # reads what you typed after "python main.py"
    return args.func(args)       # runs the function linked to that subcommand


if __name__ == "__main__":
    sys.exit(main())