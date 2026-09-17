#!/usr/bin/env python3
"""
Mini-SOC command-line interface.

Quickstart:
    python cli.py demo              # generate a week of logs + run the pipeline
    python cli.py create-user       # create your analyst login
    python run_dashboard.py         # start the web dashboard

Day-to-day (once you're wiring in real logs instead of the demo data):
    python cli.py ingest            # read any new lines from configured log sources
    python cli.py detect            # run rules + anomaly detection over what's new
    python cli.py run                 # ingest + detect in one step (what you'd cron)
"""
from __future__ import annotations

import argparse
import getpass
import sys
from datetime import timedelta

import config
from soc import alerting, database as db, incidents, reports, search
from soc.detection.engine import run_detection_pipeline
from soc.log_collector import collect_new_events
from soc.log_generator import ATTACK_INJECTORS, generate_all, simulate_attack
from soc.utils import now_iso, now_utc, to_iso


def _connect():
    return db.get_connection(config.DB_PATH)


def _print_header(text: str) -> None:
    print(f"\n== {text} ==")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init_db(args: argparse.Namespace) -> None:
    conn = _connect()
    print(f"Database ready at {config.DB_PATH}")
    conn.close()


def cmd_create_user(args: argparse.Namespace) -> None:
    from werkzeug.security import generate_password_hash

    conn = _connect()
    username = args.username or input("Username: ").strip()
    if not username:
        print("Username cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if db.get_user_by_username(conn, username):
        print(f"User '{username}' already exists.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords did not match.", file=sys.stderr)
            sys.exit(1)
    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    db.create_user(conn, username, generate_password_hash(password))
    print(f"Created analyst account '{username}'. Run `python run_dashboard.py` and log in.")


def cmd_generate_logs(args: argparse.Namespace) -> None:
    counts = generate_all(days=args.days, seed=args.seed)
    _print_header("Generated sample logs")
    for name, n in counts.items():
        print(f"  {name}: {n} lines")


def cmd_ingest(args: argparse.Namespace) -> dict:
    conn = _connect()
    result = collect_new_events(conn)
    _print_header("Ingest")
    print(f"  Read {result.lines_read} new lines ({result.lines_skipped} unparseable, skipped)")
    print(f"  Inserted {len(result.new_events)} normalized events")
    conn.close()
    return {"new_event_ids": [e["id"] for e in result.new_events]}


def _run_detect(conn, new_events) -> dict:
    detections = run_detection_pipeline(conn, new_events)
    summary = alerting.process_detections(conn, detections, config)
    return summary


def cmd_detect(args: argparse.Namespace) -> None:
    conn = _connect()
    # Re-check everything ingested "recently" (last 24h) rather than requiring
    # a fresh ingest in the same process — makes `detect` safe to re-run.
    since = to_iso(now_utc() - timedelta(hours=24))
    recent = db.query_events(conn, since=since, order="timestamp", limit=5000)
    summary = _run_detect(conn, recent)
    _print_header("Detect")
    print(f"  {len(summary['new_alerts'])} new alert(s), {len(summary['updated_alerts'])} updated, "
          f"{len(summary['incidents_created'])} incident(s) auto-opened")
    conn.close()


def cmd_run(args: argparse.Namespace) -> None:
    conn = _connect()
    result = collect_new_events(conn)
    _print_header("Ingest")
    print(f"  Read {result.lines_read} new lines ({result.lines_skipped} skipped), "
          f"inserted {len(result.new_events)} events")
    summary = _run_detect(conn, result.new_events)
    _print_header("Detect")
    print(f"  {len(summary['new_alerts'])} new alert(s), {len(summary['updated_alerts'])} updated, "
          f"{len(summary['incidents_created'])} incident(s) auto-opened")
    conn.close()


def cmd_demo(args: argparse.Namespace) -> None:
    counts = generate_all(days=args.days)
    _print_header("Generated sample logs")
    for name, n in counts.items():
        print(f"  {name}: {n} lines")

    conn = _connect()
    result = collect_new_events(conn)
    _print_header("Ingest")
    print(f"  Inserted {len(result.new_events)} events")

    summary = _run_detect(conn, result.new_events)
    _print_header("Detect")
    print(f"  {len(summary['new_alerts'])} new alert(s), {len(summary['updated_alerts'])} updated, "
          f"{len(summary['incidents_created'])} incident(s) auto-opened")

    stats = db.summary_stats(conn)
    _print_header("Current state")
    print(f"  Events: {stats['total_events']}   Alerts: {stats['total_alerts']} "
          f"({stats['alerts_by_severity']})   Open incidents: {stats['open_incidents']}")
    conn.close()

    print("\nNext steps:")
    print("  python cli.py create-user     # set up your analyst login (if you haven't)")
    print("  python run_dashboard.py       # then open http://127.0.0.1:5000")


def cmd_simulate(args: argparse.Namespace) -> None:
    counts = simulate_attack(args.attack)
    _print_header(f"Simulated: {args.attack}")
    for name, n in counts.items():
        if n:
            print(f"  +{n} lines -> {name}")
    print("  (synthetic log lines only — no real network activity was performed)")

    if args.run:
        conn = _connect()
        result = collect_new_events(conn)
        summary = _run_detect(conn, result.new_events)
        _print_header("Detect")
        print(f"  {len(summary['new_alerts'])} new alert(s), {len(summary['updated_alerts'])} updated, "
              f"{len(summary['incidents_created'])} incident(s) auto-opened")
        conn.close()


def cmd_search(args: argparse.Namespace) -> None:
    conn = _connect()
    results, page_info = search.search_events(
        conn, source_ip=args.ip, user=args.user, host=args.host, event_type=args.type,
        keyword=args.q, since=args.since, until=args.until, page=args.page, page_size=args.limit,
    )
    _print_header(f"Search results ({page_info['total']} total, page {page_info['page']}/{page_info['total_pages']})")
    for e in results:
        print(f"  [{e['timestamp']}] {e['event_type']:20s} ip={e['source_ip'] or '-':16s} "
              f"user={e['user'] or '-':12s} host={e['host']:14s} {e['description'] or ''}")
    conn.close()


def cmd_alerts(args: argparse.Namespace) -> None:
    conn = _connect()
    rows = db.query_alerts(conn, severity=args.severity, status=args.status, limit=args.limit)
    _print_header(f"Alerts ({len(rows)} shown)")
    for a in rows:
        print(f"  #{a['id']:<4d} [{a['severity']:8s}] {a['status']:14s} {a['title']}")
    conn.close()


def cmd_report(args: argparse.Namespace) -> None:
    conn = _connect()
    paths = reports.generate_incident_report(conn, args.incident)
    if paths is None:
        print(f"No incident #{args.incident} found.", file=sys.stderr)
        sys.exit(1)
    _print_header(f"Report for incident #{args.incident}")
    for fmt, path in paths.items():
        print(f"  {fmt.upper():5s} {path}")
    conn.close()


def cmd_stats(args: argparse.Namespace) -> None:
    conn = _connect()
    stats = db.summary_stats(conn)
    _print_header("Mini-SOC status")
    print(f"  Total events:        {stats['total_events']}")
    print(f"  Total alerts:        {stats['total_alerts']}  (open: {stats['open_alerts']})")
    print(f"  Alerts by severity:  {stats['alerts_by_severity']}")
    print(f"  Total incidents:     {stats['total_incidents']}  (open: {stats['open_incidents']})")
    print(f"  Analyst accounts:    {db.count_users(conn)}")
    conn.close()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli.py", description="Mini-SOC — Security Monitoring & Incident Detection Platform")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-db", help="Create the database and tables if they don't exist yet")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("create-user", help="Create a dashboard analyst login")
    p.add_argument("--username")
    p.add_argument("--password", help="If omitted, you'll be prompted (hidden input)")
    p.set_defaults(func=cmd_create_user)

    p = sub.add_parser("generate-logs", help="(Re)generate a week of synthetic Linux/Windows/firewall logs")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--seed", type=int, default=None)
    p.set_defaults(func=cmd_generate_logs)

    p = sub.add_parser("ingest", help="Read new lines from configured log sources into the database")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("detect", help="Run detection rules + anomaly detection over recently ingested events")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("run", help="ingest + detect in one step")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("demo", help="Full one-shot setup: generate logs, ingest, and detect")
    p.add_argument("--days", type=int, default=7)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("simulate", help="Append ONE fresh, synthetic attack scenario to the logs")
    p.add_argument("--attack", choices=sorted(ATTACK_INJECTORS), required=True)
    p.add_argument("--run", action="store_true", help="Also ingest + run detection immediately after")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("search", help="Search normalized events")
    p.add_argument("--ip"); p.add_argument("--user"); p.add_argument("--host")
    p.add_argument("--type", help="event_type, e.g. auth_failure")
    p.add_argument("--q", help="keyword search across description/raw text")
    p.add_argument("--since"); p.add_argument("--until")
    p.add_argument("--page", type=int, default=1)
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("alerts", help="List alerts")
    p.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--status", choices=["New", "Investigating", "Resolved", "False Positive", "Closed"])
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("report", help="Generate an incident report (Markdown + HTML, and PDF if fpdf2 is installed)")
    p.add_argument("--incident", type=int, required=True)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("stats", help="Quick summary of the current database state")
    p.set_defaults(func=cmd_stats)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
