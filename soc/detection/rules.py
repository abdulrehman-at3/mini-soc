"""
Rule-based detections.

Every rule function has the same shape:

    def detect_x(conn, trigger_events, cfg) -> list[Detection]

`trigger_events` is the batch of events just ingested this run (as
dicts). Rules use it only to know *which* entities (which source IPs,
which users) had new activity worth re-checking — the actual correlation
query then looks at the full rolling window from the database, so an
attack split across two separate ingest runs is still caught correctly.

Time windows are anchored to the *event* timestamps, not wall-clock time
(`datetime.now()`). This makes detection correct for offline/batch
analysis of historical logs — you get the same alerts whether you run
the pipeline the instant the attack happens or three days later — and
makes the rules trivially deterministic to unit test.
"""
from __future__ import annotations

import sqlite3
from datetime import timedelta
from typing import Iterable, List, Optional

from soc import database as db
from soc import threat_intel
from soc.models import Detection
from soc.utils import max_severity, parse_iso, to_iso


def _severity_for_count(count: int, thresholds: dict) -> Optional[str]:
    """thresholds like {8: 'MEDIUM', 15: 'HIGH', 25: 'CRITICAL'} -> the
    severity for the highest threshold `count` meets, or None."""
    hit = None
    for min_count, sev in sorted(thresholds.items()):
        if count >= min_count:
            hit = sev
    return hit


def _window(latest_ts: str, minutes: float = 0, seconds: float = 0) -> str:
    dt = parse_iso(latest_ts) - timedelta(minutes=minutes, seconds=seconds)
    return to_iso(dt)


# ---------------------------------------------------------------------------
# 1. Brute force (+ "succeeded after failing" -> account compromise)
# ---------------------------------------------------------------------------

def detect_brute_force(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    pairs = {
        (e["source_ip"], e["host"])
        for e in trigger_events
        if e["event_type"] == "auth_failure" and e["source_ip"]
    }
    for source_ip, host in pairs:
        latest = max(
            e["timestamp"] for e in trigger_events
            if e["source_ip"] == source_ip and e["host"] == host and e["event_type"] == "auth_failure"
        )
        window_start = _window(latest, minutes=cfg.BRUTE_FORCE_WINDOW_MINUTES)
        failures = db.query_events(
            conn, source_ip=source_ip, host=host, event_type="auth_failure",
            since=window_start, until=latest, order="timestamp", limit=1000,
        )
        count = len(failures)
        severity = _severity_for_count(count, cfg.BRUTE_FORCE_THRESHOLDS)
        if severity is None:
            continue

        successes = db.query_events(
            conn, source_ip=source_ip, host=host, event_type="auth_success",
            since=window_start, order="timestamp", limit=10,
        )
        event_ids = [f["id"] for f in failures]
        if successes:
            severity = "CRITICAL"
            compromised_user = successes[0]["user"]
            title = "Possible Successful Brute Force — Account Compromise Suspected"
            description = (
                f"{count} failed login attempts from {source_ip} against {host} within "
                f"{cfg.BRUTE_FORCE_WINDOW_MINUTES} minutes, followed by a SUCCESSFUL login for "
                f"user '{compromised_user}'. Treat the account as compromised until confirmed otherwise."
            )
            event_ids += [s["id"] for s in successes]
            user = compromised_user
        else:
            title = "Potential Brute Force Attack"
            distinct_users = sorted({f["user"] for f in failures if f["user"]})
            users_str = ", ".join(distinct_users[:6]) + ("..." if len(distinct_users) > 6 else "")
            description = (
                f"{count} failed login attempts from {source_ip} against {host} within "
                f"{cfg.BRUTE_FORCE_WINDOW_MINUTES} minutes (usernames tried: {users_str})."
            )
            user = None

        detections.append(Detection(
            rule_name="brute_force", severity=severity, title=title, description=description,
            source_ip=source_ip, user=user, host=host, event_ids=event_ids,
            dedup_key=f"brute_force:{source_ip}:{host}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 2. Port scan
# ---------------------------------------------------------------------------

def detect_port_scan(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    ips = {e["source_ip"] for e in trigger_events if e["event_type"] == "network_connection" and e["source_ip"]}
    for ip in ips:
        latest = max(
            e["timestamp"] for e in trigger_events
            if e["source_ip"] == ip and e["event_type"] == "network_connection"
        )
        window_start = _window(latest, seconds=cfg.PORT_SCAN_WINDOW_SECONDS)
        conns = db.query_events(
            conn, source_ip=ip, event_type="network_connection",
            since=window_start, until=latest, order="timestamp", limit=1000,
        )
        distinct_ports = {c["dest_port"] for c in conns if c["dest_port"] is not None}
        count = len(distinct_ports)
        severity = _severity_for_count(count, cfg.PORT_SCAN_THRESHOLDS)
        if severity is None:
            continue

        sensitive_hit = {p for p in distinct_ports if p in cfg.SENSITIVE_PORTS}
        if sensitive_hit:
            severity = max_severity(severity, "HIGH")
        host = conns[0]["host"]
        sensitive_str = ""
        if sensitive_hit:
            names = ", ".join(f"{p}/{cfg.SENSITIVE_PORTS[p]}" for p in sorted(sensitive_hit))
            sensitive_str = f" including sensitive services ({names})"

        detections.append(Detection(
            rule_name="port_scan", severity=severity, title="Potential Port Scan Detected",
            description=(
                f"{ip} probed {count} distinct ports on {host} within "
                f"{cfg.PORT_SCAN_WINDOW_SECONDS} seconds{sensitive_str}."
            ),
            source_ip=ip, user=None, host=host, event_ids=[c["id"] for c in conns],
            dedup_key=f"port_scan:{ip}:{host}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 3. Privilege escalation
# ---------------------------------------------------------------------------

def detect_privilege_escalation(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    groups: dict[tuple, list] = {}
    for e in trigger_events:
        if e["event_type"] != "privilege_escalation":
            continue
        groups.setdefault((e["user"], e["host"]), []).append(e)

    detections = []
    for (user, host), events in groups.items():
        events.sort(key=lambda ev: ev["timestamp"])
        # Preserve order, drop exact duplicate description text
        descriptions = list(dict.fromkeys(e["description"] or "" for e in events))
        detections.append(Detection(
            rule_name="privilege_escalation", severity="HIGH",
            title="Privilege Escalation Indicator Detected",
            description="; ".join(d for d in descriptions if d) or f"Privilege escalation indicator on {host} for user '{user}'",
            source_ip=events[0]["source_ip"], user=user, host=host,
            event_ids=[e["id"] for e in events],
            dedup_key=f"privilege_escalation:{user}:{host}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 4. Unusual login time
# ---------------------------------------------------------------------------

def detect_unusual_login_time(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    for e in trigger_events:
        if e["event_type"] != "auth_success" or not e["user"]:
            continue
        dt = parse_iso(e["timestamp"])
        outside_hours = not (cfg.BUSINESS_HOURS_START <= dt.hour < cfg.BUSINESS_HOURS_END)
        outside_days = dt.weekday() not in cfg.BUSINESS_DAYS
        if not (outside_hours or outside_days):
            continue
        reason = "outside business hours" if outside_hours else "on a non-business day"
        detections.append(Detection(
            rule_name="unusual_login_time", severity="LOW",
            title="Successful Login at Unusual Hour",
            description=(
                f"User '{e['user']}' logged into {e['host']} at {dt.strftime('%A %H:%M UTC')}, "
                f"which is {reason} (baseline: {cfg.BUSINESS_HOURS_START:02d}:00-{cfg.BUSINESS_HOURS_END:02d}:00, Mon-Fri)."
            ),
            source_ip=e["source_ip"], user=e["user"], host=e["host"], event_ids=[e["id"]],
            dedup_key=f"unusual_login_time:{e['user']}:{e['host']}:{dt.date()}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 5. Suspicious / known-bad source IP
# ---------------------------------------------------------------------------

def detect_suspicious_ip(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    ips = {e["source_ip"] for e in trigger_events if e["source_ip"]}
    for ip in ips:
        rep = threat_intel.lookup_ip(conn, ip)
        if rep.reputation not in ("malicious", "suspicious"):
            continue
        related = [e for e in trigger_events if e["source_ip"] == ip]
        severity = "HIGH" if rep.reputation == "malicious" else "MEDIUM"
        label = "Known Malicious" if rep.reputation == "malicious" else "Suspicious"
        note = rep.details.get("note", "")
        detections.append(Detection(
            rule_name="suspicious_ip", severity=severity,
            title=f"Activity from {label} IP Address",
            description=f"{ip} is flagged as {rep.reputation} ({rep.source}). {note}".strip(),
            source_ip=ip, user=related[0]["user"] if related else None,
            host=related[0]["host"] if related else None,
            event_ids=[e["id"] for e in related],
            dedup_key=f"suspicious_ip:{ip}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 6. Credential stuffing / username enumeration
# ---------------------------------------------------------------------------

def detect_credential_stuffing(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    ips = {e["source_ip"] for e in trigger_events if e["event_type"] == "auth_failure" and e["source_ip"]}
    for ip in ips:
        latest = max(
            e["timestamp"] for e in trigger_events
            if e["source_ip"] == ip and e["event_type"] == "auth_failure"
        )
        window_start = _window(latest, minutes=cfg.CREDENTIAL_STUFFING_WINDOW_MINUTES)
        events = db.query_events(
            conn, source_ip=ip, event_type="auth_failure",
            since=window_start, until=latest, order="timestamp", limit=1000,
        )
        distinct_users = sorted({e["user"] for e in events if e["user"]})
        if len(distinct_users) < cfg.CREDENTIAL_STUFFING_DISTINCT_USER_THRESHOLD:
            continue
        shown = ", ".join(distinct_users[:8]) + ("..." if len(distinct_users) > 8 else "")
        detections.append(Detection(
            rule_name="credential_stuffing", severity="HIGH",
            title="Possible Credential Stuffing / Username Enumeration",
            description=(
                f"{ip} attempted logins with {len(distinct_users)} distinct usernames "
                f"({shown}) within {cfg.CREDENTIAL_STUFFING_WINDOW_MINUTES} minutes."
            ),
            source_ip=ip, user=None, host=events[0]["host"], event_ids=[e["id"] for e in events],
            dedup_key=f"credential_stuffing:{ip}",
        ))
    return detections


# ---------------------------------------------------------------------------
# 7. Cross-host authentication failures (password spraying)
# ---------------------------------------------------------------------------

def detect_cross_host_failures(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    detections = []
    users = {e["user"] for e in trigger_events if e["event_type"] == "auth_failure" and e["user"]}
    for user in users:
        latest = max(
            e["timestamp"] for e in trigger_events
            if e["user"] == user and e["event_type"] == "auth_failure"
        )
        window_start = _window(latest, minutes=cfg.CROSS_HOST_WINDOW_MINUTES)
        events = db.query_events(
            conn, user=user, event_type="auth_failure",
            since=window_start, until=latest, order="timestamp", limit=1000,
        )
        distinct_hosts = sorted({e["host"] for e in events})
        if len(distinct_hosts) < cfg.CROSS_HOST_DISTINCT_HOST_THRESHOLD or len(events) < cfg.CROSS_HOST_MIN_FAILURES:
            continue
        detections.append(Detection(
            rule_name="cross_host_auth_failures", severity="MEDIUM",
            title="Multiple Failed Authentications Across Systems",
            description=(
                f"Account '{user}' had {len(events)} failed login attempts across "
                f"{len(distinct_hosts)} different hosts ({', '.join(distinct_hosts)}) within "
                f"{cfg.CROSS_HOST_WINDOW_MINUTES} minutes — possible password spraying or "
                f"a compromised credential being tested broadly."
            ),
            source_ip=events[0]["source_ip"], user=user, host=None,
            event_ids=[e["id"] for e in events],
            dedup_key=f"cross_host_auth_failures:{user}",
        ))
    return detections


RULES = [
    detect_brute_force,
    detect_port_scan,
    detect_privilege_escalation,
    detect_unusual_login_time,
    detect_suspicious_ip,
    detect_credential_stuffing,
    detect_cross_host_failures,
]
