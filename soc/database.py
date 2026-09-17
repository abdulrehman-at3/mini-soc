"""
SQLite data access layer.

Design choices worth calling out:
- Plain `sqlite3` + hand-written SQL, not an ORM. For a project this size
  it keeps every query visible and easy to reason about (and to explain
  in an interview).
- Every function takes a `conn` as its first argument (dependency
  injection) instead of managing its own connection. This makes the whole
  module trivially unit-testable against an in-memory database and lets
  the Flask layer manage one connection per request.
- Schema creation (`ensure_schema`) is idempotent and is called from
  `get_connection`, so it is impossible to hit a "no such table" error
  even if you forget to run `cli.py init-db` first.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence

from soc.models import Detection, NormalizedEvent
from soc.utils import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    user TEXT,
    host TEXT NOT NULL,
    os TEXT NOT NULL,
    status TEXT,
    description TEXT,
    source_format TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    metadata TEXT,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

CREATE TABLE IF NOT EXISTS ingest_state (
    file_path TEXT PRIMARY KEY,
    lines_ingested INTEGER NOT NULL DEFAULT 0,
    last_ingested_at TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    assigned_to TEXT,
    closed_at TEXT,
    resolution TEXT,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    author TEXT,
    note TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    source_ip TEXT,
    user TEXT,
    host TEXT,
    event_count INTEGER NOT NULL DEFAULT 1,
    first_event_at TEXT,
    last_event_at TEXT,
    dedup_key TEXT,
    incident_id INTEGER,
    metadata TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip TEXT PRIMARY KEY,
    reputation TEXT NOT NULL,
    source TEXT,
    details TEXT,
    checked_at TEXT NOT NULL
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open (and lazily create) the database, returning a connection with
    dict-like row access and foreign keys enabled."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True) if db_path != ":memory:" else None
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[dict]:
    return dict(row) if row is not None else None


def _rows_to_dicts(rows: Iterable[sqlite3.Row]) -> List[dict]:
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Users (dashboard authentication)
# ---------------------------------------------------------------------------

def count_users(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]


def create_user(conn: sqlite3.Connection, username: str, password_hash: str, role: str = "analyst") -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, password_hash, role, now_iso()),
    )
    conn.commit()
    return cur.lastrowid


def get_user_by_username(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return _row_to_dict(row)


def get_user(conn: sqlite3.Connection, user_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_dict(row)


# ---------------------------------------------------------------------------
# Ingest state (tracks how much of each raw log file has been read)
# ---------------------------------------------------------------------------

def get_ingest_offset(conn: sqlite3.Connection, file_path: str) -> int:
    row = conn.execute("SELECT lines_ingested FROM ingest_state WHERE file_path = ?", (file_path,)).fetchone()
    return row["lines_ingested"] if row else 0


def set_ingest_offset(conn: sqlite3.Connection, file_path: str, lines: int) -> None:
    conn.execute(
        """INSERT INTO ingest_state (file_path, lines_ingested, last_ingested_at)
           VALUES (?, ?, ?)
           ON CONFLICT(file_path) DO UPDATE SET lines_ingested = excluded.lines_ingested,
                                                 last_ingested_at = excluded.last_ingested_at""",
        (file_path, lines, now_iso()),
    )
    conn.commit()


def reset_ingest_state(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM ingest_state")
    conn.commit()


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(conn: sqlite3.Connection, event: NormalizedEvent) -> int:
    cur = conn.execute(
        """INSERT INTO events
           (timestamp, event_type, source_ip, dest_ip, dest_port, protocol, user,
            host, os, status, description, source_format, raw_text, metadata, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event.timestamp, event.event_type, event.source_ip, event.dest_ip,
            event.dest_port, event.protocol, event.user, event.host, event.os,
            event.status, event.description, event.source_format, event.raw_text,
            json.dumps(event.metadata or {}), now_iso(),
        ),
    )
    return cur.lastrowid


def count_all_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]


def get_event(conn: sqlite3.Connection, event_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return _row_to_dict(row)


def get_events_by_ids(conn: sqlite3.Connection, event_ids: Sequence[int]) -> List[dict]:
    if not event_ids:
        return []
    placeholders = ",".join("?" for _ in event_ids)
    rows = conn.execute(
        f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY timestamp", list(event_ids)
    ).fetchall()
    return _rows_to_dicts(rows)


ALLOWED_ORDER_COLUMNS = {
    "timestamp": "timestamp", "-timestamp": "timestamp DESC",
    "id": "id", "-id": "id DESC",
}


def query_events(
    conn: sqlite3.Connection,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    os: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    keyword: Optional[str] = None,
    order: str = "-timestamp",
    limit: int = 50,
    offset: int = 0,
) -> List[dict]:
    clauses, params = [], []
    if source_ip:
        clauses.append("source_ip = ?"); params.append(source_ip)
    if user:
        clauses.append("user = ?"); params.append(user)
    if host:
        clauses.append("host = ?"); params.append(host)
    if event_type:
        clauses.append("event_type = ?"); params.append(event_type)
    if status:
        clauses.append("status = ?"); params.append(status)
    if os:
        clauses.append("os = ?"); params.append(os)
    if since:
        clauses.append("timestamp >= ?"); params.append(since)
    if until:
        clauses.append("timestamp <= ?"); params.append(until)
    if keyword:
        clauses.append("(raw_text LIKE ? OR description LIKE ? OR user LIKE ? OR source_ip LIKE ? OR host LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw, kw, kw]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order_sql = ALLOWED_ORDER_COLUMNS.get(order, "timestamp DESC")
    sql = f"SELECT * FROM events {where} ORDER BY {order_sql} LIMIT ? OFFSET ?"
    rows = conn.execute(sql, [*params, limit, offset]).fetchall()
    return _rows_to_dicts(rows)


def count_events(
    conn: sqlite3.Connection,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    os: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    keyword: Optional[str] = None,
) -> int:
    clauses, params = [], []
    if source_ip:
        clauses.append("source_ip = ?"); params.append(source_ip)
    if user:
        clauses.append("user = ?"); params.append(user)
    if host:
        clauses.append("host = ?"); params.append(host)
    if event_type:
        clauses.append("event_type = ?"); params.append(event_type)
    if status:
        clauses.append("status = ?"); params.append(status)
    if os:
        clauses.append("os = ?"); params.append(os)
    if since:
        clauses.append("timestamp >= ?"); params.append(since)
    if until:
        clauses.append("timestamp <= ?"); params.append(until)
    if keyword:
        clauses.append("(raw_text LIKE ? OR description LIKE ? OR user LIKE ? OR source_ip LIKE ? OR host LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw, kw, kw]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT COUNT(*) AS c FROM events {where}"
    return conn.execute(sql, params).fetchone()["c"]


def events_grouped_count(conn: sqlite3.Connection, group_by: str, since: Optional[str] = None, limit: int = 10) -> List[dict]:
    """Small aggregate helper used by the dashboard (e.g. top source IPs)."""
    if group_by not in {"source_ip", "event_type", "user", "host"}:
        raise ValueError("invalid group_by column")
    where = f"WHERE {group_by} IS NOT NULL"
    params: List[Any] = []
    if since:
        where += " AND timestamp >= ?"
        params.append(since)
    sql = f"SELECT {group_by} AS key, COUNT(*) AS c FROM events {where} GROUP BY {group_by} ORDER BY c DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return _rows_to_dicts(rows)


def events_timeseries(conn: sqlite3.Connection, bucket_hours: int = 1, since: Optional[str] = None) -> List[dict]:
    """Bucketed event counts for the dashboard timeline chart. Bucketing is
    done in Python (portable across SQLite builds) rather than relying on
    SQLite date functions with variable format strings."""
    from soc.utils import parse_iso

    rows = conn.execute(
        "SELECT timestamp FROM events WHERE timestamp >= ? ORDER BY timestamp", (since,)
    ).fetchall() if since else conn.execute("SELECT timestamp FROM events ORDER BY timestamp").fetchall()

    buckets: dict[str, int] = {}
    for row in rows:
        dt = parse_iso(row["timestamp"])
        bucket_epoch_hours = int(dt.timestamp() // (3600 * bucket_hours))
        key = str(bucket_epoch_hours)
        buckets[key] = buckets.get(key, 0) + 1
    from soc.utils import now_utc
    import datetime as _dt
    out = []
    for key, count in sorted(buckets.items(), key=lambda kv: int(kv[0])):
        bucket_epoch_hours = int(key)
        label_dt = _dt.datetime.fromtimestamp(bucket_epoch_hours * 3600 * bucket_hours, tz=_dt.timezone.utc)
        out.append({"bucket": label_dt.isoformat(), "count": count})
    return out


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def find_open_alert_by_dedup(conn: sqlite3.Connection, dedup_key: str, open_statuses: Sequence[str]) -> Optional[dict]:
    placeholders = ",".join("?" for _ in open_statuses)
    row = conn.execute(
        f"""SELECT * FROM alerts WHERE dedup_key = ? AND status IN ({placeholders})
            ORDER BY id DESC LIMIT 1""",
        (dedup_key, *open_statuses),
    ).fetchone()
    return _row_to_dict(row)


def insert_alert(conn: sqlite3.Connection, detection: Detection) -> int:
    ts = now_iso()
    cur = conn.execute(
        """INSERT INTO alerts
           (created_at, updated_at, rule_name, title, description, severity, status,
            source_ip, user, host, event_count, first_event_at, last_event_at, dedup_key, metadata)
           VALUES (?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ts, ts, detection.rule_name, detection.title, detection.description, detection.severity,
            detection.source_ip, detection.user, detection.host, len(detection.event_ids) or 1,
            ts, ts, detection.dedup_key, json.dumps(detection.metadata or {}),
        ),
    )
    alert_id = cur.lastrowid
    link_alert_events(conn, alert_id, detection.event_ids)
    conn.commit()
    return alert_id


def update_alert_from_detection(conn: sqlite3.Connection, alert_id: int, detection: Detection, new_severity: str) -> None:
    conn.execute(
        """UPDATE alerts SET updated_at = ?, severity = ?, description = ?,
                              event_count = ?, last_event_at = ? WHERE id = ?""",
        (now_iso(), new_severity, detection.description, len(detection.event_ids), now_iso(), alert_id),
    )
    link_alert_events(conn, alert_id, detection.event_ids)
    conn.commit()


def link_alert_events(conn: sqlite3.Connection, alert_id: int, event_ids: Sequence[int]) -> None:
    for eid in event_ids:
        conn.execute(
            "INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", (alert_id, eid)
        )


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_dict(row)


def get_alert_event_ids(conn: sqlite3.Connection, alert_id: int) -> List[int]:
    rows = conn.execute("SELECT event_id FROM alert_events WHERE alert_id = ?", (alert_id,)).fetchall()
    return [r["event_id"] for r in rows]


def query_alerts(
    conn: sqlite3.Connection,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    incident_id: Optional[int] = None,
    keyword: Optional[str] = None,
    order: str = "-id",
    limit: int = 50,
    offset: int = 0,
) -> List[dict]:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    if status:
        clauses.append("status = ?"); params.append(status)
    if rule_name:
        clauses.append("rule_name = ?"); params.append(rule_name)
    if source_ip:
        clauses.append("source_ip = ?"); params.append(source_ip)
    if incident_id is not None:
        clauses.append("incident_id = ?"); params.append(incident_id)
    if keyword:
        clauses.append("(title LIKE ? OR description LIKE ? OR source_ip LIKE ? OR user LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw, kw]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order_sql = ALLOWED_ORDER_COLUMNS.get(order, "id DESC")
    sql = f"SELECT * FROM alerts {where} ORDER BY {order_sql} LIMIT ? OFFSET ?"
    rows = conn.execute(sql, [*params, limit, offset]).fetchall()
    return _rows_to_dicts(rows)


def count_alerts(
    conn: sqlite3.Connection,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    incident_id: Optional[int] = None,
    keyword: Optional[str] = None,
) -> int:
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    if status:
        clauses.append("status = ?"); params.append(status)
    if rule_name:
        clauses.append("rule_name = ?"); params.append(rule_name)
    if source_ip:
        clauses.append("source_ip = ?"); params.append(source_ip)
    if incident_id is not None:
        clauses.append("incident_id = ?"); params.append(incident_id)
    if keyword:
        clauses.append("(title LIKE ? OR description LIKE ? OR source_ip LIKE ? OR user LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw, kw, kw]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return conn.execute(f"SELECT COUNT(*) AS c FROM alerts {where}", params).fetchone()["c"]


def alerts_grouped_by_severity(conn: sqlite3.Connection, status_not_in: Sequence[str] = ()) -> dict:
    where = ""
    params: List[Any] = []
    if status_not_in:
        placeholders = ",".join("?" for _ in status_not_in)
        where = f"WHERE status NOT IN ({placeholders})"
        params.extend(status_not_in)
    rows = conn.execute(f"SELECT severity, COUNT(*) AS c FROM alerts {where} GROUP BY severity", params).fetchall()
    counts = {r["severity"]: r["c"] for r in rows}
    return {sev: counts.get(sev, 0) for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}


def update_alert_status(conn: sqlite3.Connection, alert_id: int, status: str) -> None:
    conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?", (status, now_iso(), alert_id))
    conn.commit()


def set_alert_incident(conn: sqlite3.Connection, alert_id: int, incident_id: int) -> None:
    conn.execute(
        "UPDATE alerts SET incident_id = ?, updated_at = ? WHERE id = ?", (incident_id, now_iso(), alert_id)
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def insert_incident(
    conn: sqlite3.Connection, title: str, description: str, severity: str,
    assigned_to: Optional[str] = None, metadata: Optional[dict] = None,
) -> int:
    ts = now_iso()
    cur = conn.execute(
        """INSERT INTO incidents (created_at, updated_at, title, description, severity, status, assigned_to, metadata)
           VALUES (?, ?, ?, ?, ?, 'Open', ?, ?)""",
        (ts, ts, title, description, severity, assigned_to, json.dumps(metadata or {})),
    )
    conn.commit()
    return cur.lastrowid


def get_incident(conn: sqlite3.Connection, incident_id: int) -> Optional[dict]:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return _row_to_dict(row)


def query_incidents(
    conn: sqlite3.Connection,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    order: str = "-id",
    limit: int = 50,
    offset: int = 0,
) -> List[dict]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?"); params.append(status)
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    if keyword:
        clauses.append("(title LIKE ? OR description LIKE ?)")
        kw = f"%{keyword}%"
        params += [kw, kw]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    order_sql = ALLOWED_ORDER_COLUMNS.get(order, "id DESC")
    sql = f"SELECT * FROM incidents {where} ORDER BY {order_sql} LIMIT ? OFFSET ?"
    rows = conn.execute(sql, [*params, limit, offset]).fetchall()
    return _rows_to_dicts(rows)


def count_incidents(conn: sqlite3.Connection, status: Optional[str] = None, severity: Optional[str] = None) -> int:
    clauses, params = [], []
    if status:
        clauses.append("status = ?"); params.append(status)
    if severity:
        clauses.append("severity = ?"); params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return conn.execute(f"SELECT COUNT(*) AS c FROM incidents {where}", params).fetchone()["c"]


def update_incident(conn: sqlite3.Connection, incident_id: int, **fields) -> None:
    if not fields:
        return
    fields["updated_at"] = now_iso()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    params = list(fields.values()) + [incident_id]
    conn.execute(f"UPDATE incidents SET {set_clause} WHERE id = ?", params)
    conn.commit()


def get_alerts_for_incident(conn: sqlite3.Connection, incident_id: int) -> List[dict]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY created_at", (incident_id,)
    ).fetchall()
    return _rows_to_dicts(rows)


def add_incident_note(conn: sqlite3.Connection, incident_id: int, author: str, note: str) -> int:
    cur = conn.execute(
        "INSERT INTO incident_notes (incident_id, created_at, author, note) VALUES (?, ?, ?, ?)",
        (incident_id, now_iso(), author, note),
    )
    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now_iso(), incident_id))
    conn.commit()
    return cur.lastrowid


def get_incident_notes(conn: sqlite3.Connection, incident_id: int) -> List[dict]:
    rows = conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at", (incident_id,)
    ).fetchall()
    return _rows_to_dicts(rows)


# ---------------------------------------------------------------------------
# Threat intel cache
# ---------------------------------------------------------------------------

def get_threat_intel_cache(conn: sqlite3.Connection, ip: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,)).fetchone()
    return _row_to_dict(row)


def set_threat_intel_cache(conn: sqlite3.Connection, ip: str, reputation: str, source: str, details: dict) -> None:
    conn.execute(
        """INSERT INTO threat_intel_cache (ip, reputation, source, details, checked_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET reputation = excluded.reputation, source = excluded.source,
                                         details = excluded.details, checked_at = excluded.checked_at""",
        (ip, reputation, source, json.dumps(details or {}), now_iso()),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Misc stats (used by `cli.py stats` and the dashboard home page)
# ---------------------------------------------------------------------------

def summary_stats(conn: sqlite3.Connection) -> dict:
    return {
        "total_events": count_all_events(conn),
        "total_alerts": count_alerts(conn),
        "open_alerts": count_alerts(conn) - conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE status IN ('Resolved','Closed','False Positive')"
        ).fetchone()["c"],
        "critical_alerts_open": conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE severity='CRITICAL' AND status NOT IN ('Resolved','Closed','False Positive')"
        ).fetchone()["c"],
        "open_incidents": count_incidents(conn) - conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE status IN ('Resolved','Closed')"
        ).fetchone()["c"],
        "total_incidents": count_incidents(conn),
        "alerts_by_severity": alerts_grouped_by_severity(conn),
    }
