"""Log search — used by both `cli.py search` and the dashboard's /search
page. Framework-agnostic: returns plain dicts, no Flask objects."""
from __future__ import annotations

import sqlite3
from typing import List, Optional, Tuple

from soc import database as db
from soc.utils import paginate


def search_events(
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
    page: int = 1,
    page_size: int = 25,
) -> Tuple[List[dict], dict]:
    filters = dict(
        source_ip=source_ip or None, user=user or None, host=host or None,
        event_type=event_type or None, status=status or None, os=os or None,
        since=since or None, until=until or None, keyword=keyword or None,
    )
    total = db.count_events(conn, **filters)
    page_info = paginate(total, page, page_size)
    results = db.query_events(conn, **filters, order="-timestamp", limit=page_size, offset=page_info["offset"])
    return results, page_info


def distinct_event_types(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type").fetchall()
    return [r["event_type"] for r in rows]


def distinct_hosts(conn: sqlite3.Connection) -> List[str]:
    rows = conn.execute("SELECT DISTINCT host FROM events ORDER BY host").fetchall()
    return [r["host"] for r in rows]
