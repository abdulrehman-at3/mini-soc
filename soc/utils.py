"""Small, dependency-free helpers shared across the codebase."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUS_COLORS = {
    "New": "status-new",
    "Investigating": "status-investigating",
    "Resolved": "status-resolved",
    "False Positive": "status-falsepositive",
    "Closed": "status-closed",
    "Open": "status-new",
    "Contained": "status-investigating",
}


def now_utc() -> datetime:
    """Timezone-aware current UTC time. Never use naive datetimes."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return to_iso(now_utc())


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_iso(ts: str) -> datetime:
    """Parse an ISO8601 string (with 'Z' or '+00:00' offset) robustly."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return -1


def max_severity(a: Optional[str], b: Optional[str]) -> str:
    if not a:
        return b
    if not b:
        return a
    return a if severity_rank(a) >= severity_rank(b) else b


def severity_at_least(sev: str, floor: str) -> bool:
    return severity_rank(sev) >= severity_rank(floor)


def humanize_timedelta(dt: datetime, reference: Optional[datetime] = None) -> str:
    """'3 minutes ago' / 'in 2 hours' style relative time for the UI."""
    ref = reference or now_utc()
    delta = ref - dt
    seconds = delta.total_seconds()
    future = seconds < 0
    seconds = abs(seconds)

    if seconds < 60:
        text = "just now" if not future else "in a few seconds"
        return text
    minutes = seconds / 60
    if minutes < 60:
        n = int(minutes)
        unit = f"{n} minute{'s' if n != 1 else ''}"
    else:
        hours = minutes / 60
        if hours < 24:
            n = int(hours)
            unit = f"{n} hour{'s' if n != 1 else ''}"
        else:
            days = hours / 24
            n = int(days)
            unit = f"{n} day{'s' if n != 1 else ''}"
    return f"in {unit}" if future else f"{unit} ago"


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def paginate(total: int, page: int, page_size: int) -> dict:
    page = max(1, page)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, total_pages)
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "offset": (page - 1) * page_size,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    }
