"""
Statistical anomaly detection — the second branch of the architecture
diagram, running alongside (not instead of) the rule engine.

The rules in rules.py are precise but local: each one asks "is *this*
source IP / *this* user doing something excessive?". A low-and-slow or
distributed attack — many source IPs, each just under every threshold —
slips straight past all of them. This module asks a different, coarser
question instead: "is *organization-wide* failed-login volume right now
unusual compared to what it normally looks like at this time of day?"

That's a real (if intentionally simple) statistical baseline: for the
current rolling window, compare the count of auth_failure events against
the count in the same-length, same-clock-time window on each of the
preceding `ANOMALY_LOOKBACK_DAYS` days, and flag a z-score outlier. A
production system would also persist and incrementally update the
baseline instead of recomputing it from raw history on every run, and
would likely baseline per-segment (per subnet, per business unit) rather
than for the whole org at once — noted here rather than built, to keep
the demo's runtime near-instant.
"""
from __future__ import annotations

import sqlite3
import statistics
from datetime import timedelta
from typing import List

from soc import database as db
from soc.models import Detection
from soc.utils import parse_iso, to_iso


def detect_volume_anomaly(conn: sqlite3.Connection, trigger_events: List[dict], cfg) -> List[Detection]:
    if trigger_events:
        reference = max(parse_iso(e["timestamp"]) for e in trigger_events)
    else:
        row = conn.execute("SELECT MAX(timestamp) AS m FROM events").fetchone()
        if not row or not row["m"]:
            return []
        reference = parse_iso(row["m"])

    window_start = reference - timedelta(minutes=cfg.ANOMALY_WINDOW_MINUTES)
    current_count = db.count_events(
        conn, event_type="auth_failure", since=to_iso(window_start), until=to_iso(reference)
    )
    if current_count < cfg.ANOMALY_MIN_CURRENT_COUNT:
        return []

    samples = []
    for d in range(1, cfg.ANOMALY_LOOKBACK_DAYS + 1):
        day_start = window_start - timedelta(days=d)
        day_end = reference - timedelta(days=d)
        samples.append(db.count_events(
            conn, event_type="auth_failure", since=to_iso(day_start), until=to_iso(day_end)
        ))

    if len(samples) < 3:
        return []  # not enough history to say what's "normal" yet

    mean = statistics.mean(samples)
    stdev = statistics.pstdev(samples) or 1.0  # guard a flat-zero baseline
    z_score = (current_count - mean) / stdev
    if z_score < cfg.ANOMALY_Z_THRESHOLD:
        return []

    events = db.query_events(
        conn, event_type="auth_failure", since=to_iso(window_start), until=to_iso(reference), limit=2000
    )
    distinct_ips = sorted({e["source_ip"] for e in events if e["source_ip"]})
    severity = "HIGH" if z_score >= 4 else "MEDIUM"

    return [Detection(
        rule_name="anomalous_auth_volume", severity=severity,
        title="Anomalous Spike in Failed-Authentication Volume",
        description=(
            f"{current_count} failed authentication events organization-wide in the last "
            f"{cfg.ANOMALY_WINDOW_MINUTES} minutes, from {len(distinct_ips)} distinct source IPs "
            f"(baseline for this time of day: {mean:.1f} \u00b1 {stdev:.1f} over the past "
            f"{len(samples)} days, z-score={z_score:.2f}). No single source crossed the per-IP "
            f"brute-force threshold — this looks like a distributed or low-and-slow campaign."
        ),
        source_ip=None, user=None, host=events[0]["host"] if events else None,
        event_ids=[e["id"] for e in events],
        dedup_key=f"anomalous_auth_volume:{reference.date()}:{reference.hour}",
    )]
