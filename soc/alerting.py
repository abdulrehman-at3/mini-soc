"""
Alert engine.

Turns raw `Detection` objects into persisted, triage-able `Alert` rows:

- Deduplication: if an open (New/Investigating) alert already exists for
  the same `dedup_key`, it's updated in place (severity can only escalate,
  never de-escalate here; event_count/last_event_at extend) instead of
  spawning a duplicate. If the prior alert for that key was already
  Resolved/Closed/False Positive, a brand new alert is opened instead —
  renewed activity from a previously-closed source deserves fresh
  analyst attention, not silently reopening an old case.
- Auto-escalation: alerts whose severity is in `AUTO_ESCALATE_SEVERITIES`
  (CRITICAL by default) automatically open an incident, so nothing
  critical can sit unnoticed in the alert queue.
"""
from __future__ import annotations

import sqlite3
from typing import List

from soc import database as db
from soc import incidents
from soc.models import Detection
from soc.utils import max_severity, now_utc, parse_iso


def _is_stale(alert: dict, cfg) -> bool:
    """An open alert that hasn't seen matching activity in a while reads
    as a closed chapter, not an ongoing case — let a fresh alert open."""
    if not alert.get("last_event_at"):
        return False
    age_hours = (now_utc() - parse_iso(alert["last_event_at"])).total_seconds() / 3600
    return age_hours > cfg.ALERT_STALE_REOPEN_HOURS


def process_detections(conn: sqlite3.Connection, detections: List[Detection], cfg) -> dict:
    new_alert_ids: List[int] = []
    updated_alert_ids: List[int] = []

    for detection in detections:
        existing = db.find_open_alert_by_dedup(conn, detection.dedup_key, tuple(cfg.ALERT_DEDUP_STATUSES))
        if existing and _is_stale(existing, cfg):
            existing = None
        if existing:
            new_severity = max_severity(existing["severity"], detection.severity)
            db.update_alert_from_detection(conn, existing["id"], detection, new_severity)
            updated_alert_ids.append(existing["id"])
        else:
            alert_id = db.insert_alert(conn, detection)
            new_alert_ids.append(alert_id)

    incidents_created: List[int] = []
    for alert_id in new_alert_ids:
        alert = db.get_alert(conn, alert_id)
        if alert["severity"] in cfg.AUTO_ESCALATE_SEVERITIES:
            incident_id = incidents.create_incident_from_alert(conn, alert_id, auto=True)
            incidents_created.append(incident_id)

    # An update can also cross into auto-escalation territory (e.g. a
    # brute-force alert climbing from MEDIUM to CRITICAL as more failed
    # attempts arrive) — escalate to an incident if it isn't linked to one.
    for alert_id in updated_alert_ids:
        alert = db.get_alert(conn, alert_id)
        if alert["severity"] in cfg.AUTO_ESCALATE_SEVERITIES and not alert["incident_id"]:
            incident_id = incidents.create_incident_from_alert(conn, alert_id, auto=True)
            incidents_created.append(incident_id)

    return {
        "new_alerts": new_alert_ids,
        "updated_alerts": updated_alert_ids,
        "incidents_created": incidents_created,
    }
