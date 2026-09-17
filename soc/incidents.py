"""Incident management: grouping one or more related alerts into a single
case an analyst can investigate, annotate, and close out."""
from __future__ import annotations

import sqlite3
from typing import List, Optional

from soc import database as db

VALID_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Closed"]


def create_incident_from_alert(conn: sqlite3.Connection, alert_id: int, assigned_to: Optional[str] = None, auto: bool = False) -> int:
    alert = db.get_alert(conn, alert_id)
    prefix = "Auto-escalated: " if auto else ""
    title = f"{prefix}{alert['title']}"
    description = (
        f"Automatically opened from {alert['severity']} alert #{alert['id']} ({alert['rule_name']})."
        if auto else f"Opened from alert #{alert['id']} ({alert['rule_name']})."
    )
    description += f"\n\n{alert['description'] or ''}"
    incident_id = db.insert_incident(
        conn, title=title, description=description.strip(), severity=alert["severity"], assigned_to=assigned_to,
    )
    db.set_alert_incident(conn, alert_id, incident_id)
    db.add_incident_note(
        conn, incident_id, author="system",
        note=f"Incident opened from alert #{alert['id']}: {alert['title']} (severity {alert['severity']}).",
    )
    return incident_id


def create_manual_incident(
    conn: sqlite3.Connection, title: str, description: str, severity: str,
    assigned_to: Optional[str] = None, alert_ids: Optional[List[int]] = None,
) -> int:
    incident_id = db.insert_incident(conn, title=title, description=description, severity=severity, assigned_to=assigned_to)
    for alert_id in alert_ids or []:
        link_alert(conn, incident_id, alert_id)
    db.add_incident_note(conn, incident_id, author="analyst", note="Incident opened manually.")
    return incident_id


def link_alert(conn: sqlite3.Connection, incident_id: int, alert_id: int) -> None:
    db.set_alert_incident(conn, alert_id, incident_id)
    alert = db.get_alert(conn, alert_id)
    db.add_incident_note(
        conn, incident_id, author="system",
        note=f"Linked alert #{alert_id}: {alert['title']} (severity {alert['severity']}).",
    )


def add_note(conn: sqlite3.Connection, incident_id: int, author: str, note: str) -> int:
    return db.add_incident_note(conn, incident_id, author, note)


def update_status(conn: sqlite3.Connection, incident_id: int, status: str, resolution: Optional[str] = None, author: str = "analyst") -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status {status!r}. Must be one of {VALID_STATUSES}")
    fields = {"status": status}
    from soc.utils import now_iso
    if status in ("Resolved", "Closed"):
        fields["closed_at"] = now_iso()
        if resolution:
            fields["resolution"] = resolution
    db.update_incident(conn, incident_id, **fields)
    note = f"Status changed to {status}."
    if resolution:
        note += f" Resolution: {resolution}"
    db.add_incident_note(conn, incident_id, author=author, note=note)


def get_full_incident(conn: sqlite3.Connection, incident_id: int) -> Optional[dict]:
    incident = db.get_incident(conn, incident_id)
    if not incident:
        return None
    incident["alerts"] = db.get_alerts_for_incident(conn, incident_id)
    incident["notes"] = db.get_incident_notes(conn, incident_id)
    all_event_ids: List[int] = []
    for alert in incident["alerts"]:
        all_event_ids.extend(db.get_alert_event_ids(conn, alert["id"]))
    incident["events"] = db.get_events_by_ids(conn, sorted(set(all_event_ids)))
    return incident
