import unittest
from types import SimpleNamespace

from soc import alerting, database as db
from soc.models import Detection
from soc.utils import now_utc, to_iso

CFG = SimpleNamespace(
    ALERT_DEDUP_STATUSES={"New", "Investigating"},
    ALERT_STALE_REOPEN_HOURS=6,
    AUTO_ESCALATE_SEVERITIES={"CRITICAL"},
)


def _detection(**overrides):
    base = dict(
        rule_name="brute_force", severity="MEDIUM", title="Potential Brute Force Attack",
        description="10 failed attempts", dedup_key="brute_force:1.2.3.4:host1",
        event_ids=[1], source_ip="1.2.3.4", user=None, host="host1",
    )
    base.update(overrides)
    return Detection(**base)


class TestAlertingDedup(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")

    def test_first_detection_creates_new_alert(self):
        summary = alerting.process_detections(self.conn, [_detection()], CFG)
        self.assertEqual(len(summary["new_alerts"]), 1)
        self.assertEqual(len(summary["updated_alerts"]), 0)

    def test_second_matching_detection_updates_not_duplicates(self):
        alerting.process_detections(self.conn, [_detection(event_ids=[1])], CFG)
        summary = alerting.process_detections(self.conn, [_detection(event_ids=[1, 2], severity="HIGH")], CFG)
        self.assertEqual(len(summary["new_alerts"]), 0)
        self.assertEqual(len(summary["updated_alerts"]), 1)
        alerts = db.query_alerts(self.conn)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")  # escalated, never de-escalated

    def test_resolved_alert_is_not_reused(self):
        summary = alerting.process_detections(self.conn, [_detection()], CFG)
        alert_id = summary["new_alerts"][0]
        db.update_alert_status(self.conn, alert_id, "Resolved")
        summary2 = alerting.process_detections(self.conn, [_detection()], CFG)
        self.assertEqual(len(summary2["new_alerts"]), 1)
        self.assertNotEqual(summary2["new_alerts"][0], alert_id)

    def test_stale_open_alert_is_not_reused(self):
        summary = alerting.process_detections(self.conn, [_detection()], CFG)
        alert_id = summary["new_alerts"][0]
        old_ts = to_iso(now_utc() - __import__("datetime").timedelta(hours=48))
        self.conn.execute("UPDATE alerts SET last_event_at = ? WHERE id = ?", (old_ts, alert_id))
        self.conn.commit()
        summary2 = alerting.process_detections(self.conn, [_detection()], CFG)
        self.assertEqual(len(summary2["new_alerts"]), 1)
        self.assertNotEqual(summary2["new_alerts"][0], alert_id)

    def test_critical_severity_auto_opens_incident(self):
        summary = alerting.process_detections(self.conn, [_detection(severity="CRITICAL")], CFG)
        self.assertEqual(len(summary["incidents_created"]), 1)
        alert = db.get_alert(self.conn, summary["new_alerts"][0])
        self.assertEqual(alert["incident_id"], summary["incidents_created"][0])

    def test_medium_severity_does_not_open_incident(self):
        summary = alerting.process_detections(self.conn, [_detection(severity="MEDIUM")], CFG)
        self.assertEqual(len(summary["incidents_created"]), 0)


if __name__ == "__main__":
    unittest.main()
