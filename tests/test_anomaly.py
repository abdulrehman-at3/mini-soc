import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from soc import database as db
from soc.detection.anomaly import detect_volume_anomaly
from soc.models import NormalizedEvent

CFG = SimpleNamespace(
    ANOMALY_WINDOW_MINUTES=15,
    ANOMALY_LOOKBACK_DAYS=7,
    ANOMALY_MIN_CURRENT_COUNT=6,
    ANOMALY_Z_THRESHOLD=2.5,
)


def _insert(conn, dt, source_ip, user):
    return db.insert_event(conn, NormalizedEvent(
        timestamp=dt.isoformat(), event_type="auth_failure", host="web-server-01", os="linux",
        source_format="ssh_auth", raw_text="x", source_ip=source_ip, user=user, status="failure",
    ))


class TestAnomalyDetection(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.now = datetime(2026, 1, 8, 15, 0, 0, tzinfo=timezone.utc)  # a Thursday

    def test_quiet_history_plus_burst_triggers_anomaly(self):
        # Sparse historical noise: one failed login per day, same time slot,
        # for the past week — a low, boring baseline.
        for d in range(1, 8):
            _insert(self.conn, self.now - timedelta(days=d), source_ip=f"10.0.0.{d}", user="jdoe")

        # "Now": a burst of failures from many distinct low-volume IPs.
        trigger_ids = []
        for i in range(20):
            ip = f"192.0.2.{i}"
            ts = self.now - timedelta(minutes=10) + timedelta(seconds=i * 20)
            trigger_ids.append(_insert(self.conn, ts, source_ip=ip, user="admin"))

        trigger_events = db.get_events_by_ids(self.conn, trigger_ids)
        detections = detect_volume_anomaly(self.conn, trigger_events, CFG)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_name, "anomalous_auth_volume")
        self.assertIn(detections[0].severity, ("MEDIUM", "HIGH"))

    def test_below_minimum_count_does_not_trigger(self):
        trigger_ids = [_insert(self.conn, self.now, source_ip="192.0.2.1", user="admin")]
        trigger_events = db.get_events_by_ids(self.conn, trigger_ids)
        self.assertEqual(detect_volume_anomaly(self.conn, trigger_events, CFG), [])

    def test_no_events_returns_empty(self):
        self.assertEqual(detect_volume_anomaly(self.conn, [], CFG), [])


if __name__ == "__main__":
    unittest.main()
