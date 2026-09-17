import unittest
from types import SimpleNamespace

from soc import database as db
from soc.detection import rules
from soc.models import NormalizedEvent

# A self-contained config namespace so these tests don't depend on (or
# break when someone tunes) the values in the real config.py.
CFG = SimpleNamespace(
    BRUTE_FORCE_WINDOW_MINUTES=5,
    BRUTE_FORCE_THRESHOLDS={8: "MEDIUM", 15: "HIGH", 30: "CRITICAL"},
    PORT_SCAN_WINDOW_SECONDS=90,
    PORT_SCAN_THRESHOLDS={8: "MEDIUM", 15: "HIGH"},
    SENSITIVE_PORTS={22: "SSH", 3389: "RDP"},
    CREDENTIAL_STUFFING_WINDOW_MINUTES=5,
    CREDENTIAL_STUFFING_DISTINCT_USER_THRESHOLD=6,
    CROSS_HOST_WINDOW_MINUTES=15,
    CROSS_HOST_DISTINCT_HOST_THRESHOLD=3,
    CROSS_HOST_MIN_FAILURES=5,
    BUSINESS_HOURS_START=7,
    BUSINESS_HOURS_END=20,
    BUSINESS_DAYS={0, 1, 2, 3, 4},
)


def _insert(conn, **kwargs):
    defaults = dict(host="web-server-01", os="linux", source_format="ssh_auth", raw_text="x")
    defaults.update(kwargs)
    return db.insert_event(conn, NormalizedEvent(**defaults))


class RuleTestCase(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")

    def _events_by_ids(self, ids):
        return db.get_events_by_ids(self.conn, ids)


class TestBruteForce(RuleTestCase):
    def test_below_threshold_no_detection(self):
        ids = []
        for i in range(3):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:00:{i:02d}+00:00",
                                event_type="auth_failure", source_ip="1.2.3.4", user="root", status="failure"))
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_brute_force(self.conn, trigger, CFG), [])

    def test_at_threshold_triggers_medium(self):
        ids = []
        for i in range(10):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:00:{i:02d}+00:00",
                                event_type="auth_failure", source_ip="1.2.3.4", user="root", status="failure"))
        trigger = self._events_by_ids(ids)
        detections = rules.detect_brute_force(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "MEDIUM")
        self.assertEqual(detections[0].dedup_key, "brute_force:1.2.3.4:web-server-01")

    def test_success_after_failures_escalates_to_critical(self):
        ids = []
        for i in range(9):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:00:{i:02d}+00:00",
                                event_type="auth_failure", source_ip="9.9.9.9", user="svc", status="failure"))
        ids.append(_insert(self.conn, timestamp="2026-01-05T10:00:30+00:00",
                            event_type="auth_success", source_ip="9.9.9.9", user="svc", status="success"))
        trigger = self._events_by_ids(ids)
        detections = rules.detect_brute_force(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "CRITICAL")
        self.assertIn("compromise", detections[0].title.lower())


class TestPortScan(RuleTestCase):
    def test_many_distinct_ports_triggers(self):
        ids = []
        for i, port in enumerate(range(1, 20)):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:00:{i:02d}+00:00",
                                event_type="network_connection", source_ip="5.5.5.5", host="fw-01", os="network",
                                source_format="firewall", dest_port=port, status="blocked"))
        trigger = self._events_by_ids(ids)
        detections = rules.detect_port_scan(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)
        self.assertIn(detections[0].severity, ("MEDIUM", "HIGH"))

    def test_few_ports_no_detection(self):
        ids = [_insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="network_connection",
                        source_ip="5.5.5.5", host="fw-01", os="network", source_format="firewall",
                        dest_port=22, status="allowed")]
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_port_scan(self.conn, trigger, CFG), [])


class TestPrivilegeEscalation(RuleTestCase):
    def test_multiple_events_same_user_host_grouped_into_one_alert(self):
        ids = [
            _insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="privilege_escalation",
                    host="WIN-DC01", os="windows", source_format="windows_security", user="svc_temp",
                    description="Special privileges assigned"),
            _insert(self.conn, timestamp="2026-01-05T10:01:00+00:00", event_type="privilege_escalation",
                    host="WIN-DC01", os="windows", source_format="windows_security", user="svc_temp",
                    description="Added to Administrators"),
        ]
        trigger = self._events_by_ids(ids)
        detections = rules.detect_privilege_escalation(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)
        self.assertEqual(len(detections[0].event_ids), 2)
        self.assertEqual(detections[0].severity, "HIGH")


class TestUnusualLoginTime(RuleTestCase):
    def test_3am_login_flagged(self):
        ids = [_insert(self.conn, timestamp="2026-01-06T03:14:00+00:00", event_type="auth_success",
                        user="mchen", status="success")]  # 2026-01-06 is a Tuesday
        trigger = self._events_by_ids(ids)
        detections = rules.detect_unusual_login_time(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)

    def test_business_hours_login_not_flagged(self):
        ids = [_insert(self.conn, timestamp="2026-01-06T14:00:00+00:00", event_type="auth_success",
                        user="mchen", status="success")]
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_unusual_login_time(self.conn, trigger, CFG), [])

    def test_weekend_login_flagged(self):
        ids = [_insert(self.conn, timestamp="2026-01-10T14:00:00+00:00", event_type="auth_success",
                        user="mchen", status="success")]  # 2026-01-10 is a Saturday
        trigger = self._events_by_ids(ids)
        self.assertEqual(len(rules.detect_unusual_login_time(self.conn, trigger, CFG)), 1)


class TestCredentialStuffing(RuleTestCase):
    def test_many_usernames_one_ip_triggers(self):
        ids = []
        for i, user in enumerate(["a", "b", "c", "d", "e", "f", "g"]):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:00:{i:02d}+00:00",
                                event_type="auth_failure", source_ip="7.7.7.7", user=user, status="failure"))
        trigger = self._events_by_ids(ids)
        detections = rules.detect_credential_stuffing(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)

    def test_few_usernames_no_detection(self):
        ids = [_insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="auth_failure",
                        source_ip="7.7.7.7", user="a", status="failure")]
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_credential_stuffing(self.conn, trigger, CFG), [])


class TestCrossHostFailures(RuleTestCase):
    def test_spread_across_three_hosts_triggers(self):
        ids = []
        for i, host in enumerate(["web-server-01", "web-server-01", "db-server-02", "db-server-02", "WIN-FILE01"]):
            ids.append(_insert(self.conn, timestamp=f"2026-01-05T10:0{i}:00+00:00", event_type="auth_failure",
                                host=host, user="rpatel", status="failure", source_ip="203.0.113.55"))
        trigger = self._events_by_ids(ids)
        detections = rules.detect_cross_host_failures(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)

    def test_single_host_no_detection(self):
        ids = [_insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="auth_failure",
                        user="rpatel", status="failure")]
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_cross_host_failures(self.conn, trigger, CFG), [])


class TestSuspiciousIp(RuleTestCase):
    def test_blocklisted_ip_triggers_high(self):
        ids = [_insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="auth_failure",
                        source_ip="198.51.100.23", user="administrator", status="failure",
                        host="WIN-FILE01", os="windows", source_format="windows_security")]
        trigger = self._events_by_ids(ids)
        detections = rules.detect_suspicious_ip(self.conn, trigger, CFG)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "HIGH")

    def test_clean_ip_no_detection(self):
        ids = [_insert(self.conn, timestamp="2026-01-05T10:00:00+00:00", event_type="auth_success",
                        source_ip="10.0.0.15", user="jdoe", status="success")]
        trigger = self._events_by_ids(ids)
        self.assertEqual(rules.detect_suspicious_ip(self.conn, trigger, CFG), [])


if __name__ == "__main__":
    unittest.main()
