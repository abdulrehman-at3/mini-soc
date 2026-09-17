"""Integration test: generate the demo dataset, run the real pipeline, and
confirm every advertised detection type fires at least once. This is a
regression guard for the demo data generator + full rule set together —
if a future change to thresholds or scenario timing silently breaks one
detection path, this test catches it."""
import shutil
import tempfile
import unittest
from pathlib import Path

import config
from soc import alerting, database as db
from soc.detection.engine import run_detection_pipeline
from soc.log_collector import collect_new_events
from soc.log_generator import generate_all


class TestFullPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.conn = db.get_connection(":memory:")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_every_rule_fires_on_generated_demo_data(self):
        generate_all(sample_log_dir=self.tmp_dir, days=7, seed=1234)
        sources = [
            {"path": str(self.tmp_dir / "auth.log"), "format": "ssh_auth"},
            {"path": str(self.tmp_dir / "windows_security.jsonl"), "format": "windows_security"},
            {"path": str(self.tmp_dir / "firewall.log"), "format": "firewall"},
        ]
        result = collect_new_events(self.conn, sources=sources)
        self.assertEqual(result.lines_skipped, 0, "every generated line should be parseable")
        self.assertGreater(len(result.new_events), 100)

        detections = run_detection_pipeline(self.conn, result.new_events)
        rule_names = {d.rule_name for d in detections}
        expected = {
            "brute_force", "port_scan", "privilege_escalation", "unusual_login_time",
            "suspicious_ip", "credential_stuffing", "cross_host_auth_failures", "anomalous_auth_volume",
        }
        missing = expected - rule_names
        self.assertFalse(missing, f"expected rules did not fire: {missing}")

        summary = alerting.process_detections(self.conn, detections, config)
        self.assertGreater(len(summary["new_alerts"]), 0)
        self.assertGreaterEqual(len(summary["incidents_created"]), 1)

        # The flagship scenario from the original brief should come through
        # exactly as described: 192.168.1.50 brute-forcing SSH on web-server-01.
        alerts = db.query_alerts(self.conn, limit=100)
        flagship = [a for a in alerts if a["rule_name"] == "brute_force" and a["source_ip"] == "192.168.1.50"]
        self.assertEqual(len(flagship), 1)
        self.assertEqual(flagship[0]["host"], "web-server-01")
        self.assertGreaterEqual(flagship[0]["event_count"], 25)


if __name__ == "__main__":
    unittest.main()
