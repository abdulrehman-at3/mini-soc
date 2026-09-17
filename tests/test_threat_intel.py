import unittest

from soc import database as db
from soc.threat_intel import lookup_ip


class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")

    def test_rfc1918_is_internal(self):
        for ip in ("10.0.0.15", "192.168.1.50", "172.16.5.5"):
            self.assertEqual(lookup_ip(self.conn, ip).reputation, "internal")

    def test_documentation_range_is_not_internal(self):
        # These stand in for "external" attacker IPs throughout the demo
        # data; they must NOT be misclassified as internal/trusted even
        # though Python's ipaddress.is_private lumps them in as such.
        for ip in ("192.0.2.10", "198.51.100.200", "203.0.113.50"):
            self.assertNotEqual(lookup_ip(self.conn, ip).reputation, "internal")

    def test_blocklisted_ip_is_malicious(self):
        result = lookup_ip(self.conn, "198.51.100.23")
        self.assertEqual(result.reputation, "malicious")
        self.assertEqual(result.source, "local_blocklist")

    def test_unknown_public_ip(self):
        result = lookup_ip(self.conn, "203.0.113.77")
        self.assertEqual(result.reputation, "unknown")

    def test_invalid_ip_handled_gracefully(self):
        result = lookup_ip(self.conn, "not-an-ip")
        self.assertEqual(result.reputation, "unknown")
        self.assertEqual(result.source, "invalid")

    def test_result_is_cached(self):
        lookup_ip(self.conn, "198.51.100.23")
        cached = db.get_threat_intel_cache(self.conn, "198.51.100.23")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["reputation"], "malicious")


if __name__ == "__main__":
    unittest.main()
