import json
import unittest

from soc.normalizer import normalize_line


class TestSshAuthNormalizer(unittest.TestCase):
    def test_failed_password_invalid_user(self):
        line = "2026-09-04T09:24:10+00:00 web-server-01 sshd[12346]: Failed password for invalid user admin from 192.168.1.50 port 51234 ssh2"
        e = normalize_line("ssh_auth", line)
        self.assertEqual(e.event_type, "auth_failure")
        self.assertEqual(e.source_ip, "192.168.1.50")
        self.assertEqual(e.user, "admin")
        self.assertEqual(e.host, "web-server-01")
        self.assertEqual(e.status, "failure")

    def test_accepted_password(self):
        line = "2026-09-04T09:23:41+00:00 web-server-01 sshd[12345]: Accepted password for jdoe from 10.0.0.15 port 54321 ssh2"
        e = normalize_line("ssh_auth", line)
        self.assertEqual(e.event_type, "auth_success")
        self.assertEqual(e.user, "jdoe")
        self.assertEqual(e.status, "success")

    def test_sensitive_sudo_command_flagged_as_privesc(self):
        line = "2026-09-04T10:05:00+00:00 web-server-01 sudo:    jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/sbin/useradd hacker"
        e = normalize_line("ssh_auth", line)
        self.assertEqual(e.event_type, "privilege_escalation")
        self.assertEqual(e.user, "jdoe")

    def test_routine_sudo_command_not_flagged(self):
        line = "2026-09-04T10:05:00+00:00 web-server-01 sudo:    jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/apt update"
        e = normalize_line("ssh_auth", line)
        self.assertEqual(e.event_type, "command_execution")

    def test_blank_line_returns_none(self):
        self.assertIsNone(normalize_line("ssh_auth", ""))

    def test_garbage_line_returns_none(self):
        self.assertIsNone(normalize_line("ssh_auth", "this matches nothing"))


class TestWindowsSecurityNormalizer(unittest.TestCase):
    def test_failed_logon(self):
        line = json.dumps({
            "TimeCreated": "2026-09-04T09:24:15+00:00", "EventID": 4625, "Computer": "WIN-DC01",
            "TargetUserName": "administrator", "IpAddress": "192.168.1.50", "LogonType": 3,
            "FailureReason": "Unknown user name or bad password",
        })
        e = normalize_line("windows_security", line)
        self.assertEqual(e.event_type, "auth_failure")
        self.assertEqual(e.source_ip, "192.168.1.50")
        self.assertEqual(e.user, "administrator")

    def test_special_privileges_flagged(self):
        line = json.dumps({"TimeCreated": "2026-09-04T10:12:00+00:00", "EventID": 4672, "Computer": "WIN-DC01", "TargetUserName": "svc_temp"})
        e = normalize_line("windows_security", line)
        self.assertEqual(e.event_type, "privilege_escalation")

    def test_group_membership_change_flagged(self):
        line = json.dumps({
            "TimeCreated": "2026-09-04T10:13:00+00:00", "EventID": 4732, "Computer": "WIN-DC01",
            "MemberName": "svc_temp", "TargetGroupName": "Administrators",
        })
        e = normalize_line("windows_security", line)
        self.assertEqual(e.event_type, "privilege_escalation")
        self.assertEqual(e.user, "svc_temp")

    def test_invalid_json_returns_none(self):
        self.assertIsNone(normalize_line("windows_security", "{not json"))

    def test_localhost_ip_is_dropped(self):
        line = json.dumps({"TimeCreated": "2026-09-04T10:00:00+00:00", "EventID": 4624, "Computer": "WIN-DC01", "TargetUserName": "svc", "IpAddress": "::1"})
        e = normalize_line("windows_security", line)
        self.assertIsNone(e.source_ip)


class TestFirewallNormalizer(unittest.TestCase):
    def test_connection_line(self):
        line = "2026-09-04T11:00:01+00:00 fw-01 CONN src=203.0.113.77 dst=10.0.0.5 dport=22 proto=tcp action=blocked"
        e = normalize_line("firewall", line)
        self.assertEqual(e.event_type, "network_connection")
        self.assertEqual(e.source_ip, "203.0.113.77")
        self.assertEqual(e.dest_port, 22)
        self.assertEqual(e.status, "blocked")


if __name__ == "__main__":
    unittest.main()
