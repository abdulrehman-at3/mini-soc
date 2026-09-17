"""
Mini-SOC configuration.

Every tunable knob for the platform lives here: file locations and
detection thresholds. Detection thresholds are intentionally tuned for
the *demo* dataset produced by `soc/log_generator.py` (small numbers,
short windows) so the workflow is visible in seconds instead of days.
In a real deployment these would be raised (e.g. brute-force window of
5-15 minutes, thresholds based on your own traffic baselines).
"""
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_LOG_DIR = DATA_DIR / "sample_logs"
THREAT_INTEL_DIR = DATA_DIR / "threat_intel"
REPORTS_DIR = DATA_DIR / "reports"

DB_PATH = os.environ.get("SOC_DB_PATH", str(DATA_DIR / "soc.db"))
MALICIOUS_IP_FEED = THREAT_INTEL_DIR / "malicious_ips.json"

SECRET_KEY_FILE = BASE_DIR / "dashboard" / ".secret_key"

# Raw log sources the collector reads from, and which parser to use for
# each one. Paths are relative to SAMPLE_LOG_DIR unless absolute.
LOG_SOURCES = [
    {"path": str(SAMPLE_LOG_DIR / "auth.log"), "format": "ssh_auth"},
    {"path": str(SAMPLE_LOG_DIR / "windows_security.jsonl"), "format": "windows_security"},
    {"path": str(SAMPLE_LOG_DIR / "firewall.log"), "format": "firewall"},
]

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

# Brute force: failed logins from the same source IP against the same host,
# within a rolling window. Maps "minimum attempt count" -> severity; the
# highest threshold met wins.
BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLDS = {8: "MEDIUM", 15: "HIGH", 30: "CRITICAL"}

# Port scan: distinct destination ports from one source IP against one host,
# within a rolling window.
PORT_SCAN_WINDOW_SECONDS = 90
PORT_SCAN_THRESHOLDS = {8: "MEDIUM", 15: "HIGH"}
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
}

# Credential stuffing / username enumeration: distinct usernames attempted
# from one source IP within a rolling window.
CREDENTIAL_STUFFING_WINDOW_MINUTES = 5
CREDENTIAL_STUFFING_DISTINCT_USER_THRESHOLD = 6

# Multi-host password spraying: one account failing logins across several
# distinct hosts within a rolling window.
CROSS_HOST_WINDOW_MINUTES = 15
CROSS_HOST_DISTINCT_HOST_THRESHOLD = 3
CROSS_HOST_MIN_FAILURES = 5

# Unusual login time: outside these hours/days is flagged. Hours are in the
# same clock the logs are generated in (the demo treats all timestamps as a
# single organizational timezone for simplicity).
BUSINESS_HOURS_START = 7
BUSINESS_HOURS_END = 20
BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Monday=0 ... Sunday=6

# Anomaly detection (statistical): org-wide failed-auth volume in a rolling
# window, compared against the same clock-time window on prior days.
ANOMALY_WINDOW_MINUTES = 15
ANOMALY_LOOKBACK_DAYS = 7
ANOMALY_MIN_CURRENT_COUNT = 6
ANOMALY_Z_THRESHOLD = 2.5

# Alert severities that automatically open an incident.
AUTO_ESCALATE_SEVERITIES = {"CRITICAL"}

# Re-use an existing open alert (rather than creating a duplicate) if one
# with the same dedup key is still New/Investigating. Alerts that are
# Resolved/Closed/False Positive will NOT be reopened; a fresh alert starts
# instead, which is what you want if the same source acts up again later.
ALERT_DEDUP_STATUSES = {"New", "Investigating"}

# Even an open alert stops absorbing new activity after this many hours of
# quiet — a source going quiet for days and then reappearing reads as a new
# case, not a 6-hour-old alert suddenly "still" being worked.
ALERT_STALE_REOPEN_HOURS = 6

# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------
# Optional live lookup. Leave blank to run fully offline using the local
# blocklist feed + private/reserved IP heuristics only.
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
THREAT_INTEL_CACHE_HOURS = 24

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
DASHBOARD_HOST = os.environ.get("SOC_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("SOC_PORT", "5000"))
PAGE_SIZE_DEFAULT = 25
