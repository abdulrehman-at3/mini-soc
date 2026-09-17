"""
Synthetic log generator.

Produces three raw log files under `data/sample_logs/`:
  - auth.log               Linux OpenSSH + sudo (rsyslog ISO8601 format)
  - windows_security.jsonl Windows Security event log (JSON lines)
  - firewall.log           Simple key=value connection log

`generate_all()` builds ~7 days of quiet, believable background activity
(a handful of employees logging into their usual machines on weekdays,
occasional mistyped passwords, light firewall traffic) and then layers a
"today" timeline of attack scenarios on top — one for every detection
rule in `soc/detection/`, so a fresh install has something interesting
to look at in every corner of the dashboard immediately after `cli.py demo`.

External/attacker IPs deliberately use the IANA documentation ranges
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) instead of made
up "real-looking" public addresses, so nothing in this demo data could be
mistaken for an actual internet host. The one exception is the very first
scenario below, which intentionally reuses 192.168.1.50 — the private,
internal IP from the original brief's own worked example — to demonstrate
the exact "27 failed SSH logins in 2 minutes" walkthrough as written.

`simulate_attack()` reuses the same scenario builders to *append* one
fresh, "just now" attack to the existing logs, for a live "run detection
and watch the alert appear" demo without regenerating the whole week.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import config

# ---------------------------------------------------------------------------
# Cast of characters
# ---------------------------------------------------------------------------

USERS = {
    "jdoe": {"ip": "10.0.0.15", "host": "web-server-01", "os": "linux"},
    "mchen": {"ip": "10.0.0.22", "host": "db-server-02", "os": "linux"},
    "asmith": {"ip": "10.0.0.31", "host": "WIN-FILE01", "os": "windows"},
    "rpatel": {"ip": "10.0.0.40", "host": "WIN-DC01", "os": "windows"},
}
HOSTS_LINUX = ["web-server-01", "db-server-02"]
HOSTS_WINDOWS = ["WIN-DC01", "WIN-FILE01"]
SERVER_IPS = {
    "web-server-01": "10.0.0.5",
    "db-server-02": "10.0.0.6",
    "WIN-DC01": "10.0.0.7",
    "WIN-FILE01": "10.0.0.8",
}
COMMON_ATTACK_USERNAMES = [
    "admin", "administrator", "root", "test", "guest", "oracle", "postgres",
    "ubuntu", "ec2-user", "support", "sales", "hr", "backup", "operator", "service",
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _most_recent_past_time_at(reference_now: datetime, hour: int, minute: int) -> datetime:
    candidate = reference_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate >= reference_now:
        candidate -= timedelta(days=1)
    return candidate


def _rand_port() -> int:
    return random.randint(40000, 60000)


# ---------------------------------------------------------------------------
# Line builder
# ---------------------------------------------------------------------------

class LogBuilder:
    """Accumulates (timestamp, line) tuples per output file so everything
    can be sorted chronologically before hitting disk."""

    def __init__(self) -> None:
        self.auth_lines: List[Tuple[datetime, str]] = []
        self.windows_lines: List[Tuple[datetime, str]] = []
        self.firewall_lines: List[Tuple[datetime, str]] = []

    def ssh(self, dt: datetime, host: str, text: str) -> None:
        pid = random.randint(10000, 99999)
        self.auth_lines.append((dt, f"{_iso(dt)} {host} sshd[{pid}]: {text}"))

    def sudo(self, dt: datetime, host: str, user: str, command: str) -> None:
        self.auth_lines.append(
            (dt, f"{_iso(dt)} {host} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")
        )

    def windows(self, dt: datetime, event_id: int, host: str, **fields) -> None:
        payload = {"TimeCreated": _iso(dt), "EventID": event_id, "Computer": host, "Channel": "Security", **fields}
        self.windows_lines.append((dt, json.dumps(payload)))

    def firewall(self, dt: datetime, host: str, src: str, dst: str, dport: int, proto: str, action: str) -> None:
        self.firewall_lines.append(
            (dt, f"{_iso(dt)} {host} CONN src={src} dst={dst} dport={dport} proto={proto} action={action}")
        )

    def write(self, sample_log_dir: Path) -> Dict[str, int]:
        """Overwrite each output file with the accumulated, sorted lines."""
        sample_log_dir.mkdir(parents=True, exist_ok=True)
        return self._flush(sample_log_dir, mode="w")

    def append(self, sample_log_dir: Path) -> Dict[str, int]:
        """Append the accumulated, sorted lines to existing output files."""
        sample_log_dir.mkdir(parents=True, exist_ok=True)
        return self._flush(sample_log_dir, mode="a")

    def _flush(self, sample_log_dir: Path, mode: str) -> Dict[str, int]:
        counts = {}
        for name, lines in (
            ("auth.log", self.auth_lines),
            ("windows_security.jsonl", self.windows_lines),
            ("firewall.log", self.firewall_lines),
        ):
            ordered = [line for _, line in sorted(lines, key=lambda item: item[0])]
            counts[name] = len(ordered)
            if not ordered:
                if mode == "w":
                    (sample_log_dir / name).touch()
                continue
            with open(sample_log_dir / name, mode) as fh:
                fh.write("\n".join(ordered) + "\n")
        return counts


# ---------------------------------------------------------------------------
# Background noise: ~1 normal week of legitimate activity
# ---------------------------------------------------------------------------

def _generate_background_noise(b: LogBuilder, reference_now: datetime, days: int) -> None:
    for d in range(days, 0, -1):
        day_date = (reference_now - timedelta(days=d)).date()
        weekday = (reference_now - timedelta(days=d)).weekday()
        if weekday >= 5:
            continue  # quiet on weekends

        for username, info in USERS.items():
            if random.random() > 0.9:
                continue  # someone's on PTO
            hour, minute = random.randint(8, 17), random.randint(0, 59)
            dt = datetime(day_date.year, day_date.month, day_date.day, hour, minute, tzinfo=timezone.utc)
            host, ip, os_ = info["host"], info["ip"], info["os"]

            if os_ == "linux":
                if random.random() < 0.15:
                    typo_dt = dt - timedelta(minutes=random.randint(1, 3))
                    b.ssh(typo_dt, host, f"Failed password for {username} from {ip} port {_rand_port()} ssh2")
                b.ssh(dt, host, f"Accepted password for {username} from {ip} port {_rand_port()} ssh2")
            else:
                if random.random() < 0.15:
                    fail_dt = dt - timedelta(minutes=random.randint(1, 3))
                    b.windows(fail_dt, 4625, host, TargetUserName=username, IpAddress=ip,
                              LogonType=3, FailureReason="Unknown user name or bad password")
                b.windows(dt, 4624, host, TargetUserName=username, IpAddress=ip, LogonType=2)

        for _ in range(random.randint(2, 4)):
            src = random.choice(list(USERS.values()))["ip"]
            dst_host = random.choice(HOSTS_LINUX + HOSTS_WINDOWS)
            hour, minute = random.randint(8, 18), random.randint(0, 59)
            dt = datetime(day_date.year, day_date.month, day_date.day, hour, minute, tzinfo=timezone.utc)
            b.firewall(dt, "fw-01", src, SERVER_IPS[dst_host], random.choice([22, 80, 443]), "tcp", "allowed")


# ---------------------------------------------------------------------------
# Attack scenarios — one per detection rule
# ---------------------------------------------------------------------------

def _inject_privilege_escalation(b: LogBuilder, start_time: datetime) -> None:
    """Windows: a low-privilege service account is granted admin rights.
    Linux: an interactive user runs a sensitive sudo command."""
    b.windows(start_time, 4672, "WIN-DC01", TargetUserName="svc_temp")
    b.windows(start_time + timedelta(minutes=1), 4732, "WIN-DC01",
              TargetUserName="svc_temp", MemberName="svc_temp", TargetGroupName="Administrators")
    b.sudo(start_time + timedelta(minutes=3), "web-server-01", "jdoe", "/usr/sbin/useradd hacker")


def _inject_port_scan(b: LogBuilder, start_time: datetime) -> None:
    """One external IP sweeps a broad range of ports on web-server-01."""
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
             993, 995, 1433, 1723, 3306, 3389, 5900, 8080]
    for i, port in enumerate(ports):
        dt = start_time + timedelta(seconds=i * 2)
        action = "allowed" if port in (22, 80) else "blocked"
        b.firewall(dt, "fw-01", "203.0.113.77", SERVER_IPS["web-server-01"], port, "tcp", action)


def _inject_brute_force(b: LogBuilder, start_time: datetime) -> None:
    """The flagship scenario from the brief: 192.168.1.50 hammering SSH.
    Deliberately kept to a small, repeated username set (not enumeration)
    so this stays a clean brute-force example distinct from the
    credential-stuffing scenario below."""
    usernames = ["root", "admin", "jdoe"]
    for i in range(27):
        dt = start_time + timedelta(seconds=i * 4)
        user = usernames[i % len(usernames)]
        prefix = "invalid user " if user != "jdoe" else ""
        b.ssh(dt, "web-server-01", f"Failed password for {prefix}{user} from 192.168.1.50 port {_rand_port()} ssh2")


def _inject_suspicious_ip(b: LogBuilder, start_time: datetime) -> None:
    """A source IP already known to the local threat-intel blocklist."""
    for i, user in enumerate(["administrator", "admin"]):
        dt = start_time + timedelta(minutes=i)
        b.windows(dt, 4625, "WIN-FILE01", TargetUserName=user, IpAddress="198.51.100.23",
                  LogonType=3, FailureReason="Unknown user name or bad password")


def _inject_credential_stuffing(b: LogBuilder, start_time: datetime) -> None:
    """One IP tries many different usernames in quick succession."""
    usernames = ["admin", "administrator", "root", "test", "guest", "oracle",
                 "postgres", "ubuntu", "ec2-user", "backup", "sales", "hr"]
    for i, user in enumerate(usernames):
        dt = start_time + timedelta(seconds=i * 14)
        b.ssh(dt, "web-server-01", f"Failed password for invalid user {user} from 203.0.113.90 port {_rand_port()} ssh2")


def _inject_cross_host_spray(b: LogBuilder, start_time: datetime) -> None:
    """One real account failing logins across several different hosts —
    password spraying / a credential being tested broadly."""
    ip = "203.0.113.55"
    b.ssh(start_time, "web-server-01", f"Failed password for rpatel from {ip} port {_rand_port()} ssh2")
    b.ssh(start_time + timedelta(minutes=2), "web-server-01", f"Failed password for rpatel from {ip} port {_rand_port()} ssh2")
    b.ssh(start_time + timedelta(minutes=4), "db-server-02", f"Failed password for rpatel from {ip} port {_rand_port()} ssh2")
    b.ssh(start_time + timedelta(minutes=6), "db-server-02", f"Failed password for rpatel from {ip} port {_rand_port()} ssh2")
    b.windows(start_time + timedelta(minutes=8), 4625, "WIN-FILE01", TargetUserName="rpatel",
              IpAddress=ip, LogonType=3, FailureReason="Unknown user name or bad password")
    b.windows(start_time + timedelta(minutes=10), 4625, "WIN-FILE01", TargetUserName="rpatel",
              IpAddress=ip, LogonType=3, FailureReason="Unknown user name or bad password")


def _inject_compromise(b: LogBuilder, start_time: datetime) -> None:
    """Brute force that *succeeds* — the account-compromise escalation path."""
    ip = "198.51.100.45"
    for i in range(9):
        dt = start_time + timedelta(seconds=i * 20)
        b.ssh(dt, "db-server-02", f"Failed password for svc_backup from {ip} port {_rand_port()} ssh2")
    success_dt = start_time + timedelta(seconds=9 * 20 + 15)
    b.ssh(success_dt, "db-server-02", f"Accepted password for svc_backup from {ip} port {_rand_port()} ssh2")


def _inject_unusual_login_time(b: LogBuilder, reference_now: datetime) -> None:
    """A legitimate account logging in from its own usual IP, but at 3 AM."""
    dt = _most_recent_past_time_at(reference_now, hour=3, minute=14)
    b.ssh(dt, "db-server-02", f"Accepted password for mchen from {USERS['mchen']['ip']} port {_rand_port()} ssh2")


def _inject_distributed_low_and_slow(b: LogBuilder, start_time: datetime) -> None:
    """~18 different low-volume source IPs, none crossing the per-IP
    brute-force/credential-stuffing thresholds alone, but collectively a
    clear volume spike — the case rules miss and anomaly detection catches.
    Timing is kept tight enough that the whole burst reliably lands inside
    one ANOMALY_WINDOW_MINUTES window."""
    ips = [f"192.0.2.{n}" for n in random.sample(range(10, 250), 18)]
    t = start_time
    for ip in ips:
        for _ in range(random.randint(2, 4)):
            user = random.choice(COMMON_ATTACK_USERNAMES)
            b.ssh(t, "web-server-01", f"Failed password for invalid user {user} from {ip} port {_rand_port()} ssh2")
            t += timedelta(seconds=random.randint(5, 15))


ATTACK_INJECTORS: Dict[str, Callable[[LogBuilder, datetime], None]] = {
    "brute_force": _inject_brute_force,
    "port_scan": _inject_port_scan,
    "privilege_escalation": _inject_privilege_escalation,
    "suspicious_ip": _inject_suspicious_ip,
    "credential_stuffing": _inject_credential_stuffing,
    "cross_host_spray": _inject_cross_host_spray,
    "compromise": _inject_compromise,
    "unusual_login_time": _inject_unusual_login_time,
    "distributed": _inject_distributed_low_and_slow,
}


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def generate_all(sample_log_dir: Path = config.SAMPLE_LOG_DIR, days: int = 7, seed: int | None = None) -> Dict[str, int]:
    """(Re)generate a full week of background traffic plus one instance of
    every attack scenario, overwriting any existing sample logs."""
    if seed is not None:
        random.seed(seed)
    now = datetime.now(timezone.utc)
    b = LogBuilder()

    _generate_background_noise(b, now, days)
    _inject_privilege_escalation(b, now - timedelta(minutes=175))
    _inject_port_scan(b, now - timedelta(minutes=155))
    _inject_brute_force(b, now - timedelta(minutes=140))
    _inject_suspicious_ip(b, now - timedelta(minutes=120))
    _inject_credential_stuffing(b, now - timedelta(minutes=100))
    _inject_cross_host_spray(b, now - timedelta(minutes=80))
    _inject_compromise(b, now - timedelta(minutes=45))
    _inject_unusual_login_time(b, now)
    _inject_distributed_low_and_slow(b, now - timedelta(minutes=12))

    return b.write(sample_log_dir)


def simulate_attack(attack_type: str, sample_log_dir: Path = config.SAMPLE_LOG_DIR) -> Dict[str, int]:
    """Append ONE fresh attack scenario, timestamped essentially 'now', to
    the existing logs. Note: this only ever *writes synthetic log lines*
    to local demo files — it never opens a real network connection, sends
    real traffic, or performs any actual intrusion attempt against
    anything. It exists purely to demonstrate the detection pipeline."""
    if attack_type not in ATTACK_INJECTORS:
        raise ValueError(f"Unknown attack type {attack_type!r}. Options: {sorted(ATTACK_INJECTORS)}")
    now = datetime.now(timezone.utc)
    b = LogBuilder()
    ATTACK_INJECTORS[attack_type](b, now)
    return b.append(sample_log_dir)
