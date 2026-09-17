"""
Log normalization.

Three raw formats come in, one common `NormalizedEvent` schema goes out:

  ssh_auth          Linux OpenSSH/sudo lines, rsyslog high-precision (ISO8601)
                     timestamp format, e.g.:
                     2026-09-04T09:24:10+00:00 web-server-01 sshd[12345]: Failed password for root from 192.168.1.50 port 51235 ssh2

  windows_security   One JSON object per line, the shape you get out of a
                     Winlogbeat/Sysmon-style JSON export of the Security
                     channel, e.g.:
                     {"TimeCreated": "...", "EventID": 4625, "Computer": "WIN-DC01", ...}

  firewall           A simple key=value connection log, e.g.:
                     2026-09-04T11:00:01+00:00 fw-01 CONN src=203.0.113.77 dst=10.0.0.5 dport=22 proto=tcp action=blocked

Any line that doesn't match a known pattern is skipped (returns None)
rather than raising, so a single malformed line never kills a whole
ingest run. Skipped-line counts are surfaced by the caller.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from soc.models import NormalizedEvent

# ---------------------------------------------------------------------------
# Linux (OpenSSH / sudo via syslog, ISO8601 timestamps)
# ---------------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>[\w.\-]+)(\[\d+\])?:\s*(?P<msg>.*)$"
)
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_FAILED_RE = re.compile(
    r"^Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# Sudo commands worth flagging as a privilege-escalation *indicator*. Routine
# commands (ls, cat, apt update, systemctl status, ...) stay classified as
# low-signal `command_execution` so the alerting layer isn't flooded.
_SENSITIVE_SUDO_PATTERNS = [
    re.compile(r"\buseradd\b"),
    re.compile(r"\busermod\b.*\b(sudo|wheel|admin)\b"),
    re.compile(r"\bgroupadd\b.*\b(sudo|wheel|admin)\b"),
    re.compile(r"\bpasswd\s+root\b"),
    re.compile(r"\bvisudo\b"),
    re.compile(r"chmod\s+[+]?[su]\+?s"),
    re.compile(r"/bin/(ba)?sh$"),
    re.compile(r"\bsu\s+-\s*$"),
]


def _sudo_is_sensitive(command: str) -> bool:
    return any(p.search(command) for p in _SENSITIVE_SUDO_PATTERNS)


def parse_ssh_auth_line(line: str) -> Optional[NormalizedEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    ts, host, proc, msg = m.group("ts"), m.group("host"), m.group("proc"), m.group("msg")

    if proc == "sshd":
        acc = _SSH_ACCEPTED_RE.match(msg)
        if acc:
            return NormalizedEvent(
                timestamp=ts, event_type="auth_success", host=host, os="linux",
                source_format="ssh_auth", raw_text=line, source_ip=acc.group("ip"),
                user=acc.group("user"), status="success",
                description=f"Accepted SSH login for '{acc.group('user')}' via {acc.group('method')}",
                metadata={"port": int(acc.group("port"))},
            )
        fail = _SSH_FAILED_RE.match(msg)
        if fail:
            return NormalizedEvent(
                timestamp=ts, event_type="auth_failure", host=host, os="linux",
                source_format="ssh_auth", raw_text=line, source_ip=fail.group("ip"),
                user=fail.group("user"), status="failure",
                description=f"Failed SSH login attempt for '{fail.group('user')}'",
                metadata={"port": int(fail.group("port"))},
            )
        return NormalizedEvent(
            timestamp=ts, event_type="other", host=host, os="linux",
            source_format="ssh_auth", raw_text=line, status="info", description=msg,
        )

    if proc == "sudo":
        cmd_match = re.search(r"COMMAND=(?P<cmd>.*)$", msg)
        user_match = re.match(r"\s*(?P<user>\S+)\s*:", msg)
        user = user_match.group("user") if user_match else None
        cmd = cmd_match.group("cmd") if cmd_match else msg
        if _sudo_is_sensitive(cmd):
            return NormalizedEvent(
                timestamp=ts, event_type="privilege_escalation", host=host, os="linux",
                source_format="ssh_auth", raw_text=line, user=user, status="info",
                description=f"Sensitive sudo command executed by '{user}': {cmd}",
                metadata={"command": cmd},
            )
        return NormalizedEvent(
            timestamp=ts, event_type="command_execution", host=host, os="linux",
            source_format="ssh_auth", raw_text=line, user=user, status="info",
            description=f"sudo command by '{user}': {cmd}", metadata={"command": cmd},
        )

    return NormalizedEvent(
        timestamp=ts, event_type="other", host=host, os="linux",
        source_format="ssh_auth", raw_text=line, status="info", description=msg,
    )


# ---------------------------------------------------------------------------
# Windows Security event log (JSON lines)
# ---------------------------------------------------------------------------

_WINDOWS_EVENT_MAP = {
    4624: ("auth_success", "success"),
    4625: ("auth_failure", "failure"),
    4634: ("logoff", "info"),
    4647: ("logoff", "info"),
    4672: ("privilege_escalation", "info"),
    4732: ("privilege_escalation", "info"),
    4720: ("account_created", "info"),
    4688: ("process_creation", "info"),
}

# Command lines (Event ID 4688) worth flagging as escalation indicators.
_SENSITIVE_CMDLINE_PATTERNS = [
    re.compile(r"net(\.exe)?\s+user\b", re.I),
    re.compile(r"net(\.exe)?\s+localgroup\s+administrators", re.I),
    re.compile(r"whoami(\.exe)?\s+/priv", re.I),
    re.compile(r"reg(\.exe)?\s+add.*\\Run\b", re.I),
    re.compile(r"mimikatz", re.I),
    re.compile(r"Invoke-Mimikatz", re.I),
    re.compile(r"wmic(\.exe)?\s+useraccount", re.I),
]


def _cmdline_is_sensitive(cmdline: str) -> bool:
    return any(p.search(cmdline) for p in _SENSITIVE_CMDLINE_PATTERNS)


def parse_windows_security_line(line: str) -> Optional[NormalizedEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    event_id = data.get("EventID")
    ts = data.get("TimeCreated")
    host = data.get("Computer", "unknown-host")
    if event_id is None or not ts:
        return None

    event_type, status = _WINDOWS_EVENT_MAP.get(event_id, ("other", "info"))
    user = data.get("TargetUserName")
    ip = data.get("IpAddress")
    ip = ip if ip and ip not in ("-", "::1", "127.0.0.1") else None
    description = data.get("Message", f"Windows Event {event_id}")

    if event_id == 4625 and data.get("FailureReason"):
        description = f"Failed logon for '{user}': {data['FailureReason']}"
    elif event_id == 4624:
        description = f"Successful logon for '{user}' (LogonType {data.get('LogonType', '?')})"
    elif event_id == 4672:
        description = f"Special privileges assigned to new logon for '{user}' (admin-equivalent access)"
    elif event_id == 4732:
        member = data.get("MemberName", user)
        group = data.get("TargetGroupName", "a privileged group")
        description = f"User '{member}' added to privileged group '{group}'"
        user = member
    elif event_id == 4720:
        description = f"New user account created: '{data.get('TargetUserName')}'"
    elif event_id == 4688:
        cmdline = data.get("CommandLine", "")
        if _cmdline_is_sensitive(cmdline):
            event_type = "privilege_escalation"
            description = f"Sensitive command executed by '{user}': {cmdline}"
        else:
            description = f"Process created by '{user}': {data.get('NewProcessName', cmdline)}"

    return NormalizedEvent(
        timestamp=ts, event_type=event_type, host=host, os="windows",
        source_format="windows_security", raw_text=line, source_ip=ip, user=user,
        status=status, description=description,
        metadata={"event_id": event_id, "logon_type": data.get("LogonType")},
    )


# ---------------------------------------------------------------------------
# Firewall / connection log (key=value)
# ---------------------------------------------------------------------------

_FW_RE = re.compile(r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+CONN\s+(?P<kv>.*)$")


def parse_firewall_line(line: str) -> Optional[NormalizedEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    m = _FW_RE.match(line)
    if not m:
        return None
    ts, host, kv_text = m.group("ts"), m.group("host"), m.group("kv")
    kv = dict(re.findall(r"(\w+)=(\S+)", kv_text))

    dest_port = kv.get("dport")
    return NormalizedEvent(
        timestamp=ts, event_type="network_connection", host=host, os="network",
        source_format="firewall", raw_text=line, source_ip=kv.get("src"), dest_ip=kv.get("dst"),
        dest_port=int(dest_port) if dest_port and dest_port.isdigit() else None,
        protocol=kv.get("proto"), status=kv.get("action"),
        description=f"Connection {kv.get('src')} -> {kv.get('dst')}:{kv.get('dport')}/{kv.get('proto')} ({kv.get('action')})",
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PARSERS = {
    "ssh_auth": parse_ssh_auth_line,
    "windows_security": parse_windows_security_line,
    "firewall": parse_firewall_line,
}


def normalize_line(source_format: str, line: str) -> Optional[NormalizedEvent]:
    parser = _PARSERS.get(source_format)
    if not parser:
        raise ValueError(f"Unknown log source format: {source_format!r}")
    return parser(line)
