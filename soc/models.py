"""Lightweight data containers shared between normalization, detection,
and alerting. These are plain dataclasses (not an ORM) — the actual
persistence layer is `soc/database.py`, which speaks SQL directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    """A single security-relevant event, in a common schema, regardless of
    whether it originated from a Linux auth.log, a Windows Security event
    log, or a firewall connection log."""

    timestamp: str  # ISO8601 UTC
    event_type: str  # auth_success, auth_failure, privilege_escalation,
    #                  account_created, network_connection, process_creation,
    #                  logoff, command_execution, other
    host: str
    os: str  # linux | windows | network
    source_format: str  # ssh_auth | windows_security | firewall
    raw_text: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    user: Optional[str] = None
    status: Optional[str] = None  # success | failure | info | allowed | blocked
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Detection:
    """The output of a single detection rule (or the anomaly engine) before
    it becomes a persisted Alert. `dedup_key` lets the alert engine collapse
    an ongoing attack into one updated alert instead of spamming duplicates.
    """

    rule_name: str
    severity: str
    title: str
    description: str
    dedup_key: str
    event_ids: List[int] = field(default_factory=list)
    source_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelResult:
    ip: str
    reputation: str  # internal | clean | unknown | suspicious | malicious
    source: str  # private_range | local_blocklist | abuseipdb | no_data | cache
    details: Dict[str, Any] = field(default_factory=dict)
