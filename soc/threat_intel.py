"""
Basic threat intelligence integration.

Three tiers, checked in order, cheapest and most reliable first:

  1. Private/reserved ranges (via the stdlib `ipaddress` module) -> "internal".
     No network, no data file, always correct.
  2. A local JSON blocklist (`data/threat_intel/malicious_ips.json`) -> "malicious"
     / "suspicious". Fully offline, ships with a few RFC 5737 documentation
     addresses so the demo works with zero configuration.
  3. (Optional) A live AbuseIPDB lookup, only attempted if ABUSEIPDB_API_KEY
     is set in the environment. Wrapped in a broad try/except with a short
     timeout so a missing key, no network, or a slow API never breaks the
     detection pipeline — it just falls back to "unknown".

Every lookup is cached in `threat_intel_cache` for THREAT_INTEL_CACHE_HOURS
so re-running detection repeatedly doesn't re-hit the network or re-parse
the JSON feed for IPs we've already seen.
"""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from functools import lru_cache
from typing import Optional

import config
from soc import database as db
from soc.models import ThreatIntelResult
from soc.utils import now_utc, parse_iso

# Deliberately narrower than ipaddress.IPv4Address.is_private, which also
# lumps in the IANA *documentation* ranges (RFC 5737: 192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) and the benchmarking range (198.18.0.0/15)
# as "private" simply because they're non-globally-routable. Those ranges
# are used throughout this project's demo data as stand-ins for external
# attacker IPs, so they must NOT be treated as internal/trusted here.
_RFC1918_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


@lru_cache(maxsize=1)
def _load_blocklist() -> dict:
    try:
        with open(config.MALICIOUS_IP_FEED, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {entry["ip"]: entry for entry in data.get("entries", [])}


def _classify_ip_kind(ip: str) -> Optional[ThreatIntelResult]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ThreatIntelResult(ip=ip, reputation="unknown", source="invalid", details={"note": "Not a valid IP address"})
    if addr.is_loopback or addr.is_link_local:
        return ThreatIntelResult(ip=ip, reputation="internal", source="private_range",
                                  details={"note": "Loopback/link-local address"})
    if any(addr in net for net in _RFC1918_NETWORKS):
        return ThreatIntelResult(ip=ip, reputation="internal", source="private_range",
                                  details={"note": "Private/internal (RFC1918) address space"})
    if addr.is_multicast:
        return ThreatIntelResult(ip=ip, reputation="internal", source="private_range",
                                  details={"note": "Multicast address"})
    return None


def _check_local_blocklist(ip: str) -> Optional[ThreatIntelResult]:
    entry = _load_blocklist().get(ip)
    if not entry:
        return None
    return ThreatIntelResult(
        ip=ip, reputation=entry.get("reputation", "suspicious"), source="local_blocklist",
        details={"note": entry.get("note", ""), "categories": entry.get("categories", [])},
    )


def _check_live_abuseipdb(ip: str) -> Optional[ThreatIntelResult]:
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5,
        )
        resp.raise_for_status()
        payload = resp.json().get("data", {})
        score = payload.get("abuseConfidenceScore", 0)
        reputation = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return ThreatIntelResult(
            ip=ip, reputation=reputation, source="abuseipdb",
            details={"abuse_confidence_score": score, "country": payload.get("countryCode"),
                     "isp": payload.get("isp"), "total_reports": payload.get("totalReports")},
        )
    except Exception as exc:  # noqa: BLE001 - any network/parse failure just falls back
        return ThreatIntelResult(ip=ip, reputation="unknown", source="abuseipdb_error", details={"error": str(exc)})


def _cache_is_fresh(cached: dict) -> bool:
    try:
        age_hours = (now_utc() - parse_iso(cached["checked_at"])).total_seconds() / 3600
    except Exception:  # noqa: BLE001
        return False
    return age_hours < config.THREAT_INTEL_CACHE_HOURS


def lookup_ip(conn: sqlite3.Connection, ip: str, use_cache: bool = True) -> ThreatIntelResult:
    if not ip:
        return ThreatIntelResult(ip="", reputation="unknown", source="no_data", details={})

    kind = _classify_ip_kind(ip)
    if kind is not None:
        return kind  # private/reserved/invalid never needs caching or lookups

    if use_cache:
        cached = db.get_threat_intel_cache(conn, ip)
        if cached and _cache_is_fresh(cached):
            return ThreatIntelResult(
                ip=ip, reputation=cached["reputation"], source=f"cache:{cached['source']}",
                details=json.loads(cached["details"] or "{}"),
            )

    result = _check_local_blocklist(ip)
    if result is None:
        result = _check_live_abuseipdb(ip)
    if result is None:
        result = ThreatIntelResult(ip=ip, reputation="unknown", source="no_data",
                                    details={"note": "No local or live threat-intel match"})

    db.set_threat_intel_cache(conn, ip, result.reputation, result.source, result.details)
    return result


def investigate_domain(conn: sqlite3.Connection, domain: str) -> dict:
    """Best-effort domain -> IP resolution, then reuse the IP investigation
    pipeline. Resolution requires outbound DNS; if unavailable (offline
    sandbox, restricted network) this degrades gracefully."""
    import socket
    try:
        resolved_ip = socket.gethostbyname(domain)
        error = None
    except (socket.gaierror, socket.timeout, OSError) as exc:
        resolved_ip = None
        error = str(exc)

    result = {"domain": domain, "resolved_ip": resolved_ip, "error": error, "threat_intel": None}
    if resolved_ip:
        result["threat_intel"] = lookup_ip(conn, resolved_ip).__dict__
    return result
