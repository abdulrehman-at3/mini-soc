"""
Incident + SOC summary report generation.

Markdown and HTML are always produced (zero extra dependencies — Jinja2
ships with Flask). PDF is produced too if `fpdf2` happens to be installed,
via a plain-text rendering of the same data; if it isn't installed, PDF
is silently skipped rather than the whole report failing. This is a
deliberate degrade-gracefully design: a demo/portfolio project shouldn't
hard-fail because of one optional dependency.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
from soc import database as db
from soc import incidents as incidents_module
from soc.utils import now_iso

_env = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "report_templates")),
    autoescape=select_autoescape(enabled_extensions=("html.j2",)),
    trim_blocks=True, lstrip_blocks=True,
)

REMEDIATION_SUGGESTIONS = {
    "brute_force": [
        "Block or rate-limit the source IP at the perimeter firewall.",
        "Confirm account-lockout policy is enabled for the targeted account(s).",
        "Enable multi-factor authentication for the targeted account(s).",
        "If any login succeeded during the window, treat the account as compromised: "
        "force a password reset and review its recent activity.",
    ],
    "port_scan": [
        "Block or rate-limit the source IP.",
        "Review which scanned ports are actually exposed and close/firewall unnecessary services.",
        "Confirm IDS/IPS signatures covering scan behavior are current.",
    ],
    "privilege_escalation": [
        "Verify the privilege change was authorized (change ticket / approval trail).",
        "Audit local admin / privileged-group membership for other unauthorized entries.",
        "Rotate credentials for the affected account.",
        "Review recent command history on the host for further unauthorized activity.",
    ],
    "suspicious_ip": [
        "Add the IP to the perimeter blocklist.",
        "Review all historical activity from this IP across the environment.",
        "Cross-reference with additional threat-intel sources if available.",
    ],
    "credential_stuffing": [
        "Block or rate-limit the source IP.",
        "Check whether any of the attempted usernames correspond to real accounts and force a password reset if so.",
        "Enable multi-factor authentication broadly if not already required.",
    ],
    "cross_host_auth_failures": [
        "Force a password reset for the targeted account.",
        "Check whether the account's credentials appear in any known breach data.",
        "Review authentication logs for the account across ALL hosts, not just the ones alerted on.",
    ],
    "unusual_login_time": [
        "Confirm with the account owner (or system owner, for service accounts) that the access was expected.",
        "Check for concurrent or impossible-travel logins from other locations.",
    ],
    "anomalous_auth_volume": [
        "Review the full list of source IPs involved for any overlap with known infrastructure.",
        "Consider temporarily tightening authentication rate limits organization-wide.",
        "Watch for a follow-up spike in successful logins, which would indicate the campaign found valid credentials.",
    ],
}
_DEFAULT_REMEDIATION = ["Review the linked events and determine an appropriate response for this alert type."]
DEFAULT_REMEDIATION = _DEFAULT_REMEDIATION  # public alias, used by the dashboard's alert-detail view


def _indicators_from(alerts: List[dict], events: List[dict]) -> Dict[str, List[str]]:
    ips = sorted({a["source_ip"] for a in alerts if a["source_ip"]} | {e["source_ip"] for e in events if e["source_ip"]})
    users = sorted({a["user"] for a in alerts if a["user"]} | {e["user"] for e in events if e["user"]})
    hosts = sorted({a["host"] for a in alerts if a["host"]} | {e["host"] for e in events if e["host"]})
    return {"ips": ips, "users": users, "hosts": hosts}


def _remediation_for(alerts: List[dict]) -> List[str]:
    steps: List[str] = []
    seen = set()
    for alert in alerts:
        for step in REMEDIATION_SUGGESTIONS.get(alert["rule_name"], _DEFAULT_REMEDIATION):
            if step not in seen:
                steps.append(step)
                seen.add(step)
    return steps or _DEFAULT_REMEDIATION


def build_incident_report_data(conn: sqlite3.Connection, incident_id: int) -> Optional[dict]:
    incident = incidents_module.get_full_incident(conn, incident_id)
    if not incident:
        return None
    alerts, events, notes = incident["alerts"], incident["events"], incident["notes"]
    return {
        "incident": incident,
        "alerts": alerts,
        "events": events,
        "notes": notes,
        "indicators": _indicators_from(alerts, events),
        "remediation": _remediation_for(alerts),
        "generated_at": now_iso(),
    }


def render_markdown(data: dict) -> str:
    return _env.get_template("incident_report.md.j2").render(**data)


def render_html(data: dict) -> str:
    return _env.get_template("incident_report.html.j2").render(**data)


def _pdf_safe(text) -> str:
    """fpdf2's core (non-Unicode) fonts only support latin-1. Normalize the
    handful of "smart" punctuation characters our own copy uses (em/en
    dashes, curly quotes, ellipsis, bullets) to plain ASCII equivalents,
    and replace anything else non-latin-1 rather than crashing report
    generation over a stray character in a user-entered note."""
    if text is None:
        return ""
    text = str(text)
    replacements = {
        "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " ", "\u2022": "-",
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _render_pdf(data: dict, out_path: Path) -> bool:
    try:
        from fpdf import FPDF
    except ImportError:
        return False

    pdf = FPDF()
    pdf.add_page()

    def line(text: str = "", bold: bool = False, size: int = 11) -> None:
        pdf.set_font("Helvetica", "B" if bold else "", size)
        pdf.multi_cell(0, 6, _pdf_safe(text))
        pdf.ln(0)  # multi_cell(width=0) leaves x at the right edge; reset to the left margin

    line(f"Incident Report #{data['incident']['id']}: {data['incident']['title']}", bold=True, size=16)
    pdf.ln(2)

    inc = data["incident"]
    line(f"Severity: {inc['severity']}    Status: {inc['status']}    Assigned to: {inc['assigned_to'] or 'Unassigned'}")
    line(f"Opened: {inc['created_at']}    Closed: {inc['closed_at'] or '-'}")
    line(f"Report generated: {data['generated_at']}")
    pdf.ln(3)
    line("Executive Summary", bold=True, size=13)
    line(inc["description"] or "")
    if inc.get("resolution"):
        line(f"Resolution: {inc['resolution']}")
    pdf.ln(3)

    line("Indicators of Compromise", bold=True, size=13)
    ind = data["indicators"]
    line(f"Source IP(s): {', '.join(ind['ips']) or 'None recorded'}")
    line(f"User account(s): {', '.join(ind['users']) or 'None recorded'}")
    line(f"Affected host(s): {', '.join(ind['hosts']) or 'None recorded'}")
    pdf.ln(3)

    line(f"Linked Alerts ({len(data['alerts'])})", bold=True, size=13)
    for a in data["alerts"]:
        line(f"#{a['id']} [{a['severity']}] {a['title']}", bold=True)
        line(f"  Rule: {a['rule_name']}  Source IP: {a['source_ip'] or '-'}  User: {a['user'] or '-'}  Host: {a['host'] or '-'}")
        line(f"  {a['description']}")
    pdf.ln(3)

    line(f"Event Timeline ({len(data['events'])} events)", bold=True, size=13)
    for e in data["events"][:200]:  # keep the PDF a reasonable length
        line(f"{e['timestamp']}  {e['event_type']:<20s} {e['source_ip'] or '-':<16s} {e['user'] or '-':<14s} {e['host']}", size=8)
    if len(data["events"]) > 200:
        line(f"... and {len(data['events']) - 200} more events (see the HTML/Markdown report for the full list).", size=8)
    pdf.ln(3)

    line("Analyst Notes", bold=True, size=13)
    for n in data["notes"]:
        line(f"{n['created_at']} ({n['author']}): {n['note']}")
    pdf.ln(3)

    line("Recommended Remediation", bold=True, size=13)
    for step in data["remediation"]:
        line(f"- {step}")

    pdf.output(str(out_path))
    return True


def generate_incident_report(
    conn: sqlite3.Connection, incident_id: int, output_dir: Path = config.REPORTS_DIR,
) -> Optional[Dict[str, str]]:
    data = build_incident_report_data(conn, incident_id)
    if data is None:
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    base = f"incident_{incident_id}"
    paths: Dict[str, str] = {}

    md_path = output_dir / f"{base}.md"
    md_path.write_text(render_markdown(data), encoding="utf-8")
    paths["md"] = str(md_path)

    html_path = output_dir / f"{base}.html"
    html_path.write_text(render_html(data), encoding="utf-8")
    paths["html"] = str(html_path)

    pdf_path = output_dir / f"{base}.pdf"
    if _render_pdf(data, pdf_path):
        paths["pdf"] = str(pdf_path)

    return paths


# ---------------------------------------------------------------------------
# SOC summary report (a lighter-weight, period-based overview)
# ---------------------------------------------------------------------------

def build_soc_summary_data(conn: sqlite3.Connection, since: str, until: str) -> dict:
    alerts = db.query_alerts(conn, limit=10000)
    alerts_in_range = [a for a in alerts if since <= a["created_at"] <= until]
    incidents_list = db.query_incidents(conn, limit=10000)
    incidents_in_range = [i for i in incidents_list if since <= i["created_at"] <= until]
    by_severity: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    for a in alerts_in_range:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        by_rule[a["rule_name"]] = by_rule.get(a["rule_name"], 0) + 1
    top_ips = db.events_grouped_count(conn, "source_ip", since=since, limit=10)
    return {
        "since": since, "until": until, "generated_at": now_iso(),
        "total_events": db.count_events(conn, since=since, until=until),
        "alerts": alerts_in_range, "incidents": incidents_in_range,
        "by_severity": by_severity, "by_rule": by_rule, "top_source_ips": top_ips,
    }


def render_soc_summary_markdown(data: dict) -> str:
    lines = [
        f"# SOC Summary Report — {data['since']} to {data['until']}", "",
        f"Generated: {data['generated_at']}", "",
        f"- Total events: {data['total_events']}",
        f"- Alerts: {len(data['alerts'])}",
        f"- Incidents: {len(data['incidents'])}", "",
        "## Alerts by severity", "",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"- {sev}: {data['by_severity'].get(sev, 0)}")
    lines += ["", "## Alerts by rule", ""]
    for rule, count in sorted(data["by_rule"].items(), key=lambda kv: -kv[1]):
        lines.append(f"- {rule}: {count}")
    lines += ["", "## Top source IPs", ""]
    for row in data["top_source_ips"]:
        lines.append(f"- {row['key']}: {row['c']} events")
    lines += ["", "## Incidents", ""]
    for inc in data["incidents"]:
        lines.append(f"- #{inc['id']} [{inc['severity']}] {inc['title']} — {inc['status']}")
    return "\n".join(lines)


def generate_soc_summary(conn: sqlite3.Connection, since: str, until: str, output_dir: Path = config.REPORTS_DIR) -> str:
    data = build_soc_summary_data(conn, since, until)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"soc_summary_{since[:10]}_to_{until[:10]}.md"
    path.write_text(render_soc_summary_markdown(data), encoding="utf-8")
    return str(path)
