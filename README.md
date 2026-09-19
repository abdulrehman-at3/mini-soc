# 🛡️ Mini-SOC — Security Monitoring & Incident Detection Platform

**A working Security Operations Center, in Python.** Logs go in one end;
correlated, severity-scored alerts and analyst-ready incident reports come
out the other — collection, normalization, rule-based *and* statistical
anomaly detection, alerting, incident management, and a full web dashboard,
all built from scratch with no external security services required.

![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.x-black.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-43%20passing-brightgreen.svg)
![Status](https://img.shields.io/badge/status-portfolio%20project-orange.svg)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Screenshots](#screenshots)
- [Quickstart](#quickstart)
- [CLI Reference](#cli-reference)
- [The Worked Example, Reproduced Exactly](#the-worked-example-reproduced-exactly)
- [Project Structure](#project-structure)
- [Detection Rules](#detection-rules)
- [Design Decisions](#design-decisions-worth-knowing)
- [Tech Stack](#tech-stack)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)

## Overview

Real SOC (Security Operations Center) tooling watches a firehose of Linux,
Windows, and network logs, correlates it against known attack patterns and
statistical baselines, and gives an analyst a queue of prioritized,
investigable alerts instead of an unreadable wall of raw text. Mini-SOC is a
small but fully functional version of that pipeline, demonstrating the
complete workflow real SOC analysts live in:

> **Detection → Alert → Investigation → Response → Reporting**

It ships with a synthetic log generator that produces realistic Linux/
Windows/firewall logs — including one worked example of *every* attack
pattern the engine understands — so the whole thing is explorable in under
a minute with zero external services, API keys, or real data required.

## Architecture

```
Windows / Linux / Firewall Logs
            │
    Log Collector (soc/log_collector.py)
            │
  Log Normalization (soc/normalizer.py)
            │
     Detection Engine (soc/detection/engine.py)
       ┌────┴─────┐
       │          │
     Rules    Anomaly Detection
  (rules.py)    (anomaly.py)
       └────┬─────┘
            │
     Alert Engine (soc/alerting.py)
            │
     SOC Dashboard (dashboard/) ── Incident Management (soc/incidents.py)
            │
   Investigation • Search • Reporting
```

## Features

| Capability | Implementation |
|---|---|
| ✅ Login/authentication monitoring | Every SSH & Windows logon event is captured and normalized |
| ✅ Failed login detection | `event_type = auth_failure`, searchable and visible on every alert |
| ✅ Brute-force detection | Per (source IP, host) count in a rolling window, with success-after-failure → CRITICAL escalation |
| ✅ Suspicious IP detection | Local blocklist + private-range heuristics, optional live threat-intel API |
| ✅ Port-scan detection | Distinct destination ports per source IP in a rolling window |
| ✅ Privilege escalation indicators | Windows Event IDs 4672/4732 + sensitive Linux `sudo` commands |
| ✅ Unusual login times | Flags successful logins outside configured business hours/days |
| ✅ Multiple failed auth attempts | Single-IP brute force **and** one-account-many-hosts password spraying |
| ✅ Log search | Full-text + field filters across every ingested event, raw log line included |
| ✅ Alert severity levels | LOW / MEDIUM / HIGH / CRITICAL, consistent across every rule |
| ✅ Incident management | Status lifecycle, analyst notes, multi-alert linking |
| ✅ IP/domain investigation | Reputation, full event history, computed risk score |
| ✅ Threat intelligence integration | Offline-first blocklist, optional live AbuseIPDB lookup, SQLite-cached |
| ✅ Security dashboard | Stat tiles, live charts, recent-alerts feed |
| ✅ Incident reports | Markdown + HTML always, PDF when `fpdf2` is available |
| ➕ Statistical anomaly detection | Catches distributed/low-and-slow attacks that stay under every per-IP threshold |

## Screenshots

*Run it locally and drop your own screenshots in here* — `python run_dashboard.py`
gets you a populated dashboard in under a minute (see [Quickstart](#quickstart)).
Recommended shots: the dashboard home, an alert detail page, and the
Investigate view for `192.168.1.50`.

## Quickstart

```bash
git clone <your-fork-url> mini-soc   # or unzip the release
cd mini-soc

python3 -m venv venv
source venv/bin/activate             # Windows: venv\Scripts\activate
pip install -r requirements.txt

python cli.py demo                   # generates a week of logs, ingests, detects
python cli.py create-user            # create your analyst login (no default creds)
python run_dashboard.py              # → http://127.0.0.1:5000
```

You'll land on a populated dashboard with a dozen alerts spanning every
severity level and one auto-opened critical incident. To watch detection
happen live instead of looking at a fait accompli:

```bash
python cli.py simulate --attack brute_force --run
```

`--attack` accepts `brute_force`, `port_scan`, `privilege_escalation`,
`suspicious_ip`, `credential_stuffing`, `cross_host_spray`, `compromise`,
`unusual_login_time`, or `distributed`. This only ever appends synthetic log
lines to local files — it never opens a real connection or performs any
actual network activity.

## CLI Reference

```
python cli.py init-db                          create the database if missing
python cli.py create-user                      create a dashboard login (prompts for password)
python cli.py generate-logs [--days N]         (re)generate a week of sample logs
python cli.py ingest                           read new lines into the database
python cli.py detect                           run rules + anomaly detection
python cli.py run                              ingest + detect in one step
python cli.py demo                             generate-logs + ingest + detect
python cli.py simulate --attack TYPE [--run]   append one live attack scenario
python cli.py search --ip/--user/--host/--type/--q ...
python cli.py alerts [--severity] [--status]
python cli.py report --incident ID             generate a report for an incident
python cli.py stats                            quick summary of current state
```

## The Worked Example, Reproduced Exactly

Input:
```
192.168.1.50 → SSH login attempts → Failed × 27 in ~2 minutes
```

Output:
```
Severity:    HIGH
Source IP:   192.168.1.50
Event:       Multiple Failed SSH Logins (Potential Brute Force Attack)
Attempts:    27
Time Window: 5 minutes (all 27 fell within it)
Status:      New → Investigating → Resolved
```

Run `python cli.py demo` and it's waiting for you in the Alerts list.

## Project Structure

```
mini-soc/
├── cli.py                    # command-line interface
├── run_dashboard.py          # `python run_dashboard.py` starts the web app
├── config.py                 # every tunable threshold and path, in one place
├── soc/                      # framework-agnostic core (no Flask import here)
│   ├── database.py             # SQLite schema + all queries
│   ├── models.py                 # NormalizedEvent / Detection / ThreatIntelResult
│   ├── log_generator.py            # synthetic Linux/Windows/firewall log + attack generator
│   ├── normalizer.py                 # raw log line -> NormalizedEvent
│   ├── log_collector.py                # tracks file offsets, ingests new lines
│   ├── detection/
│   │   ├── rules.py                      # the 7 correlation rules
│   │   ├── anomaly.py                      # statistical volume-anomaly detector
│   │   └── engine.py                         # runs all of the above
│   ├── threat_intel.py                         # private ranges + local blocklist + optional live API
│   ├── alerting.py                               # detections -> deduped, escalating alerts
│   ├── incidents.py                                # incident lifecycle
│   ├── search.py                                     # paginated event search
│   └── reports.py                                      # Markdown/HTML/PDF report generation
├── dashboard/                 # the only place Flask is imported
│   ├── app.py                   # routes
│   ├── auth.py                    # login_required, first-run /setup flow
│   └── templates/, static/          # dark "SOC console" theme, Chart.js via CDN
├── data/
│   ├── threat_intel/malicious_ips.json  # seed blocklist (RFC 5737 demo addresses)
│   ├── sample_logs/                       # generated logs land here
│   └── reports/                             # generated reports land here
└── tests/                     # 43 unit + integration tests, stdlib unittest only
```

## Detection Rules

| Rule | Signal | Default Threshold | Severity |
|---|---|---|---|
| Brute force | Failed logins, same source IP + host | 8 / 15 / 30 in 5 min | MEDIUM / HIGH / CRITICAL |
| ↳ + success after failures | A login succeeds during an active brute-force burst | — | CRITICAL |
| Port scan | Distinct destination ports, same source IP | 8 / 15 in 90 sec | MEDIUM / HIGH |
| Privilege escalation | Windows 4672/4732, sensitive `sudo` commands | any occurrence | HIGH |
| Unusual login time | Successful login outside business hours | outside 07:00–20:00 Mon–Fri | LOW |
| Suspicious IP | Source IP on blocklist / flagged by threat intel | any match | MEDIUM / HIGH |
| Credential stuffing | Distinct usernames, same source IP | 6+ in 5 min | HIGH |
| Cross-host password spraying | One account, failures across many hosts | 3+ hosts, 5+ failures in 15 min | MEDIUM |
| **Anomaly detection** | Org-wide failed-login volume vs. 7-day baseline | z-score ≥ 2.5 | MEDIUM / HIGH |

All thresholds live in one place: [`config.py`](config.py).

## Design Decisions Worth Knowing

- **Detection windows are anchored to event time, not wall-clock time.**
  Re-running `detect` on the same historical logs a week later produces
  identical alerts — important for batch analysis, and it makes every rule
  trivially unit-testable with fixed timestamps instead of mocking the clock.
- **No hardcoded default login.** The dashboard has zero users until you
  create one (`/setup` on first run, or `cli.py create-user`).
- **Demo "attacker" IPs use RFC 5737 documentation ranges**
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) so nothing in this
  repo could be mistaken for a real host. Note: Python's
  `ipaddress.is_private` quietly lumps these in as "private" — `threat_intel.py`
  checks RFC 1918 ranges explicitly instead of trusting that flag.
- **Alerts deduplicate, but also expire out of dedup.** An ongoing attack
  updates one alert instead of spamming duplicates, but an open alert stops
  absorbing new activity after 6 hours of quiet — renewed activity later
  reads as a new case, not a stale alert "still" being worked.
- **Report generation degrades gracefully.** Markdown/HTML always work; PDF
  is attempted only if `fpdf2` is installed and skipped (not a hard failure)
  if it isn't.

## Tech Stack

**Backend:** Python 3, Flask, SQLite (stdlib `sqlite3`), Jinja2
**Frontend:** Server-rendered HTML/CSS, Chart.js (via CDN), zero JS build step
**Testing:** stdlib `unittest`
**Optional:** `requests` (live threat intel), `fpdf2` (PDF reports)

No database server, no Node/npm toolchain, no external services required to run it.

## Testing

```bash
python -m unittest discover tests -v
```

43 tests covering log-format parsing, every detection rule at/under/over its
threshold, alert dedup/escalation/staleness, threat-intel classification,
the anomaly detector, and a full integration test that regenerates the demo
dataset and asserts every rule type fires.

## Roadmap

- [ ] Per-user learned login-time baselines instead of one fixed business-hours window
- [ ] Additional threat-intel providers beyond AbuseIPDB
- [ ] Real log source ingestion (syslog forwarder / Winlogbeat) alongside the demo generator
- [ ] Role-based access control (multiple analysts, read-only vs. admin)
- [ ] Dockerfile + docker-compose for one-command deployment
- [ ] WebSocket/SSE live alert feed instead of manual "Run detection"

## Disclaimer

Mini-SOC is an educational/portfolio project built to demonstrate SOC
workflows and detection engineering. **All log data is synthetically
generated** — no real logs, hosts, or network traffic are ever involved,
including in the "simulate attack" feature, which only appends text to
local files. It is not a substitute for production security tooling and
has not been hardened for exposure to untrusted networks or real
production log volumes.

## Contributing

This started as a portfolio/learning project, but issues and PRs are
welcome — especially new detection rules, additional log format parsers, or
improvements to the anomaly-detection baseline.

## License

[MIT](LICENSE)
