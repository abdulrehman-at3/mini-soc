# Mini-SOC — Security Monitoring & Incident Detection Platform

A working, self-contained SOC (Security Operations Center) platform in Python:
it collects security logs, normalizes them into a common schema, runs
rule-based **and** statistical anomaly detection over them, raises
severity-scored alerts, and gives an analyst a dashboard to investigate,
manage incidents, and generate reports — the full
**Detection → Alert → Investigation → Response → Reporting** loop.

```
Windows/Linux/Firewall Logs
            │
    Log Collector (soc/log_collector.py)
            │
  Log Normalization (soc/normalizer.py)
            │
     Detection Engine (soc/detection/engine.py)
       ┌────┴─────┐
       │          │
     Rules    Anomaly Detection
   (rules.py)   (anomaly.py)
       └────┬─────┘
            │
     Alert Engine (soc/alerting.py)
            │
     SOC Dashboard (dashboard/) ── Incident Management (soc/incidents.py)
            │
   Investigation, Search, Reporting
```

There's no real network involved anywhere in this project. It ships with a
synthetic log **generator** that produces realistic-looking Linux/Windows/
firewall logs, including one worked example of every attack pattern the
detection engine understands — so it's fully explorable in about 60 seconds
with zero external services, API keys, or real data.

## Quickstart

```bash
git clone <this repo>   # or unzip it
cd mini-soc
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python cli.py demo               # generates a week of logs, ingests, detects
python cli.py create-user        # create your analyst login (no default creds)
python run_dashboard.py          # http://127.0.0.1:5000
```

That's it — you'll land on a populated dashboard with a dozen alerts across
every severity level and one auto-opened critical incident.

To watch detection happen live rather than look at a fait accompli:

```bash
python cli.py simulate --attack brute_force --run
```

...then refresh the dashboard (or click **Run detection**) and watch a new
alert appear. `--attack` accepts `brute_force`, `port_scan`,
`privilege_escalation`, `suspicious_ip`, `credential_stuffing`,
`cross_host_spray`, `compromise`, `unusual_login_time`, or `distributed`.
This only ever appends synthetic log lines to local files — it never opens a
real connection or performs any actual network activity.

## Features

| Requested feature | Where it lives |
|---|---|
| Login/authentication monitoring | `soc/normalizer.py` — every SSH/Windows logon event is captured |
| Failed login detection | `event_type = auth_failure`, visible in Search and every alert |
| Brute-force detection | `detect_brute_force` — count-based, per (source IP, host), with success-after-failure → CRITICAL escalation |
| Suspicious IP detection | `detect_suspicious_ip` + `soc/threat_intel.py` |
| Port-scan detection | `detect_port_scan` — distinct ports per source IP in a rolling window |
| Privilege escalation indicators | `detect_privilege_escalation` — Windows 4672/4732 + sensitive Linux `sudo` commands |
| Unusual login times | `detect_unusual_login_time` — outside configured business hours/days |
| Multiple failed auth attempts | `detect_brute_force` (single IP) + `detect_cross_host_failures` (one account, many hosts) |
| Log search | `soc/search.py` + **Search** page |
| Alert severity levels | LOW / MEDIUM / HIGH / CRITICAL, consistent across every rule |
| Incident management | `soc/incidents.py` + **Incidents** pages (status, notes, linking alerts) |
| IP/domain investigation | **Investigate** page — reputation, timeline, risk score |
| Basic threat intelligence integration | `soc/threat_intel.py` — offline blocklist + private-range heuristics, optional live AbuseIPDB |
| Security dashboard | **Dashboard** home — stat tiles, charts, recent alerts |
| Incident reports | `soc/reports.py` — Markdown + HTML always, PDF if `fpdf2` is installed |

Plus one thing not on the list but worth calling out: **anomaly detection**
that catches what the rules can't — a distributed/low-and-slow credential
attack from ~18 different IPs, none of which individually cross any
threshold, flagged purely because organization-wide failed-login volume is a
statistical outlier for that time of day.

## The worked example, reproduced exactly

```
192.168.1.50 → SSH login attempts → Failed × 27 in ~2 minutes
```
produces:
```
Severity:   HIGH
Source IP:  192.168.1.50
Event:      Multiple Failed SSH Logins (Potential Brute Force Attack)
Attempts:   27
Time Window: 5 minutes (all 27 fell within it)
Status:     New → (click Investigate) → Investigating → ...
```
Run `python cli.py demo` and it's alert #3 (or thereabouts) waiting for you.

## Project structure

```
mini-soc/
├── cli.py                   # command-line interface (see below)
├── run_dashboard.py          # `python run_dashboard.py` starts the web app
├── config.py                 # every tunable threshold and path, in one place
├── soc/                       # framework-agnostic core (no Flask import here)
│   ├── database.py            # SQLite schema + all queries
│   ├── models.py                # NormalizedEvent / Detection / ThreatIntelResult
│   ├── log_generator.py          # synthetic Linux/Windows/firewall log + attack generator
│   ├── normalizer.py               # raw log line -> NormalizedEvent
│   ├── log_collector.py             # tracks file offsets, ingests new lines
│   ├── detection/
│   │   ├── rules.py                  # the 7 correlation rules
│   │   ├── anomaly.py                 # statistical volume-anomaly detector
│   │   └── engine.py                   # runs all of the above
│   ├── threat_intel.py                  # private ranges + local blocklist + optional live API
│   ├── alerting.py                       # detections -> deduped, escalating alerts
│   ├── incidents.py                       # incident lifecycle
│   ├── search.py                           # paginated event search
│   └── reports.py                          # Markdown/HTML/PDF report generation
├── dashboard/                # the only place Flask is imported
│   ├── app.py                  # routes
│   ├── auth.py                   # login_required, first-run /setup flow
│   └── templates/, static/          # dark "SOC console" theme, Chart.js via CDN
├── data/
│   ├── threat_intel/malicious_ips.json  # seed blocklist (RFC 5737 demo addresses)
│   ├── sample_logs/                       # generated logs land here
│   └── reports/                             # generated reports land here
└── tests/                    # 43 unit + integration tests, stdlib unittest only
```

## CLI reference

```
python cli.py init-db                       create the database if missing
python cli.py create-user                   create a dashboard login (prompts for password)
python cli.py generate-logs [--days N]      (re)generate a week of sample logs
python cli.py ingest                        read new lines into the database
python cli.py detect                        run rules + anomaly detection
python cli.py run                           ingest + detect in one step
python cli.py demo                          generate-logs + ingest + detect
python cli.py simulate --attack TYPE [--run]  append one live attack scenario
python cli.py search --ip/--user/--host/--type/--q ...
python cli.py alerts [--severity] [--status]
python cli.py report --incident ID          generate a report for an incident
python cli.py stats                         quick summary of the current state
```

## Design notes (things worth knowing / mentioning in an interview)

- **Detection windows are anchored to event time, not wall-clock time.**
  `detect_brute_force` and friends compute "now" as the latest timestamp
  among the relevant events, not `datetime.now()`. That means re-running
  `detect` a week after ingesting a batch of historical logs gives the exact
  same alerts as running it the instant the logs arrived — important for
  batch/offline analysis, and it makes the rules trivially unit-testable
  with fixed timestamps instead of mocking the clock.
- **Rules and the anomaly detector deliberately overlap once, on purpose.**
  The credential-stuffing demo IP also crosses the brute-force volume
  threshold — in the demo data that's left in intentionally, because in
  real SOC work one root cause often trips more than one alert, which is
  exactly why alerts link into a single incident rather than each spawning
  its own case.
- **No hardcoded default login.** The dashboard has zero users until you
  create one (`/setup` on first run, or `cli.py create-user`). Shipping
  `admin`/`admin123` and hoping people change it is the exact anti-pattern
  this kind of tool exists to flag.
- **Demo "attacker" IPs use RFC 5737 documentation ranges**
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) instead of
  made-up-but-plausible public addresses, so nothing in this repo could be
  mistaken for a real host. Watch out: Python's `ipaddress.is_private` also
  quietly lumps these in as "private" (they're non-globally-routable) —
  `soc/threat_intel.py` deliberately checks RFC 1918 ranges explicitly
  instead of trusting that flag, or every demo "attacker" would be
  misclassified as internal/trusted.
- **Alerts expire out of dedup, not just status.** An open alert stops
  absorbing new matching activity after `ALERT_STALE_REOPEN_HOURS` (default
  6h) of quiet — a source going silent for a week and then reappearing
  reads as a new case, not a stale alert "still" being worked.
- **Report generation degrades gracefully.** Markdown and HTML always work
  (Jinja2 ships with Flask). PDF is attempted only if `fpdf2` is installed
  and is skipped — not a hard failure — if it isn't.
- **Threat intel is pluggable.** Fully offline by default (private-range
  heuristics + local JSON blocklist). Set `ABUSEIPDB_API_KEY` in the
  environment to additionally check live reputation data; lookups are
  cached in SQLite either way.

## Extending it

- **New log source**: write a `parse_x_line(line) -> NormalizedEvent | None`
  in `soc/normalizer.py`, register it in `_PARSERS`, add it to
  `config.LOG_SOURCES`.
- **New detection rule**: add a `detect_x(conn, trigger_events, cfg) ->
  list[Detection]` function to `soc/detection/rules.py` and append it to
  `RULES`. Give it a `dedup_key` and it gets deduplication/escalation for free.
- **Real threat intel feed**: edit `data/threat_intel/malicious_ips.json`,
  or set `ABUSEIPDB_API_KEY` for live lookups.
- **Per-user learned baselines** (instead of one fixed business-hours
  window) would be the natural next step for `detect_unusual_login_time` —
  noted rather than built, to keep the demo's setup instant.

## Testing

```bash
python -m unittest discover tests -v
```

43 tests: log-format parsing, every detection rule at/under/over its
threshold, alert dedup/escalation/staleness, threat-intel classification,
the anomaly detector, and one full integration test that regenerates the
demo dataset and asserts every rule type fires.

## License

MIT — see `LICENSE`.
#   M i n i - S O C  
 