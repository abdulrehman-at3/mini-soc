"""
Mini-SOC dashboard (Flask).

This file is intentionally the only place `Flask` is imported anywhere in
the codebase. Every route is a thin wrapper: pull request params, call
into `soc.*`, render a template. All of the actual detection/alerting/
incident logic lives in the framework-agnostic `soc` package and is
exercised the same way whether it's driven from here or from `cli.py`.
"""
from __future__ import annotations

import re
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config
from dashboard.auth import current_user, login_required, no_users_exist
from soc import alerting, database as db, incidents as incidents_module, reports, search, threat_intel
from soc.detection.engine import run_detection_pipeline
from soc.log_collector import collect_new_events
from soc.log_generator import ATTACK_INJECTORS, simulate_attack
from soc.utils import STATUS_COLORS, humanize_timedelta, now_iso, now_utc, paginate, parse_iso, to_iso

ALERT_STATUSES = ["New", "Investigating", "Resolved", "False Positive", "Closed"]


def _load_or_create_secret_key() -> str:
    path = config.SECRET_KEY_FILE
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    path.write_text(key)
    return key


def _compute_risk_score(ti, related_alerts: list) -> int:
    score = 0
    if ti:
        score += {"malicious": 50, "suspicious": 25, "unknown": 5, "internal": 0, "clean": 0}.get(ti.reputation, 0)
    for a in related_alerts:
        score += {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(a["severity"], 0)
    return min(100, score)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = _load_or_create_secret_key()

    # -- request lifecycle: one SQLite connection per request --------------
    @app.before_request
    def _open_db():
        g.db = db.get_connection(config.DB_PATH)

    @app.teardown_appcontext
    def _close_db(_exception):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.context_processor
    def inject_globals():
        return {"logged_in_user": current_user() if session.get("user_id") else None}

    @app.template_filter("timeago")
    def timeago_filter(value):
        if not value:
            return ""
        return humanize_timedelta(parse_iso(value))

    @app.template_filter("statusclass")
    def statusclass_filter(value):
        return STATUS_COLORS.get(value, "status-new")

    # -- Auth ----------------------------------------------------------------
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if not no_users_exist():
            return redirect(url_for("login"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            if not username:
                flash("Choose a username.", "error")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
            elif password != confirm:
                flash("Passwords did not match.", "error")
            else:
                db.create_user(g.db, username, generate_password_hash(password))
                flash("Account created. Log in below.", "success")
                return redirect(url_for("login"))
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if no_users_exist():
            return redirect(url_for("setup"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db.get_user_by_username(g.db, username)
            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                return redirect(url_for("dashboard_home"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # -- Dashboard home --------------------------------------------------------
    @app.route("/")
    @login_required
    def dashboard_home():
        stats = db.summary_stats(g.db)
        recent_alerts = db.query_alerts(g.db, limit=8)
        top_ips = db.events_grouped_count(g.db, "source_ip", limit=6)
        return render_template("dashboard.html", stats=stats, recent_alerts=recent_alerts, top_ips=top_ips,
                               attack_types=sorted(ATTACK_INJECTORS))

    @app.route("/api/stats/alerts-by-severity")
    @login_required
    def api_alerts_by_severity():
        return jsonify(db.alerts_grouped_by_severity(g.db))

    @app.route("/api/stats/events-timeline")
    @login_required
    def api_events_timeline():
        since = to_iso(now_utc() - timedelta(hours=48))
        rows = db.events_timeseries(g.db, bucket_hours=2, since=since)
        out = [{"label": parse_iso(r["bucket"]).strftime("%m-%d %H:%M"), "count": r["count"]} for r in rows]
        return jsonify(out)

    # -- Pipeline actions --------------------------------------------------
    @app.route("/pipeline/run", methods=["POST"])
    @login_required
    def pipeline_run():
        result = collect_new_events(g.db)
        detections = run_detection_pipeline(g.db, result.new_events)
        summary = alerting.process_detections(g.db, detections, config)
        flash(f"Ingested {len(result.new_events)} new event(s). "
              f"{len(summary['new_alerts'])} new alert(s), {len(summary['updated_alerts'])} updated, "
              f"{len(summary['incidents_created'])} incident(s) opened.", "success")
        return redirect(request.referrer or url_for("dashboard_home"))

    @app.route("/pipeline/simulate", methods=["POST"])
    @login_required
    def pipeline_simulate():
        attack_type = request.form.get("attack_type")
        if attack_type not in ATTACK_INJECTORS:
            flash("Unknown attack type.", "error")
            return redirect(url_for("dashboard_home"))
        simulate_attack(attack_type)
        result = collect_new_events(g.db)
        detections = run_detection_pipeline(g.db, result.new_events)
        summary = alerting.process_detections(g.db, detections, config)
        flash(f"Simulated '{attack_type}': {len(summary['new_alerts'])} new alert(s), "
              f"{len(summary['updated_alerts'])} updated. (Synthetic log lines only — no real network "
              f"activity was performed.)", "success")
        return redirect(url_for("dashboard_home"))

    # -- Alerts ---------------------------------------------------------------
    @app.route("/alerts")
    @login_required
    def alerts_list():
        severity = request.args.get("severity") or None
        status = request.args.get("status") or None
        q = request.args.get("q") or None
        page = int(request.args.get("page", 1))
        total = db.count_alerts(g.db, severity=severity, status=status, keyword=q)
        page_info = paginate(total, page, config.PAGE_SIZE_DEFAULT)
        rows = db.query_alerts(g.db, severity=severity, status=status, keyword=q,
                                limit=config.PAGE_SIZE_DEFAULT, offset=page_info["offset"])
        return render_template("alerts.html", alerts=rows, page_info=page_info,
                                severity=severity or "", status=status or "", q=q or "",
                                statuses=ALERT_STATUSES)

    @app.route("/alerts/<int:alert_id>")
    @login_required
    def alert_detail(alert_id):
        alert = db.get_alert(g.db, alert_id)
        if not alert:
            abort(404)
        event_ids = db.get_alert_event_ids(g.db, alert_id)
        events = db.get_events_by_ids(g.db, event_ids)
        ti = threat_intel.lookup_ip(g.db, alert["source_ip"]) if alert["source_ip"] else None
        incident = db.get_incident(g.db, alert["incident_id"]) if alert["incident_id"] else None
        remediation_hints = dict(reports.REMEDIATION_SUGGESTIONS, _default=reports.DEFAULT_REMEDIATION)
        return render_template("alert_detail.html", alert=alert, events=events, threat_intel=ti,
                                incident=incident, statuses=ALERT_STATUSES, remediation_hints=remediation_hints)

    @app.route("/alerts/<int:alert_id>/status", methods=["POST"])
    @login_required
    def alert_update_status(alert_id):
        status = request.form.get("status")
        if status not in ALERT_STATUSES:
            abort(400)
        db.update_alert_status(g.db, alert_id, status)
        flash(f"Alert #{alert_id} marked {status}.", "success")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.route("/alerts/<int:alert_id>/create-incident", methods=["POST"])
    @login_required
    def alert_create_incident(alert_id):
        user = current_user()
        incident_id = incidents_module.create_incident_from_alert(
            g.db, alert_id, assigned_to=user["username"] if user else None
        )
        flash(f"Incident #{incident_id} created from alert #{alert_id}.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    # -- Incidents --------------------------------------------------------
    @app.route("/incidents")
    @login_required
    def incidents_list():
        status = request.args.get("status") or None
        severity = request.args.get("severity") or None
        page = int(request.args.get("page", 1))
        total = db.count_incidents(g.db, status=status, severity=severity)
        page_info = paginate(total, page, config.PAGE_SIZE_DEFAULT)
        rows = db.query_incidents(g.db, status=status, severity=severity,
                                   limit=config.PAGE_SIZE_DEFAULT, offset=page_info["offset"])
        return render_template("incidents.html", incidents=rows, page_info=page_info,
                                status=status or "", severity=severity or "",
                                statuses=incidents_module.VALID_STATUSES)

    @app.route("/incidents/new", methods=["GET", "POST"])
    @login_required
    def incident_new():
        alert_id = request.args.get("alert_id", type=int)
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            severity = request.form.get("severity", "MEDIUM")
            if not title:
                flash("Title is required.", "error")
                return render_template("incident_new.html")
            user = current_user()
            incident_id = incidents_module.create_manual_incident(
                g.db, title, description, severity, assigned_to=user["username"] if user else None,
            )
            flash(f"Incident #{incident_id} created.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        return render_template("incident_new.html", alert_id=alert_id)

    @app.route("/incidents/<int:incident_id>")
    @login_required
    def incident_detail(incident_id):
        incident = incidents_module.get_full_incident(g.db, incident_id)
        if not incident:
            abort(404)
        return render_template("incident_detail.html", incident=incident,
                                statuses=incidents_module.VALID_STATUSES)

    @app.route("/incidents/<int:incident_id>/notes", methods=["POST"])
    @login_required
    def incident_add_note(incident_id):
        note = request.form.get("note", "").strip()
        user = current_user()
        if note:
            incidents_module.add_note(g.db, incident_id, user["username"] if user else "analyst", note)
            flash("Note added.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.route("/incidents/<int:incident_id>/status", methods=["POST"])
    @login_required
    def incident_update_status(incident_id):
        status = request.form.get("status")
        resolution = request.form.get("resolution", "").strip() or None
        if status not in incidents_module.VALID_STATUSES:
            abort(400)
        user = current_user()
        incidents_module.update_status(g.db, incident_id, status, resolution=resolution,
                                        author=user["username"] if user else "analyst")
        flash(f"Incident #{incident_id} status changed to {status}.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.route("/incidents/<int:incident_id>/link-alert", methods=["POST"])
    @login_required
    def incident_link_alert(incident_id):
        alert_id = request.form.get("alert_id", type=int)
        if alert_id:
            incidents_module.link_alert(g.db, incident_id, alert_id)
            flash(f"Alert #{alert_id} linked.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    # -- Investigate ----------------------------------------------------------
    @app.route("/investigate")
    @login_required
    def investigate():
        query = request.args.get("q", "").strip()
        result = None
        if query:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
                ti = threat_intel.lookup_ip(g.db, query)
                events = db.query_events(g.db, source_ip=query, limit=300)
                related_alerts = db.query_alerts(g.db, source_ip=query, limit=50)
                timestamps = [e["timestamp"] for e in events]
                result = {
                    "kind": "ip", "ip": query, "threat_intel": ti, "events": events, "alerts": related_alerts,
                    "first_seen": min(timestamps) if timestamps else None,
                    "last_seen": max(timestamps) if timestamps else None,
                    "distinct_users": sorted({e["user"] for e in events if e["user"]}),
                    "distinct_hosts": sorted({e["host"] for e in events if e["host"]}),
                    "risk_score": _compute_risk_score(ti, related_alerts),
                }
            else:
                result = {"kind": "domain", **threat_intel.investigate_domain(g.db, query)}
        return render_template("investigate.html", query=query, result=result)

    # -- Search -----------------------------------------------------------
    @app.route("/search")
    @login_required
    def search_page():
        filters = dict(
            source_ip=request.args.get("ip") or None, user=request.args.get("user") or None,
            host=request.args.get("host") or None, event_type=request.args.get("type") or None,
            keyword=request.args.get("q") or None,
        )
        page = int(request.args.get("page", 1))
        results, page_info = search.search_events(g.db, page=page, page_size=config.PAGE_SIZE_DEFAULT, **filters)
        return render_template("search.html", results=results, page_info=page_info,
                                filters={k: (v or "") for k, v in filters.items()},
                                event_types=search.distinct_event_types(g.db), hosts=search.distinct_hosts(g.db))

    # -- Reports ------------------------------------------------------------
    @app.route("/reports")
    @login_required
    def reports_list():
        reports_dir = Path(config.REPORTS_DIR)
        files = sorted(reports_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True) if reports_dir.exists() else []
        all_incidents = db.query_incidents(g.db, limit=200)
        return render_template("reports.html", files=files, incidents=all_incidents)

    @app.route("/reports/incident/<int:incident_id>/view")
    @login_required
    def report_incident_view(incident_id):
        data = reports.build_incident_report_data(g.db, incident_id)
        if not data:
            abort(404)
        return reports.render_html(data)

    @app.route("/reports/incident/<int:incident_id>/generate", methods=["POST"])
    @login_required
    def report_incident_generate(incident_id):
        paths = reports.generate_incident_report(g.db, incident_id)
        if not paths:
            abort(404)
        flash(f"Report generated for incident #{incident_id} ({', '.join(paths)}).", "success")
        return redirect(url_for("reports_list"))

    @app.route("/reports/summary", methods=["POST"])
    @login_required
    def report_summary_generate():
        days = request.form.get("days", 7, type=int)
        since, until = to_iso(now_utc() - timedelta(days=days)), now_iso()
        path = reports.generate_soc_summary(g.db, since, until)
        flash(f"SOC summary report generated: {Path(path).name}", "success")
        return redirect(url_for("reports_list"))

    @app.route("/reports/download/<path:filename>")
    @login_required
    def report_download(filename):
        safe_dir = Path(config.REPORTS_DIR).resolve()
        target = (safe_dir / filename).resolve()
        if safe_dir not in target.parents or not target.exists():
            abort(404)
        return send_file(target, as_attachment=True)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, debug=True)
