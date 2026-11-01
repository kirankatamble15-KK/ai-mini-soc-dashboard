"""Security detection and SOC operation API routes."""

from collections import Counter
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from app.alerts.alert_manager import create_alerts
from app.database.connection import (
    count_events,
    list_alerts,
    list_events,
    save_alerts,
    save_events,
    update_alert_status,
)
from app.detection.detection_engine import analyze_events
from app.ingestion.log_parser import parse_log_line
from app.ingestion.log_reader import read_log_file


detection_api = Blueprint("detection_api", __name__)
ALERT_STATUSES = {"open", "acknowledged", "resolved"}


@detection_api.get("/api/demo/analysis")
def analyze_sample_log():
    """Parse the sample authentication log and return findings."""
    project_root = Path(__file__).resolve().parents[3]
    sample_path = project_root / "data" / "samples" / "auth.log"
    events = list(read_log_file(sample_path))
    findings = analyze_events(events)
    alerts = create_alerts(findings)
    return jsonify(
        event_count=len(events),
        alert_count=len(alerts),
        alerts=alerts,
    )


@detection_api.get("/api/demo/web-analysis")
def analyze_sample_web_log():
    """Parse synthetic web requests and report attack findings."""
    project_root = Path(__file__).resolve().parents[3]
    sample_path = project_root / "data" / "samples" / "access.log"
    events = list(read_log_file(sample_path))
    findings = analyze_events(events)
    return jsonify(event_count=len(events), finding_count=len(findings), findings=findings)


@detection_api.post("/api/demo/analyze")
def analyze_and_save_sample():
    """Analyze both bundled sample logs, persist raw events, and generate alerts."""
    project_root = Path(__file__).resolve().parents[3]
    samples_dir = project_root / "data" / "samples"
    events = list(read_log_file(samples_dir / "auth.log"))
    events.extend(read_log_file(samples_dir / "access.log"))

    db_path = current_app.config["DATABASE_PATH"]
    # Save raw events for SOC log explorer & drill-down investigation
    save_events(db_path, events)

    alerts = create_alerts(analyze_events(events))
    save_alerts(db_path, alerts)
    return jsonify(event_count=len(events), alert_count=len(alerts), alerts=alerts), 201


@detection_api.get("/api/alerts")
def get_alerts():
    """Return saved alerts from the local SQLite database."""
    alerts = list_alerts(current_app.config["DATABASE_PATH"])
    return jsonify(alert_count=len(alerts), alerts=alerts)


@detection_api.patch("/api/alerts/<alert_id>")
def change_alert_status(alert_id: str):
    """Change an alert's analyst workflow status."""
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(error="request body must be a JSON object"), 400
    status = payload.get("status")
    if status not in ALERT_STATUSES:
        return jsonify(
            error="status must be one of: open, acknowledged, resolved"
        ), 400

    found = update_alert_status(current_app.config["DATABASE_PATH"], alert_id, status)
    if not found:
        return jsonify(error="alert not found"), 404
    return jsonify(id=alert_id, status=status)


@detection_api.get("/api/logs")
def get_logs():
    """Retrieve ingested raw security events with filtering for the Log Explorer."""
    event_type = request.args.get("event_type")
    source_ip = request.args.get("source_ip")
    search = request.args.get("search")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))

    db_path = current_app.config["DATABASE_PATH"]
    events = list_events(
        db_path,
        event_type=event_type,
        source_ip=source_ip,
        search=search,
        limit=limit,
        offset=offset,
    )
    total = count_events(db_path)
    return jsonify(total=total, returned=len(events), events=events)


@detection_api.post("/api/logs/ingest")
def ingest_live_logs():
    """Ingest custom or streaming security log entries in JSON or JSON Lines format.

    Validates each line, saves raw logs to the database, runs detections, and persists
    any newly generated alerts.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify(error="Request body must be a JSON object or array of events"), 400

    raw_items = payload if isinstance(payload, list) else [payload]
    validated_events: list[dict[str, Any]] = []
    errors: list[str] = []

    for idx, item in enumerate(raw_items):
        try:
            if isinstance(item, str):
                event = parse_log_line(item)
            elif isinstance(item, dict):
                import json
                event = parse_log_line(json.dumps(item))
            else:
                errors.append(f"Item #{idx}: Expected string or object")
                continue
            validated_events.append(event)
        except Exception as exc:
            errors.append(f"Item #{idx}: {exc}")

    if not validated_events and errors:
        return jsonify(error="Validation failed", details=errors), 400

    db_path = current_app.config["DATABASE_PATH"]
    save_events(db_path, validated_events)

    findings = analyze_events(validated_events)
    alerts = create_alerts(findings)
    if alerts:
        save_alerts(db_path, alerts)

    return jsonify(
        ingested_count=len(validated_events),
        alerts_generated=len(alerts),
        alerts=alerts,
        errors=errors,
    ), 201


@detection_api.get("/api/stats")
def get_soc_metrics():
    """Return high-level SOC operations metrics and MITRE technique distribution."""
    db_path = current_app.config["DATABASE_PATH"]
    alerts = list_alerts(db_path)
    total_events = count_events(db_path)

    severities = Counter(a.get("severity", "low") for a in alerts)
    statuses = Counter(a.get("status", "open") for a in alerts)
    tactics = Counter(a.get("mitre_tactic", "Unknown") for a in alerts)
    techniques = Counter(a.get("mitre_technique_id", "N/A") for a in alerts)

    return jsonify(
        total_alerts=len(alerts),
        total_events=total_events,
        open_alerts=statuses.get("open", 0),
        high_or_critical=severities.get("high", 0) + severities.get("critical", 0),
        severities=dict(severities),
        statuses=dict(statuses),
        mitre_tactics=dict(tactics),
        mitre_techniques=dict(techniques),
    )
