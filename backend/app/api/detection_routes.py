"""API endpoint for analyzing the bundled synthetic log sample."""

from pathlib import Path

from flask import Blueprint, current_app, jsonify

from app.alerts.alert_manager import create_alerts
from app.database.connection import list_alerts, save_alerts
from app.detection.detection_engine import analyze_events
from app.ingestion.log_reader import read_log_file


detection_api = Blueprint("detection_api", __name__)


@detection_api.get("/api/demo/analysis")
def analyze_sample_log():
    """Parse the sample log and return any detection findings."""
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
    """Parse synthetic web requests and report SQL injection patterns."""
    project_root = Path(__file__).resolve().parents[3]
    sample_path = project_root / "data" / "samples" / "access.log"
    events = list(read_log_file(sample_path))
    findings = analyze_events(events)
    return jsonify(event_count=len(events), finding_count=len(findings), findings=findings)


@detection_api.post("/api/demo/analyze")
def analyze_and_save_sample():
    """Analyze both bundled sample logs and persist generated alerts."""
    project_root = Path(__file__).resolve().parents[3]
    samples_dir = project_root / "data" / "samples"
    events = list(read_log_file(samples_dir / "auth.log"))
    events.extend(read_log_file(samples_dir / "access.log"))
    alerts = create_alerts(analyze_events(events))
    save_alerts(current_app.config["DATABASE_PATH"], alerts)
    return jsonify(event_count=len(events), alert_count=len(alerts), alerts=alerts), 201


@detection_api.get("/api/alerts")
def get_alerts():
    """Return saved alerts from the local SQLite database."""
    alerts = list_alerts(current_app.config["DATABASE_PATH"])
    return jsonify(alert_count=len(alerts), alerts=alerts)
