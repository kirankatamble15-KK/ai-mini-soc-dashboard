"""Coordinate and execute rule-based and ML detection engines across an event batch."""

from typing import Any, Iterable

from app.detection.brute_force import detect_brute_force, detect_password_spraying
from app.detection.suspicious_requests import (
    detect_command_injection,
    detect_path_traversal,
    detect_security_scanners,
    detect_sql_injection,
)
from app.ml.anomaly_detector import get_anomaly_detector


def analyze_events(
    events: Iterable[dict[str, Any]],
    enable_ml: bool = True,
) -> list[dict[str, Any]]:
    """Run signature rules and ML anomaly detection against an ingested batch of events."""
    event_batch = list(events)
    findings: list[dict[str, Any]] = []

    # Credential access detection (Authentication events)
    findings.extend(detect_brute_force(event_batch))
    findings.extend(detect_password_spraying(event_batch))

    # Web application attack detection (Web request events)
    findings.extend(detect_sql_injection(event_batch))
    findings.extend(detect_path_traversal(event_batch))
    findings.extend(detect_command_injection(event_batch))
    findings.extend(detect_security_scanners(event_batch))

    # Machine learning behavioral anomaly detection (Isolation Forest)
    if enable_ml and event_batch:
        try:
            detector = get_anomaly_detector()
            ml_anomalies = detector.predict_anomalies(event_batch)
            findings.extend(ml_anomalies)
        except Exception:
            # Fall back gracefully so rule-based engine operates even if model fails
            pass

    return findings
