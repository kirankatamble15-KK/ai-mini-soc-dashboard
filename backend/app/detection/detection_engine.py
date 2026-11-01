"""Coordinate and execute detection rules across an event batch."""

from typing import Any, Iterable

from app.detection.brute_force import detect_brute_force, detect_password_spraying
from app.detection.suspicious_requests import (
    detect_command_injection,
    detect_path_traversal,
    detect_security_scanners,
    detect_sql_injection,
)


def analyze_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run all detection rules against an ingested batch of events."""
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

    return findings
