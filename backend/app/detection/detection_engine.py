"""Coordinate the currently implemented detection rules."""

from typing import Any, Iterable

from app.detection.brute_force import detect_brute_force
from app.detection.suspicious_requests import detect_sql_injection


def analyze_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run each detection rule against one batch of parsed events."""
    event_batch = list(events)
    return detect_brute_force(event_batch) + detect_sql_injection(event_batch)
