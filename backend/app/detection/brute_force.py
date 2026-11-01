"""Detect repeated failed logins and password spraying attempts with sliding time-windows."""

from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable

from app.detection.mitre import get_mitre_metadata


def _parse_iso(timestamp: str) -> datetime:
    """Safely parse ISO 8601 timestamps with or without timezone."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def detect_brute_force(
    events: Iterable[dict[str, Any]],
    threshold: int = 3,
    window_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Detect high-frequency failed login attempts against accounts from a single IP.

    Uses a sliding time-window (default 5 minutes / 300s) to distinguish active
    brute force attacks (MITRE ATT&CK T1110.001) from sporadic user typos over days.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")

    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login" and event.get("success") is False:
            failures_by_ip[event["source_ip"]].append(event)

    findings: list[dict[str, Any]] = []

    for source_ip, ip_events in failures_by_ip.items():
        # Sort chronologically by timestamp
        sorted_events = sorted(ip_events, key=lambda e: _parse_iso(e["timestamp"]))
        
        # Sliding time-window grouping
        i = 0
        while i < len(sorted_events):
            start_time = _parse_iso(sorted_events[i]["timestamp"])
            window_events = [sorted_events[i]]

            j = i + 1
            while j < len(sorted_events):
                delta = (_parse_iso(sorted_events[j]["timestamp"]) - start_time).total_seconds()
                if delta <= window_seconds:
                    window_events.append(sorted_events[j])
                    j += 1
                else:
                    break

            if len(window_events) >= threshold:
                targeted_users = sorted({e["username"] for e in window_events})
                findings.append(
                    {
                        "rule": "repeated_failed_logins",
                        "title": "Repeated Failed Logins (Brute Force)",
                        "source_ip": source_ip,
                        "failed_attempts": len(window_events),
                        "usernames": targeted_users,
                        "first_seen": window_events[0]["timestamp"],
                        "last_seen": window_events[-1]["timestamp"],
                        "window_seconds": window_seconds,
                        "mitre": get_mitre_metadata("repeated_failed_logins"),
                    }
                )
                # Advance pointer past this burst to prevent duplicate overlapping alerts
                i = j
            else:
                i += 1

    return findings


def detect_password_spraying(
    events: Iterable[dict[str, Any]],
    unique_user_threshold: int = 3,
    window_seconds: int = 600,
) -> list[dict[str, Any]]:
    """Detect password spraying attacks (MITRE ATT&CK T1110.003).

    A password spray occurs when an attacker tests passwords across many different
    usernames from one IP, intentionally keeping attempts per user low to evade
    account lockouts.
    """
    if unique_user_threshold < 2:
        raise ValueError("unique_user_threshold must be at least 2")
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")

    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login" and event.get("success") is False:
            failures_by_ip[event["source_ip"]].append(event)

    findings: list[dict[str, Any]] = []

    for source_ip, ip_events in failures_by_ip.items():
        sorted_events = sorted(ip_events, key=lambda e: _parse_iso(e["timestamp"]))

        i = 0
        while i < len(sorted_events):
            start_time = _parse_iso(sorted_events[i]["timestamp"])
            window_events = [sorted_events[i]]

            j = i + 1
            while j < len(sorted_events):
                delta = (_parse_iso(sorted_events[j]["timestamp"]) - start_time).total_seconds()
                if delta <= window_seconds:
                    window_events.append(sorted_events[j])
                    j += 1
                else:
                    break

            targeted_users = sorted({e["username"] for e in window_events})
            if len(targeted_users) >= unique_user_threshold:
                findings.append(
                    {
                        "rule": "password_spraying",
                        "title": "Password Spraying Campaign",
                        "source_ip": source_ip,
                        "failed_attempts": len(window_events),
                        "usernames": targeted_users,
                        "first_seen": window_events[0]["timestamp"],
                        "last_seen": window_events[-1]["timestamp"],
                        "window_seconds": window_seconds,
                        "mitre": get_mitre_metadata("password_spraying"),
                    }
                )
                i = j
            else:
                i += 1

    return findings
