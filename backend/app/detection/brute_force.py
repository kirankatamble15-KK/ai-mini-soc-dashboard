"""Detect repeated failed logins from a single source IP address."""

from collections import defaultdict
from typing import Any, Iterable


def detect_brute_force(
    events: Iterable[dict[str, Any]], threshold: int = 3
) -> list[dict[str, Any]]:
    """Return one finding per IP with at least ``threshold`` failed logins.

    The supplied events are treated as one analysis batch. Time-windowing is a
    later improvement; this first rule keeps the counting logic easy to follow.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failures_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("event_type") == "login" and event.get("success") is False:
            failures_by_ip[event["source_ip"]].append(event)

    findings = []
    for source_ip, failures in failures_by_ip.items():
        if len(failures) >= threshold:
            findings.append(
                {
                    "rule": "repeated_failed_logins",
                    "title": "Repeated failed logins",
                    "source_ip": source_ip,
                    "failed_attempts": len(failures),
                    "usernames": sorted({event["username"] for event in failures}),
                    "first_seen": min(event["timestamp"] for event in failures),
                    "last_seen": max(event["timestamp"] for event in failures),
                }
            )

    return findings
