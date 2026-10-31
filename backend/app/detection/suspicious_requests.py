"""Detect common SQL injection strings in synthetic web request paths."""

import re
from typing import Any, Iterable
from urllib.parse import unquote_plus


SQL_INJECTION_PATTERNS = {
    "union_select": re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    "boolean_condition": re.compile(r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
}


def detect_sql_injection(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return findings when a request path contains a known SQLi pattern.

    This is a teaching rule for obvious examples. It is not a replacement for
    validation, parameterized queries, or a production web application firewall.
    """
    findings = []
    for event in events:
        if event.get("event_type") != "web_request":
            continue

        decoded_path = unquote_plus(event["path"])
        matched_patterns = [
            name for name, pattern in SQL_INJECTION_PATTERNS.items()
            if pattern.search(decoded_path)
        ]
        if not matched_patterns:
            continue

        findings.append(
            {
                "rule": "sql_injection_pattern",
                "title": "Possible SQL injection request",
                "source_ip": event["source_ip"],
                "method": event["method"],
                "path": event["path"],
                "status_code": event["status_code"],
                "matched_patterns": matched_patterns,
                "timestamp": event["timestamp"],
            }
        )

    return findings
