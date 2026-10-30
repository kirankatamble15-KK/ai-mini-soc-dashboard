"""Parse and validate one JSON Lines authentication event."""

import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any


REQUIRED_FIELDS = {"timestamp", "event_type", "username", "source_ip", "success"}


def parse_log_line(line: str) -> dict[str, Any]:
    """Convert one JSON log line into a validated event dictionary."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON log entry: {exc.msg}") from exc

    if not isinstance(event, dict):
        raise ValueError("A log entry must be a JSON object")

    missing = REQUIRED_FIELDS - event.keys()
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(sorted(missing))}")

    try:
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("timestamp must be an ISO 8601 date and time") from exc

    try:
        source_ip = str(ip_address(event["source_ip"]))
    except ValueError as exc:
        raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc

    if not isinstance(event["success"], bool):
        raise ValueError("success must be true or false")
    if not isinstance(event["username"], str) or not event["username"].strip():
        raise ValueError("username must be a non-empty string")
    if event["event_type"] != "login":
        raise ValueError("event_type must be 'login'")

    event["timestamp"] = timestamp.isoformat()
    event["source_ip"] = source_ip
    event["username"] = event["username"].strip()
    return event
