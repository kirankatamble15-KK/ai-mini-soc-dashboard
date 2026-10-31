"""Parse and validate one JSON Lines authentication or web event."""

import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any


COMMON_FIELDS = {"timestamp", "event_type", "source_ip"}
EVENT_FIELDS = {
    "login": {"username", "success"},
    "web_request": {"method", "path", "status_code"},
}


def parse_log_line(line: str) -> dict[str, Any]:
    """Convert one JSON log line into a validated event dictionary."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON log entry: {exc.msg}") from exc

    if not isinstance(event, dict):
        raise ValueError("A log entry must be a JSON object")

    event_type = event.get("event_type")
    if event_type not in EVENT_FIELDS:
        raise ValueError("event_type must be 'login' or 'web_request'")

    required_fields = COMMON_FIELDS | EVENT_FIELDS[event_type]
    missing = required_fields - event.keys()
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

    event["timestamp"] = timestamp.isoformat()
    event["source_ip"] = source_ip

    if event_type == "login":
        if not isinstance(event["success"], bool):
            raise ValueError("success must be true or false")
        if not isinstance(event["username"], str) or not event["username"].strip():
            raise ValueError("username must be a non-empty string")
        event["username"] = event["username"].strip()
    else:
        if not isinstance(event["method"], str) or not event["method"].isalpha():
            raise ValueError("method must contain letters only")
        if not isinstance(event["path"], str) or not event["path"].startswith("/"):
            raise ValueError("path must be a URL path starting with '/'")
        if isinstance(event["status_code"], bool) or not isinstance(event["status_code"], int):
            raise ValueError("status_code must be an integer")
        if not 100 <= event["status_code"] <= 599:
            raise ValueError("status_code must be between 100 and 599")
        event["method"] = event["method"].upper()

    return event
