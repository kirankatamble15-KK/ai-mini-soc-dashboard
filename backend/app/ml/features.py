"""Feature engineering pipeline for ML threat anomaly detection.

Extracts numerical feature vectors from raw normalized security events to model
baseline user and network behavior.
"""

from datetime import datetime
from typing import Any
import numpy as np


FEATURE_NAMES = [
    "hour_normalized",          # Time of day (0.0 to 1.0)
    "is_off_hours",             # 1.0 if event occurred between 22:00 and 06:00
    "is_failure_or_error",      # 1.0 if failed login or HTTP >= 400
    "payload_length",           # Length of path or username (scaled)
    "endpoint_depth",           # Count of path segments '/'
    "suspicious_char_ratio",    # Frequency of shell/SQL symbols in payload
    "ip_burst_velocity",        # Event frequency from this source IP in 5m window
]


def _parse_timestamp(ts: str) -> datetime:
    """Safely parse ISO 8601 string timestamp."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def compute_ip_velocities(events: list[dict[str, Any]], window_seconds: int = 300) -> list[int]:
    """Compute how many events occurred from the same source IP within a sliding 5m window."""
    velocities = []
    # Pre-parse timestamps
    parsed_events = []
    for e in events:
        try:
            parsed_events.append((_parse_timestamp(e["timestamp"]), e.get("source_ip", "")))
        except Exception:
            parsed_events.append((datetime.now(), e.get("source_ip", "")))

    for i, (current_time, source_ip) in enumerate(parsed_events):
        burst_count = 1
        # Look backwards in time up to window_seconds
        for j in range(i - 1, -1, -1):
            prev_time, prev_ip = parsed_events[j]
            time_diff = (current_time - prev_time).total_seconds()
            if time_diff > window_seconds:
                break
            if prev_ip == source_ip:
                burst_count += 1
        velocities.append(burst_count)
    return velocities


def extract_features_from_event(
    event: dict[str, Any],
    burst_velocity: int = 1,
) -> np.ndarray:
    """Transform a single security event into a standardized numerical feature vector."""
    try:
        dt = _parse_timestamp(event.get("timestamp", ""))
        hour = dt.hour + (dt.minute / 60.0)
    except Exception:
        hour = 12.0

    hour_normalized = hour / 24.0
    is_off_hours = 1.0 if (hour < 6.0 or hour >= 22.0) else 0.0

    event_type = event.get("event_type", "unknown")
    if event_type == "login":
        is_failure_or_error = 1.0 if event.get("success") is False else 0.0
        payload = event.get("username", "")
        endpoint_depth = 0.0
    else:
        status = event.get("status_code", 200)
        is_failure_or_error = 1.0 if status >= 400 else 0.0
        payload = event.get("path", "")
        endpoint_depth = float(payload.count("/"))

    payload_length = min(float(len(payload)) / 100.0, 5.0)  # capped scaling

    # Frequency of special characters indicative of injection / path traversal
    suspicious_chars = set("'\"`;<>()\\|{}[]$%&")
    if payload:
        suspicious_count = sum(1 for c in payload if c in suspicious_chars)
        suspicious_char_ratio = suspicious_count / len(payload)
    else:
        suspicious_char_ratio = 0.0

    # Scaled burst velocity
    velocity_scaled = min(float(burst_velocity) / 20.0, 5.0)

    return np.array([
        hour_normalized,
        is_off_hours,
        is_failure_or_error,
        payload_length,
        endpoint_depth,
        suspicious_char_ratio,
        velocity_scaled,
    ], dtype=np.float32)


def extract_dataset_features(events: list[dict[str, Any]]) -> np.ndarray:
    """Extract a 2D feature matrix (N samples x M features) from an event collection."""
    if not events:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)

    velocities = compute_ip_velocities(events)
    matrix = [
        extract_features_from_event(event, velocities[idx])
        for idx, event in enumerate(events)
    ]
    return np.array(matrix, dtype=np.float32)
