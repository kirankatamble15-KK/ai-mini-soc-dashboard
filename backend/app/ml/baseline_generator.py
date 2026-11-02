"""Generate synthetic normal baseline security logs for ML model training.

Simulates enterprise daytime operations, standard URI accesses, and high-success
authentication rates to train the Isolation Forest baseline.
"""

from datetime import datetime, timedelta
import random
from typing import Any


NORMAL_USERS = ["alice", "bob", "carol", "dan", "erin", "frank", "grace", "heidi"]
NORMAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.1.45", "10.0.2.110",
    "192.168.1.101", "192.168.1.105", "192.168.1.140",
]
NORMAL_PATHS = [
    "/",
    "/dashboard",
    "/api/v1/products",
    "/api/v1/orders",
    "/search?q=laptops",
    "/profile/settings",
    "/static/bundle.js",
    "/static/theme.css",
    "/help/faq",
    "/docs/overview",
]


def generate_baseline_dataset(sample_count: int = 500) -> list[dict[str, Any]]:
    """Create a diverse baseline of normal corporate user and web activity."""
    random.seed(42)  # Deterministic generation
    events: list[dict[str, Any]] = []
    base_time = datetime(2026, 10, 20, 9, 0, 0)

    for i in range(sample_count):
        # Normal business hours: 08:30 to 18:30 with occasional late evening
        hour_offset = random.choices([9, 10, 11, 13, 14, 15, 16, 17, 19], weights=[10, 12, 12, 15, 15, 12, 10, 8, 3])[0]
        minute_offset = random.randint(0, 59)
        second_offset = random.randint(0, 59)
        day_offset = random.randint(0, 5)

        event_time = (base_time + timedelta(days=day_offset, hours=hour_offset, minutes=minute_offset, seconds=second_offset)).isoformat() + "Z"
        source_ip = random.choice(NORMAL_IPS)

        if random.random() < 0.35:
            # Normal login event (98% success rate)
            success = random.random() < 0.98
            events.append({
                "timestamp": event_time,
                "event_type": "login",
                "username": random.choice(NORMAL_USERS),
                "source_ip": source_ip,
                "success": success,
            })
        else:
            # Normal web request (97% 200/304 OK, standard path)
            status_code = random.choices([200, 304, 204, 404], weights=[90, 6, 2, 2])[0]
            events.append({
                "timestamp": event_time,
                "event_type": "web_request",
                "source_ip": source_ip,
                "method": "GET" if random.random() < 0.85 else "POST",
                "path": random.choice(NORMAL_PATHS),
                "status_code": status_code,
            })

    # Chronologically sort the baseline
    events.sort(key=lambda e: e["timestamp"])
    return events

