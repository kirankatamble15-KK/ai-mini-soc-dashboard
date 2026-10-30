"""Convert detection findings into dashboard-ready alert records."""

from uuid import uuid4

from app.alerts.severity import severity_for_finding


def create_alerts(findings: list[dict]) -> list[dict]:
    """Build alert records from findings; these are not persisted yet."""
    alerts = []
    for finding in findings:
        alerts.append(
            {
                "id": str(uuid4()),
                "title": finding["title"],
                "severity": severity_for_finding(finding),
                "status": "open",
                "source_ip": finding["source_ip"],
                "failed_attempts": finding["failed_attempts"],
                "usernames": finding["usernames"],
                "first_seen": finding["first_seen"],
                "last_seen": finding["last_seen"],
                "rule": finding["rule"],
            }
        )
    return alerts
