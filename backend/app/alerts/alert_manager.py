"""Convert detection findings into dashboard-ready alert records."""

from uuid import uuid4

from app.alerts.severity import severity_for_finding


def create_alerts(findings: list[dict]) -> list[dict]:
    """Build common alert records while retaining rule-specific evidence."""
    alerts = []
    for finding in findings:
        is_login_burst = "failed_attempts" in finding
        evidence_fields = ("method", "path", "status_code", "matched_patterns")
        alerts.append(
            {
                "id": str(uuid4()),
                "title": finding["title"],
                "severity": severity_for_finding(finding),
                "status": "open",
                "source_ip": finding["source_ip"],
                "failed_attempts": finding.get("failed_attempts", 0),
                "usernames": finding.get("usernames", []),
                "event_count": finding.get("failed_attempts", 1),
                "count_label": "failed logins" if is_login_burst else "requests",
                "details": {key: finding[key] for key in evidence_fields if key in finding},
                "first_seen": finding.get("first_seen") or finding.get("timestamp"),
                "last_seen": finding.get("last_seen") or finding.get("timestamp"),
                "rule": finding["rule"],
            }
        )
    return alerts
