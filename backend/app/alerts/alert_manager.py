"""Convert detection findings into dashboard-ready alert records with MITRE ATT&CK taxonomy."""

from uuid import uuid4

from app.alerts.severity import severity_for_finding
from app.detection.mitre import get_mitre_metadata


def create_alerts(findings: list[dict]) -> list[dict]:
    """Build standardized alert records enriched with MITRE ATT&CK metadata."""
    alerts = []
    for finding in findings:
        is_login_burst = "failed_attempts" in finding
        evidence_fields = ("method", "path", "status_code", "matched_patterns")
        mitre_data = finding.get("mitre") or get_mitre_metadata(finding.get("rule", ""))

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
                "mitre_tactic": mitre_data.get("tactic", "Unknown"),
                "mitre_technique_id": mitre_data.get("technique_id", "N/A"),
                "mitre_technique_name": mitre_data.get("technique_name", "N/A"),
                "mitre_url": mitre_data.get("url", ""),
            }
        )
    return alerts
