"""Assign triage severity based on attack type, impact, and blast radius."""


def severity_for_finding(finding: dict) -> str:
    """Assign standardized SOC severity: critical, high, medium, low.

    Follows NIST SP 800-61 incident severity guidelines.
    """
    rule = finding.get("rule", "")

    # Critical severity: remote code execution indicators
    if rule == "command_injection_pattern":
        return "critical"

    # High severity: credential spraying or potential data breach
    if rule == "password_spraying":
        return "high"

    if rule == "sql_injection_pattern":
        # If the web app returned 200 OK to a SQL injection payload, higher risk of breach
        if finding.get("status_code") == 200:
            return "high"
        return "medium"

    if rule == "path_traversal_pattern":
        if finding.get("status_code") == 200:
            return "high"
        return "medium"

    if rule == "repeated_failed_logins":
        attempts = finding.get("failed_attempts", 0)
        if attempts >= 10:
            return "high"
        if attempts >= 5:
            return "medium"
        return "low"

    if rule == "security_scanner_recon":
        return "low"

    return "medium"
