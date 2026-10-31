"""Map detection findings to a simple severity label."""


def severity_for_finding(finding: dict) -> str:
    """Assign a starter severity based on the type and size of a finding."""
    if finding.get("rule") == "sql_injection_pattern":
        return "medium"

    attempts = finding.get("failed_attempts", 0)
    if attempts >= 10:
        return "high"
    if attempts >= 5:
        return "medium"
    return "low"
