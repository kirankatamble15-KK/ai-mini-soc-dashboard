"""Map detection findings to a simple severity label."""


def severity_for_finding(finding: dict) -> str:
    """Assign severity based on the number of failed login attempts."""
    attempts = finding.get("failed_attempts", 0)
    if attempts >= 10:
        return "high"
    if attempts >= 5:
        return "medium"
    return "low"
