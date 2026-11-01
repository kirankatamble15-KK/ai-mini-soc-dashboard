"""Detect web application attack patterns and reconnaissance in HTTP request logs.

Covers:
- SQL Injection (MITRE T1190)
- Path / Directory Traversal (MITRE T1083)
- Command Injection (MITRE T1059)
- Vulnerability Scanner Reconnaissance (MITRE T1595.002)
"""

import re
from typing import Any, Iterable
from urllib.parse import unquote_plus

from app.detection.mitre import get_mitre_metadata


SQL_INJECTION_PATTERNS = {
    "union_select": re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    "boolean_condition": re.compile(r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+", re.IGNORECASE),
    "stacked_queries": re.compile(r";\s*(?:select|insert|update|delete|drop|alter)\b", re.IGNORECASE),
    "time_based_sleep": re.compile(r"\b(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", re.IGNORECASE),
}

PATH_TRAVERSAL_PATTERNS = {
    "dot_dot_slash": re.compile(r"(?:\.\.[/\\])+", re.IGNORECASE),
    "etc_passwd": re.compile(r"\b(?:etc[/\\]passwd|etc[/\\]shadow)\b", re.IGNORECASE),
    "win_system_file": re.compile(r"\b(?:windows[/\\]system32|win\.ini|boot\.ini)\b", re.IGNORECASE),
}

COMMAND_INJECTION_PATTERNS = {
    "command_chaining": re.compile(
        r"(?:;|\||`|&&|\$\()\s*(?:cat|whoami|id|uname|nc|netsh|powershell|cmd\.exe|curl|wget)\b",
        re.IGNORECASE,
    ),
}

KNOWN_SECURITY_SCANNERS = re.compile(
    r"\b(sqlmap|nikto|gobuster|dirbuster|nmap|masscan|wpscan|acunetix|nessus|openvas|hydra|zgrab)\b",
    re.IGNORECASE,
)


def detect_sql_injection(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect SQL Injection patterns in request path or parameters (MITRE T1190)."""
    findings = []
    for event in events:
        if event.get("event_type") != "web_request":
            continue

        raw_path = event.get("path", "")
        decoded_path = unquote_plus(raw_path)
        matched_patterns = [
            name
            for name, pattern in SQL_INJECTION_PATTERNS.items()
            if pattern.search(decoded_path)
        ]
        if not matched_patterns:
            continue

        findings.append(
            {
                "rule": "sql_injection_pattern",
                "title": "SQL Injection Attack Attempt",
                "source_ip": event["source_ip"],
                "method": event["method"],
                "path": event["path"],
                "status_code": event["status_code"],
                "matched_patterns": matched_patterns,
                "timestamp": event["timestamp"],
                "mitre": get_mitre_metadata("sql_injection_pattern"),
            }
        )
    return findings


def detect_path_traversal(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect directory and path traversal patterns in web requests (MITRE T1083)."""
    findings = []
    for event in events:
        if event.get("event_type") != "web_request":
            continue

        raw_path = event.get("path", "")
        decoded_path = unquote_plus(raw_path)
        matched_patterns = [
            name
            for name, pattern in PATH_TRAVERSAL_PATTERNS.items()
            if pattern.search(decoded_path)
        ]
        if not matched_patterns:
            continue

        findings.append(
            {
                "rule": "path_traversal_pattern",
                "title": "Path Traversal / Arbitrary File Read Attempt",
                "source_ip": event["source_ip"],
                "method": event["method"],
                "path": event["path"],
                "status_code": event["status_code"],
                "matched_patterns": matched_patterns,
                "timestamp": event["timestamp"],
                "mitre": get_mitre_metadata("path_traversal_pattern"),
            }
        )
    return findings


def detect_command_injection(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect remote OS command injection syntax in request paths (MITRE T1059)."""
    findings = []
    for event in events:
        if event.get("event_type") != "web_request":
            continue

        raw_path = event.get("path", "")
        decoded_path = unquote_plus(raw_path)
        matched_patterns = [
            name
            for name, pattern in COMMAND_INJECTION_PATTERNS.items()
            if pattern.search(decoded_path)
        ]
        if not matched_patterns:
            continue

        findings.append(
            {
                "rule": "command_injection_pattern",
                "title": "Remote Command Injection Attempt",
                "source_ip": event["source_ip"],
                "method": event["method"],
                "path": event["path"],
                "status_code": event["status_code"],
                "matched_patterns": matched_patterns,
                "timestamp": event["timestamp"],
                "mitre": get_mitre_metadata("command_injection_pattern"),
            }
        )
    return findings


def detect_security_scanners(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect automated offensive vulnerability and directory scanners (MITRE T1595.002)."""
    findings = []
    for event in events:
        if event.get("event_type") != "web_request":
            continue

        # Check user_agent header if present or path parameters
        user_agent = event.get("user_agent", "")
        raw_path = event.get("path", "")
        target_str = f"{user_agent} {raw_path}"

        match = KNOWN_SECURITY_SCANNERS.search(target_str)
        if match:
            scanner_name = match.group(1).lower()
            findings.append(
                {
                    "rule": "security_scanner_recon",
                    "title": f"Automated Scanner Reconnaissance ({scanner_name})",
                    "source_ip": event["source_ip"],
                    "method": event["method"],
                    "path": event["path"],
                    "status_code": event["status_code"],
                    "matched_patterns": [scanner_name],
                    "timestamp": event["timestamp"],
                    "mitre": get_mitre_metadata("security_scanner_recon"),
                }
            )
    return findings
