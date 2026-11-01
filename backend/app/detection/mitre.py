"""MITRE ATT&CK Framework taxonomy and mapping helpers.

Maps security detection rules to standardized MITRE ATT&CK tactics, techniques,
and sub-techniques for enterprise security operations.
"""

from typing import Any


MITRE_TACTICS = {
    "credential_access": {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "Techniques used by adversaries to steal credentials like account names and passwords.",
    },
    "initial_access": {
        "id": "TA0001",
        "name": "Initial Access",
        "description": "Techniques that use various entry vectors to gain an initial foothold within a network.",
    },
    "discovery": {
        "id": "TA0007",
        "name": "Discovery",
        "description": "Techniques an adversary may use to gain knowledge about the system and internal network.",
    },
    "execution": {
        "id": "TA0002",
        "name": "Execution",
        "description": "Techniques that result in adversary-controlled code running on a local or remote system.",
    },
    "defense_evasion": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "Techniques an adversary uses to avoid detection throughout their compromise.",
    },
}

MITRE_TECHNIQUES = {
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "credential_access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries may systematically guess passwords to attempt to log in to target accounts.",
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "credential_access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to avoid account lockouts.",
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "initial_access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries may exploit vulnerabilities such as SQL injection in Internet-facing applications.",
    },
    "T1083": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "description": "Adversaries may enumerate files and directories or use path traversal patterns to access sensitive files.",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands.",
    },
    "T1595.002": {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "discovery",
        "url": "https://attack.mitre.org/techniques/T1595/002/",
        "description": "Adversaries may execute automated vulnerability or directory scanners against public applications.",
    },
}

RULE_MITRE_MAP: dict[str, str] = {
    "repeated_failed_logins": "T1110.001",
    "password_spraying": "T1110.003",
    "sql_injection_pattern": "T1190",
    "path_traversal_pattern": "T1083",
    "command_injection_pattern": "T1059",
    "security_scanner_recon": "T1595.002",
}


def get_mitre_metadata(rule_id: str) -> dict[str, Any]:
    """Retrieve structured MITRE ATT&CK taxonomy details for a detection rule."""
    technique_id = RULE_MITRE_MAP.get(rule_id)
    if not technique_id:
        return {
            "tactic": "Unknown",
            "tactic_id": "N/A",
            "technique_id": "N/A",
            "technique_name": "Custom Rule",
            "url": "https://attack.mitre.org/",
        }

    technique = MITRE_TECHNIQUES[technique_id]
    tactic_key = technique["tactic"]
    tactic = MITRE_TACTICS.get(tactic_key, {"name": tactic_key.replace("_", " ").title(), "id": "N/A"})

    return {
        "tactic": tactic["name"],
        "tactic_id": tactic["id"],
        "technique_id": technique["id"],
        "technique_name": technique["name"],
        "url": technique["url"],
    }

