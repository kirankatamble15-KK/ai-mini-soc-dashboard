"""
analyst.py — AI SOC Analyst Copilot (template-based, no paid API required)

Real-world concept: SOC Copilots (Splunk SOAR, Microsoft Sentinel Copilot) use LLMs
or rule-based engines to auto-generate incident context so analysts reduce MTTR.
This implementation uses a structured template engine keyed on MITRE technique IDs
and rule names — fully offline, deterministic, and portfolio-demonstrable.

Interview talking point:
  "I built a template-based copilot engine that maps MITRE ATT&CK technique IDs to
   structured incident narratives, kill-chain stage analysis, and concrete remediation
   playbooks — mimicking how enterprise SOAR platforms automate Level-1 triage."
"""

from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Kill-chain stage definitions (Lockheed Martin Cyber Kill Chain mapped to
# MITRE ATT&CK tactics)
# ---------------------------------------------------------------------------
KILL_CHAIN_STAGES = {
    "TA0043": ("Reconnaissance", "1 - Reconnaissance"),
    "TA0042": ("Resource Development", "2 - Weaponisation"),
    "TA0001": ("Initial Access", "3 - Delivery / Initial Access"),
    "TA0002": ("Execution", "4 - Exploitation"),
    "TA0003": ("Persistence", "5 - Installation / Persistence"),
    "TA0004": ("Privilege Escalation", "5 - Installation / Persistence"),
    "TA0005": ("Defense Evasion", "5 - Installation / Persistence"),
    "TA0006": ("Credential Access", "3 - Delivery / Initial Access"),
    "TA0007": ("Discovery", "3 - Delivery / Initial Access"),
    "TA0008": ("Lateral Movement", "6 - Command & Control"),
    "TA0009": ("Collection", "6 - Command & Control"),
    "TA0011": ("Command and Control", "6 - Command & Control"),
    "TA0010": ("Exfiltration", "7 - Actions on Objectives"),
    "TA0040": ("Impact", "7 - Actions on Objectives"),
}

# ---------------------------------------------------------------------------
# Per-rule template library
# Each entry has: executive, intent, remediation (list), ioc_fields
# ---------------------------------------------------------------------------
_TEMPLATES: dict[str, dict] = {
    "brute_force": {
        "executive": (
            "A brute-force credential attack was detected from {source_ip}. "
            "{count} failed authentication attempts were recorded within a short time window, "
            "indicating automated password guessing targeting the account '{user}'. "
            "Severity is assessed as {severity_upper}."
        ),
        "intent": (
            "The adversary is attempting to gain unauthorised access by exhausting "
            "password combinations against a single account (T1110.001 — Brute Force: "
            "Password Guessing). This is typically the first step in an account-takeover "
            "chain, after which the attacker may pivot to privilege escalation or "
            "lateral movement within the network."
        ),
        "kill_chain": "3 - Delivery / Initial Access",
        "remediation": [
            "# 1. Temporarily block the offending IP at the firewall",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 2. Lock the targeted account immediately",
            "sudo usermod -L {user}    # Linux",
            "# Windows: Disable-ADAccount -Identity {user}",
            "",
            "# 3. Review auth logs for the past 24 hours",
            "grep '{source_ip}' /var/log/auth.log | tail -50",
            "",
            "# 4. Enable account lockout policy (≥5 failures → 30 min lockout)",
            "# Linux PAM: edit /etc/pam.d/common-auth — add pam_faillock module",
            "# Windows GPO: Account Lockout Threshold = 5",
            "",
            "# 5. Alert the account owner and reset credentials if any success found",
            "grep -E 'Accepted|session opened' /var/log/auth.log | grep '{source_ip}'",
        ],
        "ioc_fields": ["source_ip", "user"],
    },

    "password_spray": {
        "executive": (
            "A password-spraying campaign was detected from {source_ip}. "
            "The source attempted authentication against {count} distinct user accounts "
            "using a low-and-slow pattern designed to evade per-account lockout policies. "
            "Severity: {severity_upper}."
        ),
        "intent": (
            "Password spraying (T1110.003) is an evasion-aware credential attack that "
            "tries one common password across many accounts rather than many passwords "
            "against one account. This bypasses lockout controls and is a hallmark of "
            "nation-state and APT intrusion sets. A single successful authentication "
            "during a spray campaign immediately enables lateral movement."
        ),
        "kill_chain": "3 - Delivery / Initial Access",
        "remediation": [
            "# 1. Block the spray source IP",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 2. Identify any successful logins from this IP",
            "grep 'Accepted' /var/log/auth.log | grep '{source_ip}'",
            "",
            "# 3. Force password reset for ALL targeted accounts",
            "# Windows: Get-ADUser -Filter * | where {{$_.LastBadPasswordAttempt -gt (Get-Date).AddHours(-1)}}",
            "",
            "# 4. Enable MFA immediately for all VPN and web-facing services",
            "",
            "# 5. Implement a per-IP connection rate limit",
            "sudo fail2ban-client set sshd banip {source_ip}",
            "",
            "# 6. Escalate to Tier-2 analyst — spray campaigns often precede APT intrusion",
        ],
        "ioc_fields": ["source_ip"],
    },

    "sql_injection": {
        "executive": (
            "A SQL injection attack was detected from {source_ip} targeting endpoint '{path}'. "
            "The HTTP response code {status_code} suggests the request may have {success_hint}. "
            "SQL injection enables direct database exfiltration and authentication bypass. "
            "Severity: {severity_upper}."
        ),
        "intent": (
            "SQL Injection (T1190 — Exploit Public-Facing Application) allows an attacker "
            "to manipulate database queries, potentially exposing all stored records, "
            "bypassing login authentication, or executing OS-level commands via "
            "xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL). A 200 OK response to a "
            "SQLi payload is a critical finding indicating likely successful exploitation."
        ),
        "kill_chain": "3 - Delivery / Initial Access",
        "remediation": [
            "# 1. Immediately block the attacker IP at WAF / firewall",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 2. Check if data was exfiltrated — review DB query logs",
            "# MySQL: tail -f /var/log/mysql/mysql.log | grep -i 'union\\|select\\|--'",
            "# PostgreSQL: tail /var/log/postgresql/postgresql-*.log",
            "",
            "# 3. Rotate all database credentials immediately",
            "# Update DB password and all app config files / secrets",
            "",
            "# 4. Audit the vulnerable endpoint and apply parameterised queries",
            "# Python SQLAlchemy: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "",
            "# 5. Enable ModSecurity WAF rules for SQLi (OWASP CRS)",
            "sudo a2enmod security2",
            "",
            "# 6. Notify DPO if PII or credentials may have been accessed (GDPR Art. 33)",
        ],
        "ioc_fields": ["source_ip", "path"],
    },

    "path_traversal": {
        "executive": (
            "A directory/path traversal attack was detected from {source_ip} targeting '{path}'. "
            "The attacker is attempting to read sensitive files outside the web root "
            "(e.g., /etc/passwd, /etc/shadow, application config files). "
            "Severity: {severity_upper}."
        ),
        "intent": (
            "Path Traversal (T1083 — File and Directory Discovery) exploits insufficient "
            "input sanitisation to navigate above the intended directory using '../' sequences. "
            "Successful exploitation can expose SSH private keys, database credentials in "
            "config files, and OS password hashes — all of which enable further compromise."
        ),
        "kill_chain": "3 - Delivery / Initial Access",
        "remediation": [
            "# 1. Block attacker IP",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 2. Determine which file was requested",
            "grep '{source_ip}' /var/log/nginx/access.log | grep '\\.\\.'",
            "",
            "# 3. Check if sensitive files were served (HTTP 200 response)",
            "# If /etc/passwd or SSH keys were accessed, treat as full compromise",
            "",
            "# 4. Fix the vulnerable code — use os.path.realpath() to canonicalise paths",
            "# Python: safe_path = os.path.realpath(os.path.join(base_dir, user_input))",
            "# if not safe_path.startswith(base_dir): raise PermissionError",
            "",
            "# 5. Configure web server to restrict file access",
            "# Nginx: add 'location ~* \\.\\. { deny all; }' block",
        ],
        "ioc_fields": ["source_ip", "path"],
    },

    "command_injection": {
        "executive": (
            "A command injection attack was CRITICALLY detected from {source_ip} targeting '{path}'. "
            "The payload contains OS command separators (;, &&, |, backtick) indicating the attacker "
            "is attempting to execute arbitrary operating system commands on the server. "
            "This is a CRITICAL severity finding — immediate containment required."
        ),
        "intent": (
            "Command Injection (T1059 — Command and Scripting Interpreter) allows an attacker "
            "to run arbitrary OS commands with the privilege of the web server process. "
            "Successful exploitation typically leads to: reverse shell establishment, "
            "credential harvesting, persistence mechanisms (cron jobs, SSH backdoors), "
            "and full system compromise. This is the highest-risk web vulnerability class."
        ),
        "kill_chain": "4 - Exploitation",
        "remediation": [
            "# ⚠️  CRITICAL — Execute containment steps in order within 15 minutes",
            "",
            "# 1. ISOLATE the server from the network immediately",
            "sudo iptables -I INPUT -j DROP",
            "sudo iptables -I OUTPUT -j DROP",
            "# (Keep a management console session open for recovery)",
            "",
            "# 2. Kill any unexpected child processes spawned by the web server",
            "sudo ps aux | grep -E 'bash|sh|nc|ncat|python' | grep -v grep",
            "# Kill suspicious PIDs: sudo kill -9 <PID>",
            "",
            "# 3. Check for new cron jobs or SSH keys (persistence indicators)",
            "sudo crontab -l -u www-data",
            "cat /home/*/.ssh/authorized_keys",
            "cat /root/.ssh/authorized_keys",
            "",
            "# 4. Preserve forensic evidence before remediation",
            "sudo dd if=/dev/sda of=/mnt/forensic/disk_image.img bs=4M",
            "sudo cp /var/log/auth.log /mnt/forensic/",
            "",
            "# 5. Block the attacker IP and rotate ALL credentials",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 6. Patch the vulnerable code — NEVER pass user input to shell",
            "# Python: use subprocess with list args, never shell=True",
            "# subprocess.run(['ping', user_input], shell=False)  # SAFE",
        ],
        "ioc_fields": ["source_ip", "path"],
    },

    "scanner_recon": {
        "executive": (
            "Web vulnerability scanner activity was detected from {source_ip}. "
            "The User-Agent or request pattern matches known security scanners (Nikto, DirBuster, "
            "Nmap NSE scripts, etc.), indicating active reconnaissance of the application. "
            "Severity: {severity_upper}."
        ),
        "intent": (
            "Active Scanning (T1595.002 — Vulnerability Scanning) is the reconnaissance "
            "phase of an attack lifecycle. Automated scanners enumerate endpoints, probe "
            "for CVEs, and fingerprint technology stacks to inform a targeted exploit. "
            "This activity typically precedes SQLi, command injection, or CVE exploitation "
            "attempts. Reconnaissance detection gives defenders early warning before impact."
        ),
        "kill_chain": "1 - Reconnaissance",
        "remediation": [
            "# 1. Block the scanning IP at the firewall",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 2. Review what endpoints the scanner discovered",
            "grep '{source_ip}' /var/log/nginx/access.log | awk '{print $7}' | sort -u",
            "",
            "# 3. Implement rate limiting to detect future scans",
            "# Nginx: limit_req_zone $binary_remote_addr zone=scan_limit:10m rate=10r/s;",
            "",
            "# 4. Deploy a honeypot endpoint to catch scanners early",
            "# Any request to /admin, /wp-admin, /.env → alert + auto-block",
            "",
            "# 5. Check if scanner found any valid 200 OK responses to sensitive paths",
            "grep '{source_ip}' /var/log/nginx/access.log | grep ' 200 '",
        ],
        "ioc_fields": ["source_ip"],
    },

    "ml_behavioral_anomaly": {
        "executive": (
            "The AI Isolation Forest anomaly detection model flagged unusual behaviour "
            "from {source_ip} with an anomaly confidence of {confidence}. "
            "The request did not match known attack signatures but deviates significantly "
            "from the established behavioural baseline. "
            "Key anomaly indicators: {anomaly_features}. "
            "Severity: {severity_upper}."
        ),
        "intent": (
            "This alert was generated by an unsupervised ML model (Isolation Forest) trained "
            "on normal corporate traffic patterns. Behavioural anomalies can indicate "
            "zero-day exploits, insider threats, or novel attack vectors that evade "
            "signature-based detection (T1027 — Obfuscated Files or Information). "
            "ML-detected anomalies require human analyst review to confirm or dismiss — "
            "they represent the frontier of threat detection where rules cannot yet reach."
        ),
        "kill_chain": "3 - Delivery / Initial Access",
        "remediation": [
            "# ML Anomaly — requires analyst judgement (not an automated block)",
            "",
            "# 1. Review the full request context in the Log Explorer",
            "# Filter by IP: {source_ip} — look for correlated events in the same time window",
            "",
            "# 2. Correlate with other alerts from same source IP",
            "grep '{source_ip}' /var/log/nginx/access.log | tail -20",
            "",
            "# 3. If anomaly is confirmed malicious, block at firewall",
            "sudo iptables -I INPUT -s {source_ip} -j DROP",
            "",
            "# 4. Add the confirmed pattern as a new detection rule",
            "# Document the attack vector and update detection_engine.py",
            "",
            "# 5. Retrain the ML model with the new labelled data point",
            "# POST /api/ml/train — incorporates latest traffic patterns",
            "",
            "# 6. If anomaly is benign, mark alert as False Positive for model feedback",
        ],
        "ioc_fields": ["source_ip"],
    },
}

# Default template for unknown rule types
_DEFAULT_TEMPLATE: dict = {
    "executive": (
        "A security alert was triggered from {source_ip} with rule '{rule}'. "
        "Severity: {severity_upper}. Please review the event details for context."
    ),
    "intent": (
        "This alert was generated by the detection engine. Review the associated "
        "log entries and MITRE ATT&CK mapping for further context on adversary intent."
    ),
    "kill_chain": "Unknown",
    "remediation": [
        "# 1. Review the alert details and associated log entries",
        "# 2. Correlate with other alerts from the same source IP",
        "grep '{source_ip}' /var/log/*.log",
        "# 3. Apply block if confirmed malicious",
        "sudo iptables -I INPUT -s {source_ip} -j DROP",
    ],
    "ioc_fields": ["source_ip"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_incident_analysis(alert: dict) -> dict:
    """
    Generate a structured AI incident analysis for a given alert dict.

    Args:
        alert: dict from list_alerts() / get_alert_by_id() — must contain at
               minimum: rule, source_ip, severity, details

    Returns:
        dict with keys: executive_summary, adversary_intent, kill_chain_stage,
                        remediation_playbook (list[str]), ioc_list (list[dict]),
                        confidence_note, generated_at
    """
    rule = (alert.get("rule") or "unknown").lower()
    source_ip = alert.get("source_ip") or "Unknown IP"
    severity = alert.get("severity") or "medium"
    details = alert.get("details") or {}
    mitre_technique_id = alert.get("mitre_technique_id") or ""
    mitre_tactic = alert.get("mitre_tactic") or ""
    mitre_technique_name = alert.get("mitre_technique_name") or "Unknown Technique"

    # Resolve template
    tmpl = _TEMPLATES.get(rule, _DEFAULT_TEMPLATE)

    # Build context for template formatting
    ctx = _build_context(alert, rule, source_ip, severity, details)

    # Render sections
    executive_summary = _render(tmpl["executive"], ctx)
    adversary_intent = _render(tmpl["intent"], ctx)
    kill_chain_stage = tmpl["kill_chain"]

    # Resolve kill chain from MITRE tactic if available
    if mitre_tactic and mitre_tactic in KILL_CHAIN_STAGES:
        kill_chain_stage = KILL_CHAIN_STAGES[mitre_tactic][1]

    # Remediation playbook
    remediation_playbook = [_render(line, ctx) for line in tmpl["remediation"]]

    # IOC list
    ioc_list = _extract_iocs(alert, details, tmpl["ioc_fields"])

    # Confidence note for ML alerts
    confidence_note = _build_confidence_note(rule, details)

    return {
        "executive_summary": executive_summary,
        "adversary_intent": adversary_intent,
        "kill_chain_stage": kill_chain_stage,
        "mitre_technique_id": mitre_technique_id,
        "mitre_technique_name": mitre_technique_name,
        "mitre_tactic": mitre_tactic,
        "remediation_playbook": remediation_playbook,
        "ioc_list": ioc_list,
        "confidence_note": confidence_note,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_context(alert: dict, rule: str, source_ip: str, severity: str, details: dict) -> dict:
    """Build a formatting context dict from alert fields."""
    # Extract common details fields safely
    user = details.get("user") or details.get("target_user") or "unknown"
    path = details.get("path") or details.get("endpoint") or details.get("url") or "/unknown"
    count = details.get("count") or details.get("attempt_count") or details.get("num_users") or 1
    status_code = details.get("status_code") or details.get("response_code") or "?"

    # Success hint for SQLi
    success_hint = "been successful (HTTP 200)" if str(status_code) == "200" else "failed (non-200 response)"

    # Anomaly features for ML alerts
    anomaly_features_raw = details.get("top_features") or details.get("anomaly_features") or []
    if isinstance(anomaly_features_raw, list):
        anomaly_features = ", ".join(str(f) for f in anomaly_features_raw[:3]) or "off-hours access, high payload entropy"
    else:
        anomaly_features = str(anomaly_features_raw) or "off-hours access, high payload entropy"

    confidence = details.get("confidence") or details.get("anomaly_score") or "N/A"
    if isinstance(confidence, float):
        confidence = f"{confidence:.1%}"

    return {
        "rule": rule,
        "source_ip": source_ip,
        "severity": severity,
        "severity_upper": severity.upper(),
        "user": user,
        "path": path,
        "count": count,
        "status_code": status_code,
        "success_hint": success_hint,
        "anomaly_features": anomaly_features,
        "confidence": confidence,
    }


def _render(template: str, ctx: dict) -> str:
    """Safe string format — missing keys fall back to '<unknown>'."""
    try:
        return template.format(**ctx)
    except KeyError as e:
        # Replace missing key with placeholder
        key = str(e).strip("'")
        ctx[key] = f"<{key}>"
        return _render(template, ctx)


def _extract_iocs(alert: dict, details: dict, ioc_fields: list[str]) -> list[dict]:
    """Extract indicators of compromise as structured dicts."""
    iocs: list[dict] = []

    if "source_ip" in ioc_fields:
        ip = alert.get("source_ip")
        if ip:
            iocs.append({"type": "IP Address", "value": ip, "context": "Attack source"})

    if "user" in ioc_fields:
        user = details.get("user") or details.get("target_user")
        if user:
            iocs.append({"type": "Username", "value": user, "context": "Targeted account"})

    if "path" in ioc_fields:
        path = details.get("path") or details.get("endpoint")
        if path:
            iocs.append({"type": "URL Path", "value": path, "context": "Attack vector"})

    # Always add MITRE technique if present
    mitre_id = alert.get("mitre_technique_id")
    mitre_name = alert.get("mitre_technique_name")
    if mitre_id:
        iocs.append({"type": "MITRE Technique", "value": mitre_id, "context": mitre_name or ""})

    # Extract any additional users from spray/brute details
    targets = details.get("target_users") or details.get("users_targeted") or []
    if isinstance(targets, list):
        for u in targets[:5]:
            iocs.append({"type": "Targeted User", "value": u, "context": "Password spray target"})

    return iocs


def _build_confidence_note(rule: str, details: dict) -> Optional[str]:
    """Generate a confidence/context note, especially for ML alerts."""
    if rule == "ml_behavioral_anomaly":
        score = details.get("anomaly_score") or details.get("confidence")
        features = details.get("top_features") or []
        note = (
            "⚠️  This alert was generated by an unsupervised ML model. "
            "Human analyst review is required to confirm or dismiss. "
        )
        if score:
            note += f"Model confidence: {score}. "
        if features:
            note += f"Anomalous features: {', '.join(str(f) for f in features[:3])}."
        return note
    return None
