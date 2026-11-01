"""Unit and integration tests for detection rules and MITRE ATT&CK taxonomy."""

import unittest
from app.detection.brute_force import detect_brute_force, detect_password_spraying
from app.detection.suspicious_requests import (
    detect_command_injection,
    detect_path_traversal,
    detect_security_scanners,
    detect_sql_injection,
)
from app.detection.detection_engine import analyze_events
from app.detection.mitre import get_mitre_metadata


class DetectionRulesTestCase(unittest.TestCase):
    """Test suite covering True Positive and True Negative detection scenarios."""

    def test_brute_force_sliding_window_true_positive(self):
        """Verify that high-frequency failed logins within window trigger T1110.001."""
        events = [
            {"timestamp": "2026-10-29T09:14:17Z", "event_type": "login", "username": "admin", "source_ip": "198.51.100.24", "success": False},
            {"timestamp": "2026-10-29T09:14:23Z", "event_type": "login", "username": "admin", "source_ip": "198.51.100.24", "success": False},
            {"timestamp": "2026-10-29T09:14:31Z", "event_type": "login", "username": "admin", "source_ip": "198.51.100.24", "success": False},
        ]
        findings = detect_brute_force(events, threshold=3, window_seconds=300)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "repeated_failed_logins")
        self.assertEqual(findings[0]["source_ip"], "198.51.100.24")
        self.assertEqual(findings[0]["failed_attempts"], 3)
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1110.001")

    def test_brute_force_sliding_window_false_positive_prevention(self):
        """Ensure sporadic failed logins separated by hours do NOT trigger false positives."""
        events = [
            {"timestamp": "2026-10-29T10:00:00Z", "event_type": "login", "username": "emma", "source_ip": "192.0.2.14", "success": False},
            {"timestamp": "2026-10-29T14:00:00Z", "event_type": "login", "username": "emma", "source_ip": "192.0.2.14", "success": False},
            {"timestamp": "2026-10-29T18:00:00Z", "event_type": "login", "username": "emma", "source_ip": "192.0.2.14", "success": False},
        ]
        findings = detect_brute_force(events, threshold=3, window_seconds=300)
        self.assertEqual(len(findings), 0, "Sporadic failed logins should not trigger brute force alert")

    def test_password_spraying_detection(self):
        """Verify password spray detection when 1 IP targets multiple accounts."""
        events = [
            {"timestamp": "2026-10-29T11:00:10Z", "event_type": "login", "username": "sarah", "source_ip": "198.51.100.99", "success": False},
            {"timestamp": "2026-10-29T11:00:20Z", "event_type": "login", "username": "david", "source_ip": "198.51.100.99", "success": False},
            {"timestamp": "2026-10-29T11:00:30Z", "event_type": "login", "username": "rachel", "source_ip": "198.51.100.99", "success": False},
        ]
        findings = detect_password_spraying(events, unique_user_threshold=3, window_seconds=600)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "password_spraying")
        self.assertEqual(findings[0]["source_ip"], "198.51.100.99")
        self.assertEqual(len(findings[0]["usernames"]), 3)
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1110.003")

    def test_sql_injection_detection(self):
        """Verify SQL injection patterns in URL paths."""
        events = [
            {"timestamp": "2026-10-30T10:05:39Z", "event_type": "web_request", "source_ip": "192.0.2.55", "method": "GET", "path": "/items?id=1%20UNION%20SELECT%20password", "status_code": 400},
            {"timestamp": "2026-10-30T10:02:11Z", "event_type": "web_request", "source_ip": "203.0.113.42", "method": "GET", "path": "/products?category=books", "status_code": 200},
        ]
        findings = detect_sql_injection(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "sql_injection_pattern")
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1190")

    def test_path_traversal_detection(self):
        """Verify path traversal pattern detection."""
        events = [
            {"timestamp": "2026-10-30T10:08:14Z", "event_type": "web_request", "source_ip": "198.51.100.120", "method": "GET", "path": "/static/../../../../etc/passwd", "status_code": 403},
        ]
        findings = detect_path_traversal(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "path_traversal_pattern")
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1083")

    def test_command_injection_detection(self):
        """Verify remote OS command injection detection."""
        events = [
            {"timestamp": "2026-10-30T10:09:50Z", "event_type": "web_request", "source_ip": "198.51.100.201", "method": "POST", "path": "/api/tools/ping?host=127.0.0.1;whoami", "status_code": 500},
        ]
        findings = detect_command_injection(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "command_injection_pattern")
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1059")

    def test_scanner_reconnaissance_detection(self):
        """Verify detection of offensive security scanner signatures."""
        events = [
            {"timestamp": "2026-10-30T10:11:02Z", "event_type": "web_request", "source_ip": "203.0.113.199", "method": "GET", "path": "/admin?scanner=nikto-test", "status_code": 404},
        ]
        findings = detect_security_scanners(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "security_scanner_recon")
        self.assertEqual(findings[0]["mitre"]["technique_id"], "T1595.002")


if __name__ == "__main__":
    unittest.main()

