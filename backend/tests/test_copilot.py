"""
test_copilot.py — Tests for the AI SOC Analyst Copilot

Covers:
  - Template rendering for each rule type
  - IOC extraction
  - API endpoint (GET /api/alerts/<alert_id>/copilot)
  - 404 for unknown alert IDs
  - Confidence note for ML anomaly alerts
"""

import json
import tempfile
import unittest
from pathlib import Path

from app.copilot.analyst import generate_incident_analysis, _extract_iocs
from app.database.connection import initialize_database, save_alerts, get_alert_by_id


# ---------------------------------------------------------------------------
# Sample alert factory
# ---------------------------------------------------------------------------

def _make_alert(rule: str, severity: str = "high", **kwargs) -> dict:
    base = {
        "id": f"test-{rule}-001",
        "title": f"Test {rule} alert",
        "severity": severity,
        "status": "open",
        "source_ip": "192.168.1.99",
        "failed_attempts": 10,
        "usernames": ["admin"],
        "first_seen": "2024-01-01T00:00:00Z",
        "last_seen": "2024-01-01T00:05:00Z",
        "rule": rule,
        "event_count": 10,
        "count_label": "failed logins",
        "details": kwargs.get("details", {}),
        "mitre_tactic": kwargs.get("mitre_tactic", "TA0001"),
        "mitre_technique_id": kwargs.get("mitre_technique_id", "T1110"),
        "mitre_technique_name": kwargs.get("mitre_technique_name", "Brute Force"),
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
    }
    return base


class TestCopilotTemplates(unittest.TestCase):
    """Unit tests for the template-based incident analysis engine."""

    def test_brute_force_summary_contains_ip(self):
        alert = _make_alert("brute_force", details={"user": "admin", "count": 15})
        result = generate_incident_analysis(alert)
        self.assertIn("192.168.1.99", result["executive_summary"])
        self.assertIn("executive_summary", result)
        self.assertIn("adversary_intent", result)
        self.assertIn("remediation_playbook", result)
        self.assertIn("ioc_list", result)
        self.assertIn("kill_chain_stage", result)

    def test_sql_injection_summary_contains_path(self):
        alert = _make_alert(
            "sql_injection",
            severity="critical",
            details={"path": "/api/login", "status_code": 200},
        )
        result = generate_incident_analysis(alert)
        self.assertIn("/api/login", result["executive_summary"])
        self.assertIn("CRITICAL", result["executive_summary"])

    def test_command_injection_is_critical(self):
        alert = _make_alert(
            "command_injection",
            severity="critical",
            details={"path": "/search?q=;whoami"},
        )
        result = generate_incident_analysis(alert)
        self.assertIn("CRITICAL", result["executive_summary"])
        # Playbook should include isolation step
        playbook_text = "\n".join(result["remediation_playbook"])
        self.assertIn("ISOLATE", playbook_text)

    def test_password_spray_summary(self):
        alert = _make_alert("password_spray", details={"count": 8})
        result = generate_incident_analysis(alert)
        self.assertIn("spray", result["executive_summary"].lower())
        self.assertIn("T1110.003", result["adversary_intent"])

    def test_ml_anomaly_confidence_note(self):
        alert = _make_alert(
            "ml_behavioral_anomaly",
            details={
                "confidence": 0.87,
                "top_features": ["off_hours", "high_payload", "rare_endpoint"],
            },
        )
        result = generate_incident_analysis(alert)
        self.assertIsNotNone(result["confidence_note"])
        self.assertIn("ML model", result["confidence_note"])

    def test_scanner_recon_kill_chain(self):
        alert = _make_alert("scanner_recon", mitre_tactic="TA0043")
        result = generate_incident_analysis(alert)
        # TA0043 = Reconnaissance → "1 - Reconnaissance"
        self.assertIn("Reconnaissance", result["kill_chain_stage"])

    def test_unknown_rule_falls_back_to_default(self):
        alert = _make_alert("some_future_rule_xyz")
        result = generate_incident_analysis(alert)
        # Should not raise; should return structured dict
        self.assertIn("executive_summary", result)
        self.assertIsInstance(result["remediation_playbook"], list)

    def test_remediation_is_list_of_strings(self):
        for rule in ["brute_force", "sql_injection", "path_traversal", "command_injection",
                     "password_spray", "scanner_recon", "ml_behavioral_anomaly"]:
            with self.subTest(rule=rule):
                alert = _make_alert(rule, details={"path": "/test", "user": "admin"})
                result = generate_incident_analysis(alert)
                self.assertIsInstance(result["remediation_playbook"], list)
                for line in result["remediation_playbook"]:
                    self.assertIsInstance(line, str)

    def test_ioc_list_always_contains_ip(self):
        alert = _make_alert("brute_force", details={"user": "root"})
        result = generate_incident_analysis(alert)
        ip_iocs = [i for i in result["ioc_list"] if i["type"] == "IP Address"]
        self.assertEqual(len(ip_iocs), 1)
        self.assertEqual(ip_iocs[0]["value"], "192.168.1.99")

    def test_generated_at_is_utc_iso(self):
        alert = _make_alert("brute_force")
        result = generate_incident_analysis(alert)
        self.assertTrue(result["generated_at"].endswith("Z"))


class TestCopilotAPI(unittest.TestCase):
    """Integration tests for the /api/alerts/<id>/copilot endpoint."""

    def setUp(self):
        from app.main import create_app
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = Path(self._tmp.name) / "test.db"
        initialize_database(db_path)

        # Pre-load a real alert
        self._alert_id = "test-copilot-api-001"
        save_alerts(db_path, [
            {
                "id": self._alert_id,
                "title": "Brute Force: admin from 10.0.0.1",
                "severity": "high",
                "status": "open",
                "source_ip": "10.0.0.1",
                "failed_attempts": 12,
                "usernames": ["admin"],
                "first_seen": "2024-01-01T03:00:00Z",
                "last_seen": "2024-01-01T03:05:00Z",
                "rule": "brute_force",
                "event_count": 12,
                "count_label": "failed logins",
                "details": {"user": "admin", "count": 12},
                "mitre_tactic": "TA0006",
                "mitre_technique_id": "T1110.001",
                "mitre_technique_name": "Password Guessing",
                "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
            }
        ])

        self.app = create_app({"TESTING": True, "DATABASE": str(db_path)})
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            self._tmp.cleanup()
        except Exception:
            pass

    def test_copilot_returns_200_for_known_alert(self):
        resp = self.client.get(f"/api/alerts/{self._alert_id}/copilot")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["alert_id"], self._alert_id)
        self.assertIn("analysis", data)

    def test_copilot_analysis_has_required_keys(self):
        resp = self.client.get(f"/api/alerts/{self._alert_id}/copilot")
        analysis = resp.get_json()["analysis"]
        required_keys = [
            "executive_summary", "adversary_intent", "kill_chain_stage",
            "remediation_playbook", "ioc_list", "generated_at"
        ]
        for key in required_keys:
            with self.subTest(key=key):
                self.assertIn(key, analysis)

    def test_copilot_returns_404_for_unknown_alert(self):
        resp = self.client.get("/api/alerts/nonexistent-alert-id-xyz/copilot")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("error", resp.get_json())

    def test_copilot_source_ip_in_executive_summary(self):
        resp = self.client.get(f"/api/alerts/{self._alert_id}/copilot")
        analysis = resp.get_json()["analysis"]
        self.assertIn("10.0.0.1", analysis["executive_summary"])

    def test_copilot_ioc_list_not_empty(self):
        resp = self.client.get(f"/api/alerts/{self._alert_id}/copilot")
        ioc_list = resp.get_json()["analysis"]["ioc_list"]
        self.assertGreater(len(ioc_list), 0)


if __name__ == "__main__":
    unittest.main()

