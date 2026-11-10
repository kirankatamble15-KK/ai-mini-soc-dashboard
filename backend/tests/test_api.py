"""Integration tests for Mini SOC REST API endpoints."""

import json
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.database.connection import initialize_database


class ApiEndpointsTestCase(unittest.TestCase):
    """Test suite verifying end-to-end API behaviors with an isolated test SQLite db."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_soc.db"

        self.app = create_app({"TESTING": True, "DATABASE": str(self.db_path)})
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_health_check(self):
        """Verify API health endpoint."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")

    def test_demo_analyze_and_list_alerts(self):
        """Verify demo log analysis, alert persistence, and alert retrieval."""
        res_analyze = self.client.post("/api/demo/analyze")
        self.assertEqual(res_analyze.status_code, 201)
        analyze_data = res_analyze.get_json()
        self.assertGreater(analyze_data["alert_count"], 0)

        res_alerts = self.client.get("/api/alerts")
        self.assertEqual(res_alerts.status_code, 200)
        alerts_data = res_alerts.get_json()
        self.assertEqual(alerts_data["alert_count"], analyze_data["alert_count"])

        # Check MITRE taxonomy is present on alerts
        first_alert = alerts_data["alerts"][0]
        self.assertIn("mitre_tactic", first_alert)
        self.assertIn("mitre_technique_id", first_alert)

    def test_repeated_demo_analysis_deduplicates_and_preserves_triage(self):
        """Repeated sample analysis should not create alerts or erase analyst work."""
        first_response = self.client.post("/api/demo/analyze")
        self.assertEqual(first_response.status_code, 201)
        first_run = first_response.get_json()
        self.assertGreater(first_run["alert_count"], 0)
        self.assertEqual(first_run["duplicate_alert_count"], 0)

        alert = first_run["alerts"][0]
        alert_id = alert["id"]
        status_response = self.client.patch(
            f"/api/alerts/{alert_id}", json={"status": "acknowledged"}
        )
        self.assertEqual(status_response.status_code, 200)

        note_response = self.client.post(
            f"/api/alerts/{alert_id}/notes",
            json={"note": "Reviewed the repeated sample finding."},
        )
        self.assertEqual(note_response.status_code, 201)

        second_response = self.client.post("/api/demo/analyze")
        self.assertEqual(second_response.status_code, 201)
        second_run = second_response.get_json()
        self.assertEqual(second_run["alert_count"], 0)
        self.assertEqual(
            second_run["duplicate_alert_count"], first_run["analyzed_alert_count"]
        )

        saved_alerts = self.client.get("/api/alerts").get_json()
        self.assertEqual(saved_alerts["alert_count"], first_run["alert_count"])
        preserved_alert = next(a for a in saved_alerts["alerts"] if a["id"] == alert_id)
        self.assertEqual(preserved_alert["status"], "acknowledged")

        saved_notes = self.client.get(f"/api/alerts/{alert_id}/notes").get_json()
        self.assertEqual(saved_notes["note_count"], 1)
        self.assertEqual(
            saved_notes["notes"][0]["note"], "Reviewed the repeated sample finding."
        )

    def test_patch_alert_status(self):
        """Verify alert triage state transitions."""
        self.client.post("/api/demo/analyze")
        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        alert_id = alerts[0]["id"]

        patch_res = self.client.patch(
            f"/api/alerts/{alert_id}",
            data=json.dumps({"status": "acknowledged"}),
            content_type="application/json",
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.get_json()["status"], "acknowledged")

    def test_logs_endpoint_and_filtering(self):
        """Verify log retrieval and filtering after analysis."""
        self.client.post("/api/demo/analyze")
        res_logs = self.client.get("/api/logs?limit=50")
        self.assertEqual(res_logs.status_code, 200)
        log_data = res_logs.get_json()
        self.assertGreater(log_data["total"], 0)

    def test_live_log_ingest(self):
        """Verify ingesting custom logs dynamically via POST /api/logs/ingest."""
        payload = [
            {"timestamp": "2026-10-31T12:00:00Z", "event_type": "login", "username": "victim", "source_ip": "198.51.100.5", "success": False},
            {"timestamp": "2026-10-31T12:00:05Z", "event_type": "login", "username": "victim", "source_ip": "198.51.100.5", "success": False},
            {"timestamp": "2026-10-31T12:00:10Z", "event_type": "login", "username": "victim", "source_ip": "198.51.100.5", "success": False},
        ]
        res = self.client.post("/api/logs/ingest", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["ingested_count"], 3)
        self.assertGreaterEqual(data["alerts_generated"], 1)

    def test_soc_stats_metrics(self):
        """Verify aggregate SOC metrics and MITRE breakdown."""
        self.client.post("/api/demo/analyze")
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_alerts", data)
        self.assertIn("mitre_tactics", data)
        self.assertIn("mitre_techniques", data)


if __name__ == "__main__":
    unittest.main()
