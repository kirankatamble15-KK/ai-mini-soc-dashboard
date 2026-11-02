"""Unsupervised Anomaly Detection using Scikit-Learn Isolation Forest.

Identifies behavioral outliers, zero-day indicators, and traffic anomalies that
traditional signature-based detection rules miss.
"""

from pathlib import Path
from typing import Any
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.detection.mitre import get_mitre_metadata
from app.ml.baseline_generator import generate_baseline_dataset
from app.ml.features import (
    FEATURE_NAMES,
    extract_dataset_features,
    extract_features_from_event,
    compute_ip_velocities,
)


DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "isolation_forest.joblib"


class ThreatAnomalyDetector:
    """Isolation Forest anomaly detection engine with Explainable AI (XAI) feature attribution."""

    def __init__(self, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: IsolationForest | None = None
        self.feature_means: np.ndarray | None = None
        self.feature_stds: np.ndarray | None = None

    def is_trained(self) -> bool:
        """Check whether the model is trained and ready for inference."""
        return self.model is not None

    def train(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Train Isolation Forest on baseline security event traffic."""
        X = extract_dataset_features(events)
        if len(X) < 10:
            raise ValueError("Baseline dataset must have at least 10 samples to train")

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self.model.fit(X)

        # Baseline statistics for Explainable AI (XAI) attribution
        self.feature_means = np.mean(X, axis=0)
        self.feature_stds = np.std(X, axis=0) + 1e-6  # avoid zero div

        return {
            "training_samples": len(X),
            "features_used": FEATURE_NAMES,
            "contamination": self.contamination,
        }

    def save(self, path: Path | str = DEFAULT_MODEL_PATH) -> None:
        """Serialize and persist trained model and baseline statistics to disk."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "feature_means": self.feature_means,
                "feature_stds": self.feature_stds,
                "contamination": self.contamination,
                "feature_names": FEATURE_NAMES,
            },
            target_path,
        )

    def load(self, path: Path | str = DEFAULT_MODEL_PATH) -> bool:
        """Load a persisted model from disk."""
        target_path = Path(path)
        if not target_path.exists():
            return False

        try:
            payload = joblib.load(target_path)
            self.model = payload["model"]
            self.feature_means = payload.get("feature_means")
            self.feature_stds = payload.get("feature_stds")
            self.contamination = payload.get("contamination", self.contamination)
            return True
        except Exception:
            return False

    def explain_anomaly(self, feature_vector: np.ndarray) -> list[str]:
        """Generate human-readable explanations of which features drove the anomaly score."""
        if self.feature_means is None or self.feature_stds is None:
            return ["Statistically anomalous behavioral pattern"]

        z_scores = np.abs((feature_vector - self.feature_means) / self.feature_stds)
        top_indices = np.argsort(z_scores)[::-1]

        reasons = []
        for idx in top_indices[:2]:
            feat = FEATURE_NAMES[idx]
            val = feature_vector[idx]
            if feat == "is_off_hours" and val > 0.5:
                reasons.append("Off-hours activity outside standard business hours")
            elif feat == "ip_burst_velocity" and val > 0.3:
                reasons.append("Abnormal request velocity / high-frequency burst")
            elif feat == "suspicious_char_ratio" and val > 0.1:
                reasons.append("High density of special injection/scripting characters")
            elif feat == "payload_length" and val > 0.5:
                reasons.append("Unusually long request payload length")
            elif feat == "is_failure_or_error" and val > 0.5:
                reasons.append("Elevated failure / HTTP error rate")
            elif feat == "endpoint_depth" and val > 2.0:
                reasons.append("Unusual URI path depth exploration")

        return reasons if reasons else ["Multivariate statistical anomaly across activity profile"]

    def predict_anomalies(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run inference over incoming events and generate ML anomaly findings."""
        if not self.is_trained():
            return []

        if not events:
            return []

        X = extract_dataset_features(events)
        predictions = self.model.predict(X)  # -1 for anomaly, 1 for inlier
        decision_scores = self.model.decision_function(X)

        findings: list[dict[str, Any]] = []

        for idx, (pred, score) in enumerate(zip(predictions, decision_scores)):
            if pred == -1:  # Outlier detected
                event = events[idx]
                feat_vec = X[idx]
                explanations = self.explain_anomaly(feat_vec)

                # Convert decision score to confidence percentage (0.0 to 1.0)
                # Lower decision score = further outside decision boundary
                anomaly_confidence = round(min(max(0.55 + (-score * 1.5), 0.55), 0.99), 2)

                event_type = event.get("event_type", "unknown")
                source_ip = event.get("source_ip", "0.0.0.0")

                findings.append(
                    {
                        "rule": "ml_behavioral_anomaly",
                        "title": f"Behavioral Anomaly ({int(anomaly_confidence * 100)}% Confidence)",
                        "source_ip": source_ip,
                        "anomaly_score": anomaly_confidence,
                        "raw_score": float(score),
                        "explanation": ", ".join(explanations),
                        "event_type": event_type,
                        "method": event.get("method"),
                        "path": event.get("path") or event.get("username"),
                        "status_code": event.get("status_code"),
                        "timestamp": event.get("timestamp"),
                        "mitre": {
                            "tactic": "Defense Evasion",
                            "tactic_id": "TA0005",
                            "technique_id": "T1078",
                            "technique_name": "Valid Accounts / Anomaly",
                            "url": "https://attack.mitre.org/techniques/T1078/",
                        },
                    }
                )

        return findings


# Global singleton instance for app-wide inference
_detector_instance: ThreatAnomalyDetector | None = None


def get_anomaly_detector(model_path: Path | str = DEFAULT_MODEL_PATH) -> ThreatAnomalyDetector:
    """Retrieve or initialize the global anomaly detector singleton."""
    global _detector_instance
    if _detector_instance is None:
        detector = ThreatAnomalyDetector()
        loaded = detector.load(model_path)
        if not loaded:
            # Auto-train on synthetic baseline if no persisted model exists
            baseline = generate_baseline_dataset(300)
            detector.train(baseline)
            detector.save(model_path)
        _detector_instance = detector
    return _detector_instance

