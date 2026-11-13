"""Small, labeled synthetic benchmark for the Isolation Forest detector."""

from datetime import datetime, timedelta, timezone
from typing import Any

from app.ml.baseline_generator import generate_baseline_dataset
from app.ml.features import extract_dataset_features


def build_evaluation_dataset() -> tuple[list[dict[str, Any]], list[int], list[str]]:
    """Build labeled events, including each attack category, in time order."""
    normal_events = generate_baseline_dataset(120)
    labeled = [(event, 0, "normal") for event in normal_events]

    # A tight, off-hours burst from one synthetic source makes the benchmark's
    # attack behavior explicit and repeatable for the burst-velocity feature.
    start = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)
    attack_paths = [
        "/login?user=admin%27%20OR%201%3D1",
        "/items?id=1%20UNION%20SELECT%20password",
        "/../../../../etc/passwd",
        "/api/run?cmd=%3Bcat%20/etc/passwd",
    ]
    attack_categories = [
        "failed_login",
        "sql_injection",
        "path_traversal",
        "command_injection",
    ]
    for index in range(40):
        timestamp = (start + timedelta(seconds=index * 5)).isoformat().replace("+00:00", "Z")
        category = attack_categories[index % len(attack_categories)]
        if index % 4 == 0:
            event = {
                "timestamp": timestamp,
                "event_type": "login",
                "username": "admin",
                "source_ip": "203.0.113.77",
                "success": False,
            }
        else:
            event = {
                "timestamp": timestamp,
                "event_type": "web_request",
                "source_ip": "203.0.113.77",
                "method": "GET",
                "path": attack_paths[index % len(attack_paths)],
                "status_code": 400,
            }
        labeled.append((event, 1, category))

    labeled.sort(key=lambda item: item[0]["timestamp"])
    return (
        [event for event, _, _ in labeled],
        [label for _, label, _ in labeled],
        [category for _, _, category in labeled],
    )


def evaluate_detector(detector: Any) -> dict[str, Any]:
    """Score predictions against synthetic labels and return common metrics."""
    if not detector.is_trained():
        raise ValueError("The anomaly detector must be trained before evaluation")

    events, labels, categories = build_evaluation_dataset()
    predictions = detector.model.predict(extract_dataset_features(events))
    predicted_attack = [int(value == -1) for value in predictions]

    true_positive = sum(actual == 1 and predicted == 1 for actual, predicted in zip(labels, predicted_attack))
    false_positive = sum(actual == 0 and predicted == 1 for actual, predicted in zip(labels, predicted_attack))
    true_negative = sum(actual == 0 and predicted == 0 for actual, predicted in zip(labels, predicted_attack))
    false_negative = sum(actual == 1 and predicted == 0 for actual, predicted in zip(labels, predicted_attack))

    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    category_results = {}
    for category in sorted(set(categories) - {"normal"}):
        category_indexes = [index for index, value in enumerate(categories) if value == category]
        detected = sum(predicted_attack[index] for index in category_indexes)
        total = len(category_indexes)
        category_results[category] = {
            "sample_count": total,
            "detected_count": detected,
            "recall": round(detected / total, 3) if total else 0.0,
        }

    return {
        "benchmark": "synthetic",
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "sample_count": len(events),
        "normal_count": sum(label == 0 for label in labels),
        "attack_count": sum(label == 1 for label in labels),
        "metrics": {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "false_positive_rate": round(false_positive_rate, 3),
        },
        "confusion_matrix": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
        },
        "attack_categories": category_results,
        "note": "Synthetic benchmark only; these scores do not represent real-world detection performance.",
    }
