"""Flask application factory for the AI Mini SOC."""

from pathlib import Path
from typing import Any

from flask import Flask, jsonify

from app.api.detection_routes import detection_api
from app.database.connection import initialize_database


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        test_config: Optional dict of config overrides for testing.
                     Supports the 'DATABASE' key to point to a temp DB.
    """
    app = Flask(__name__)

    # Default database path
    default_db = Path(app.instance_path) / "soc.db"
    app.config["DATABASE"] = str(default_db)

    if test_config is not None:
        app.config.update(test_config)

    # Ensure instance directory exists for non-test runs
    db_path = Path(app.config["DATABASE"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    initialize_database(app.config["DATABASE"])
    app.register_blueprint(detection_api)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", service="ai-mini-soc")

    return app
