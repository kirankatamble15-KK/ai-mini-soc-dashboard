"""Flask application factory for the AI Mini SOC."""

from pathlib import Path

from flask import Flask, jsonify

from app.api.detection_routes import detection_api
from app.database.connection import initialize_database


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = Path(app.instance_path) / "soc.db"
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    initialize_database(app.config["DATABASE_PATH"])
    app.register_blueprint(detection_api)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", service="ai-mini-soc")

    return app
