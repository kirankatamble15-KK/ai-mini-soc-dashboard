"""SQLite connection and alert persistence helpers."""

import json
import sqlite3
from pathlib import Path


def connect_database(path: str | Path) -> sqlite3.Connection:
    """Open a SQLite database and return rows by column name."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(path: str | Path) -> None:
    """Create the alerts table and add fields required by newer alert types."""
    with connect_database(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                usernames TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                rule TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                count_label TEXT NOT NULL DEFAULT 'events',
                details TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        migrations = {
            "event_count": "ALTER TABLE alerts ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0",
            "count_label": "ALTER TABLE alerts ADD COLUMN count_label TEXT NOT NULL DEFAULT 'events'",
            "details": "ALTER TABLE alerts ADD COLUMN details TEXT NOT NULL DEFAULT '{}'",
        }
        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)

        connection.execute(
            "UPDATE alerts SET event_count = failed_attempts, count_label = 'failed logins' "
            "WHERE event_count = 0 AND failed_attempts > 0"
        )


def save_alerts(path: str | Path, alerts: list[dict]) -> None:
    """Insert alert records into SQLite."""
    with connect_database(path) as connection:
        connection.executemany(
            """
            INSERT INTO alerts (
                id, title, severity, status, source_ip, failed_attempts,
                usernames, first_seen, last_seen, rule, event_count, count_label, details
            ) VALUES (
                :id, :title, :severity, :status, :source_ip, :failed_attempts,
                :usernames, :first_seen, :last_seen, :rule, :event_count, :count_label, :details
            )
            """,
            [
                {
                    **alert,
                    "usernames": json.dumps(alert["usernames"]),
                    "details": json.dumps(alert["details"]),
                }
                for alert in alerts
            ],
        )


def list_alerts(path: str | Path) -> list[dict]:
    """Return stored alerts, newest first."""
    with connect_database(path) as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY rowid DESC"
        ).fetchall()
    alerts = [dict(row) for row in rows]
    for alert in alerts:
        alert["usernames"] = json.loads(alert["usernames"])
        alert["details"] = json.loads(alert["details"])
    return alerts
