"""SQLite connection, schema migration, and security data persistence helpers."""

import json
import sqlite3
from pathlib import Path
from typing import Any


def connect_database(path: str | Path) -> sqlite3.Connection:
    """Open a SQLite database and return rows by column name."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(path: str | Path) -> None:
    """Create alerts and events tables and apply progressive schema migrations."""
    with connect_database(path) as connection:
        # Core alerts table
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
                details TEXT NOT NULL DEFAULT '{}',
                mitre_tactic TEXT NOT NULL DEFAULT 'Unknown',
                mitre_technique_id TEXT NOT NULL DEFAULT 'N/A',
                mitre_technique_name TEXT NOT NULL DEFAULT 'N/A',
                mitre_url TEXT NOT NULL DEFAULT ''
            )
            """
        )

        # Raw security events table for log exploration and incident drill-down
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT,
                success INTEGER,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                raw_json TEXT NOT NULL
            )
            """
        )

        # Analyst-written investigation notes linked to saved alerts
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            )
            """
        )

        # Synthetic ML evaluation history for model comparison over time
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ml_evaluation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluated_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )

        # Check existing alert table columns and dynamically migrate if needed
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        migrations = {
            "event_count": "ALTER TABLE alerts ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0",
            "count_label": "ALTER TABLE alerts ADD COLUMN count_label TEXT NOT NULL DEFAULT 'events'",
            "details": "ALTER TABLE alerts ADD COLUMN details TEXT NOT NULL DEFAULT '{}'",
            "mitre_tactic": "ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT NOT NULL DEFAULT 'Unknown'",
            "mitre_technique_id": "ALTER TABLE alerts ADD COLUMN mitre_technique_id TEXT NOT NULL DEFAULT 'N/A'",
            "mitre_technique_name": "ALTER TABLE alerts ADD COLUMN mitre_technique_name TEXT NOT NULL DEFAULT 'N/A'",
            "mitre_url": "ALTER TABLE alerts ADD COLUMN mitre_url TEXT NOT NULL DEFAULT ''",
        }
        for column, statement in migrations.items():
            if column not in columns:
                connection.execute(statement)

        connection.execute(
            "UPDATE alerts SET event_count = failed_attempts, count_label = 'failed logins' "
            "WHERE event_count = 0 AND failed_attempts > 0"
        )


def save_alerts(path: str | Path, alerts: list[dict]) -> dict[str, Any]:
    """Insert new alerts and update matching findings without resetting triage state."""
    inserted_alerts: list[dict] = []
    duplicate_count = 0
    with connect_database(path) as connection:
        for alert in alerts:
            usernames = alert.get("usernames", [])
            details = alert.get("details", {})
            candidates = connection.execute(
                """
                SELECT id, title, usernames, details
                FROM alerts
                WHERE rule = ? AND source_ip = ? AND first_seen IS ? AND last_seen IS ?
                ORDER BY rowid DESC
                """,
                (
                    alert["rule"],
                    alert["source_ip"],
                    alert.get("first_seen"),
                    alert.get("last_seen"),
                ),
            ).fetchall()
            matching_alert = next(
                (
                    row
                    for row in candidates
                    if row["title"] == alert["title"]
                    and sorted(json.loads(row["usernames"])) == sorted(usernames)
                    and json.loads(row["details"]) == details
                ),
                None,
            )

            if matching_alert:
                # Keep the original ID and status so linked notes and analyst triage survive.
                connection.execute(
                    """
                    UPDATE alerts
                    SET severity = ?, failed_attempts = MAX(failed_attempts, ?),
                        event_count = MAX(event_count, ?), count_label = ?,
                        details = ?, mitre_tactic = ?, mitre_technique_id = ?,
                        mitre_technique_name = ?, mitre_url = ?
                    WHERE id = ?
                    """,
                    (
                        alert["severity"],
                        alert.get("failed_attempts", 0),
                        alert.get("event_count", 0),
                        alert.get("count_label", "events"),
                        json.dumps(details),
                        alert.get("mitre_tactic", "Unknown"),
                        alert.get("mitre_technique_id", "N/A"),
                        alert.get("mitre_technique_name", "N/A"),
                        alert.get("mitre_url", ""),
                        matching_alert["id"],
                    ),
                )
                duplicate_count += 1
                continue

            connection.execute(
                """
                INSERT INTO alerts (
                    id, title, severity, status, source_ip, failed_attempts,
                    usernames, first_seen, last_seen, rule, event_count, count_label,
                    details, mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    alert["title"],
                    alert["severity"],
                    alert.get("status", "open"),
                    alert["source_ip"],
                    alert.get("failed_attempts", 0),
                    json.dumps(usernames),
                    alert.get("first_seen"),
                    alert.get("last_seen"),
                    alert["rule"],
                    alert.get("event_count", 0),
                    alert.get("count_label", "events"),
                    json.dumps(details),
                    alert.get("mitre_tactic", "Unknown"),
                    alert.get("mitre_technique_id", "N/A"),
                    alert.get("mitre_technique_name", "N/A"),
                    alert.get("mitre_url", ""),
                ),
            )
            inserted_alerts.append(alert)

    return {
        "alerts": inserted_alerts,
        "saved_count": len(inserted_alerts),
        "duplicate_count": duplicate_count,
    }


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


def update_alert_status(path: str | Path, alert_id: str, status: str) -> bool:
    """Update one alert's workflow status and report whether its ID exists."""
    with connect_database(path) as connection:
        cursor = connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
        )
        return cursor.rowcount > 0


def add_analyst_note(path: str | Path, alert_id: str, note: str, created_at: str) -> dict:
    """Save an analyst note and return the saved note with its database ID."""
    with connect_database(path) as connection:
        cursor = connection.execute(
            "INSERT INTO analyst_notes (alert_id, note, created_at) VALUES (?, ?, ?)",
            (alert_id, note, created_at),
        )
        return {"id": cursor.lastrowid, "alert_id": alert_id, "note": note, "created_at": created_at}


def list_analyst_notes(path: str | Path, alert_id: str) -> list[dict]:
    """Return investigation notes for one alert, oldest first."""
    with connect_database(path) as connection:
        rows = connection.execute(
            "SELECT id, alert_id, note, created_at FROM analyst_notes WHERE alert_id = ? ORDER BY id ASC",
            (alert_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_ml_evaluation(path: str | Path, report: dict[str, Any]) -> int:
    """Persist one benchmark report and return its database ID."""
    with connect_database(path) as connection:
        cursor = connection.execute(
            "INSERT INTO ml_evaluation_runs (evaluated_at, report_json) VALUES (?, ?)",
            (report["evaluated_at"], json.dumps(report)),
        )
        return int(cursor.lastrowid)


def list_ml_evaluations(path: str | Path, limit: int = 10) -> list[dict[str, Any]]:
    """Return the most recent saved benchmark reports."""
    with connect_database(path) as connection:
        rows = connection.execute(
            "SELECT id, evaluated_at, report_json FROM ml_evaluation_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {"id": row["id"], **json.loads(row["report_json"])}
        for row in rows
    ]


def save_events(path: str | Path, events: list[dict[str, Any]]) -> None:
    """Persist normalized raw events into SQLite for log search and investigation."""
    with connect_database(path) as connection:
        connection.executemany(
            """
            INSERT INTO events (
                timestamp, event_type, source_ip, username, success, method, path, status_code, raw_json
            ) VALUES (
                :timestamp, :event_type, :source_ip, :username, :success, :method, :path, :status_code, :raw_json
            )
            """,
            [
                {
                    "timestamp": event["timestamp"],
                    "event_type": event["event_type"],
                    "source_ip": event["source_ip"],
                    "username": event.get("username"),
                    "success": 1 if event.get("success") is True else (0 if event.get("success") is False else None),
                    "method": event.get("method"),
                    "path": event.get("path"),
                    "status_code": event.get("status_code"),
                    "raw_json": json.dumps(event),
                }
                for event in events
            ],
        )


def list_events(
    path: str | Path,
    event_type: str | None = None,
    source_ip: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Query ingested logs with filtering options for the Log Explorer."""
    query = "SELECT * FROM events WHERE 1=1"
    params: list[Any] = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if search:
        query += " AND (path LIKE ? OR username LIKE ? OR source_ip LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with connect_database(path) as connection:
        rows = connection.execute(query, params).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        item["raw"] = json.loads(item["raw_json"])
        del item["raw_json"]
        result.append(item)
    return result


def count_events(path: str | Path) -> int:
    """Return the total count of stored events."""
    with connect_database(path) as connection:
        row = connection.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
        return row["cnt"] if row else 0


def get_alert_by_id(path: str | Path, alert_id: str) -> dict | None:
    """Fetch a single alert by its UUID.  Returns None when not found."""
    with connect_database(path) as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
    if row is None:
        return None
    alert = dict(row)
    alert["usernames"] = json.loads(alert["usernames"])
    alert["details"] = json.loads(alert["details"])
    return alert
