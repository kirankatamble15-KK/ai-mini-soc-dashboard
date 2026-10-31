# AI Mini SOC

A learning project for ingesting synthetic security logs, detecting suspicious activity, and presenting alerts in a small analyst dashboard.

## Build roadmap

1. **Foundation** — Flask API, configuration, and a documented event format.
2. **Log pipeline** — synthetic data, parsing, validation, and ingestion.
3. **Detections** — explainable rules for brute force attempts, SQL injection patterns, and suspicious requests.
4. **Alerts and storage** — persist events and alerts, then expose useful API endpoints.
5. **Dashboard** — browse alerts, logs, and incident summaries.
6. **Hardening and extensions** — authentication, threat intelligence, and evaluated anomaly detection.

We will use synthetic logs while developing. Only ingest logs from systems you own or are authorized to monitor. Rule-based detection comes before machine learning so each alert has a clear reason.

## Current status

Milestone 1: initial Flask service scaffold.

Milestone 2: JSON Lines sample authentication log, parser, and file reader. Each event includes `timestamp`, `event_type`, `username`, `source_ip`, and `success`.

Milestone 3: first rule detects three or more failed logins from the same IP in one analysis batch. The current rule does not yet apply a time window.

Milestone 4: `GET /api/demo/analysis` reads the bundled synthetic log, runs the parser and detection rule, and returns a JSON summary.

Milestone 5: detection findings are converted to dashboard-ready alerts with an ID, status, and severity.

Milestone 6: SQLite stores alerts in the local Flask `instance/soc.db` database. Use `POST /api/demo/analyze` to analyze and save the sample alerts, then `GET /api/alerts` to list saved alerts.

Milestone 7: React dashboard in `frontend/` reads saved alerts from the Flask API through a Vite development proxy.

Milestone 8: the parser accepts synthetic web request events, and a starter SQL injection rule checks decoded request paths for `UNION SELECT` and quoted numeric `OR/AND` conditions. Inspect its output at `GET /api/demo/web-analysis`.

Milestone 9: sample analysis saves both login and web request alerts. The dashboard shows each alert's activity count and rule-specific evidence. SQLite adds new fields without removing existing alert records.

## Run locally

From the `backend` directory, create a virtual environment, install `requirements.txt`, then run:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m flask --app app.main run --debug
```

The health endpoint is available at `http://127.0.0.1:5000/api/health`. The sample analysis endpoint is at `http://127.0.0.1:5000/api/demo/analysis`; web request analysis is at `http://127.0.0.1:5000/api/demo/web-analysis`. To save alerts from both sample logs, send a `POST` request to `http://127.0.0.1:5000/api/demo/analyze`, then view them at `http://127.0.0.1:5000/api/alerts`.

## Start the dashboard

Keep Flask running in one terminal. In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (usually `http://localhost:5173`). The dashboard reads saved alerts from the Flask API, so run the sample analysis once with `POST /api/demo/analyze` if the table is empty.

## Configuration

Copy `.env.example` to `.env` for local settings. Never commit `.env` or real credentials.
