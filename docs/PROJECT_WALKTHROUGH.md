# AI Mini SOC: Project Walkthrough

## What the project does

This is a small, local practice Security Operations Center (SOC). It reads sample or manually submitted security events, looks for suspicious patterns, saves possible alerts, and gives an analyst a dashboard to review them.

It does not watch a computer or network continuously. Analysis starts when someone clicks a button or submits events to the local API. The bundled data and the failed-login demo are synthetic.

## How the pieces work together

```text
Sample logs or demo events
          ↓
Flask API validates and stores events
          ↓
Detection rules + Isolation Forest
          ↓
SQLite stores alerts and investigation notes
          ↓
React dashboard displays alerts and evidence
```

Rule detections include repeated failed logins, password spraying, and suspicious web requests such as SQL injection, path traversal, and command injection. The Isolation Forest adds experimental anomaly alerts. Rule-based alerts include clear evidence; ML benchmark scores use generated sample data and are for learning.

## What an analyst can do

- In **Threat Overview**, replay the bundled logs or click **Try failed-login demo** to add three fake login failures and see the detection result.
- In **Active Security Alerts**, search and filter alerts, change their status, export the filtered list, or expand an alert to see related logs.
- In **Security Log Explorer**, search the stored events, load more results, and expand a row to see its raw JSON.
- In **AI / ML Engine**, retrain the example model and compare saved synthetic benchmark runs.
- In **Incidents & Playbooks**, review a plain-language incident summary and response suggestions, and save investigation notes.

Alerts are investigation leads, not proof that an attack occurred. The demo does not automatically block anything.

## Run the project

Open two VS Code terminals from the project folder.

**Terminal 1 — backend:**

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m flask --app app.main run --debug
```

**Terminal 2 — dashboard:**

```powershell
cd frontend
npm run dev
```

Open the local address printed by Vite, usually `http://localhost:5173`.

## Short presentation script

> “I built a local mini SOC dashboard using Flask, React, and SQLite. It accepts synthetic login and web events, checks them with explainable detection rules and an experimental Isolation Forest, then saves possible alerts for an analyst to investigate. The dashboard shows the related event evidence, supports analyst notes and status changes, and evaluates the ML model against generated sample data. It is an educational prototype: it runs on demand and does not monitor or protect a live network.”

## What remains outside this learning MVP

- User login and access control.
- A current, external threat-intelligence provider.
- Continuous ingestion from a real system you are authorized to monitor.
- Production deployment, monitoring, and security review.

These need separate design, configuration, and validation. Do not present this local demo as production-ready security software.
