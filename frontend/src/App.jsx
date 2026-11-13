import { useEffect, useState } from 'react'

function formatDate(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

function csvCell(value) {
  const text = value == null ? '' : String(value)
  return `"${text.replaceAll('"', '""')}"`
}

function downloadAlertsCsv(alerts) {
  const columns = [
    ['Title', (alert) => alert.title],
    ['Severity', (alert) => alert.severity],
    ['Status', (alert) => alert.status],
    ['Source IP', (alert) => alert.source_ip],
    ['Detection rule', (alert) => alert.rule],
    ['Activity count', (alert) => alert.event_count],
    ['Count label', (alert) => alert.count_label],
    ['MITRE tactic', (alert) => alert.mitre_tactic],
    ['MITRE technique ID', (alert) => alert.mitre_technique_id],
    ['MITRE technique', (alert) => alert.mitre_technique_name],
    ['First seen', (alert) => alert.first_seen],
    ['Last seen', (alert) => alert.last_seen],
    ['Evidence', (alert) => alert.details?.explanation
      ?? alert.details?.path
      ?? alert.details?.matched_patterns?.join(', ')
      ?? alert.usernames?.join(', ')],
  ]
  const csv = [
    columns.map(([heading]) => csvCell(heading)).join(','),
    ...alerts.map((alert) => columns.map(([, valueFor]) => csvCell(valueFor(alert))).join(',')),
  ].join('\r\n')

  const file = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' })
  const downloadUrl = URL.createObjectURL(file)
  const link = document.createElement('a')
  link.href = downloadUrl
  link.download = `soc-alerts-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(downloadUrl)
}

function downloadMlEvaluationCsv(report) {
  const rows = [
    ['Evaluation time', report.evaluated_at],
    ['Benchmark type', report.benchmark],
    ['Total samples', report.sample_count],
    ['Normal samples', report.normal_count],
    ['Attack samples', report.attack_count],
    ['Precision', report.metrics.precision],
    ['Recall', report.metrics.recall],
    ['F1 score', report.metrics.f1],
    ['False-positive rate', report.metrics.false_positive_rate],
    [],
    ['Attack category', 'Detected samples', 'Total samples', 'Recall'],
    ...Object.entries(report.attack_categories || {}).map(([category, result]) => [
      category.replaceAll('_', ' '),
      result.detected_count,
      result.sample_count,
      result.recall,
    ]),
    [],
    ['Note', report.note],
  ]
  const csv = rows.map((row) => row.map(csvCell).join(',')).join('\r\n')
  const file = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' })
  const downloadUrl = URL.createObjectURL(file)
  const link = document.createElement('a')
  link.href = downloadUrl
  link.download = `ml-evaluation-${new Date().toISOString().slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(downloadUrl)
}

export default function App() {
  const [currentTab, setCurrentTab] = useState('overview')
  const [alerts, setAlerts] = useState([])
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState(null)
  const [mlStatus, setMlStatus] = useState(null)
  const [mlEvaluation, setMlEvaluation] = useState(null)
  const [mlEvaluationLoading, setMlEvaluationLoading] = useState(false)
  const [mlEvaluationError, setMlEvaluationError] = useState('')
  const [copilotAlertId, setCopilotAlertId] = useState('')
  const [copilotAnalysis, setCopilotAnalysis] = useState(null)
  const [copilotLoading, setCopilotLoading] = useState(false)
  const [analystNotes, setAnalystNotes] = useState([])
  const [noteText, setNoteText] = useState('')
  const [notesLoading, setNotesLoading] = useState(false)
  const [noteSaving, setNoteSaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [retraining, setRetraining] = useState(false)
  const [error, setError] = useState('')
  const [actionError, setActionError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // Log explorer filters
  const [logFilterType, setLogFilterType] = useState('')
  const [logSearchQuery, setLogSearchQuery] = useState('')
  const [alertSearchQuery, setAlertSearchQuery] = useState('')
  const [alertSeverityFilter, setAlertSeverityFilter] = useState('')
  const [alertStatusFilter, setAlertStatusFilter] = useState('')

  async function loadAlerts() {
    setLoading(true)
    setError('')
    try {
      const [alertsRes, statsRes, mlRes] = await Promise.all([
        fetch('/api/alerts'),
        fetch('/api/stats'),
        fetch('/api/ml/status'),
      ])
      if (!alertsRes.ok) throw new Error(`Alerts server returned ${alertsRes.status}`)
      const alertsData = await alertsRes.json()
      setAlerts(alertsData.alerts ?? [])

      if (statsRes.ok) {
        const statsData = await statsRes.json()
        setStats(statsData)
      }

      if (mlRes.ok) {
        const mlData = await mlRes.json()
        setMlStatus(mlData)
      }
    } catch (err) {
      setError('Could not load alerts. Check that the Flask backend is running.')
    } finally {
      setLoading(false)
    }
  }

  async function loadLogs() {
    try {
      const params = new URLSearchParams()
      if (logFilterType) params.set('event_type', logFilterType)
      if (logSearchQuery.trim()) params.set('search', logSearchQuery.trim())
      params.set('limit', '100')

      const res = await fetch(`/api/logs?${params.toString()}`)
      if (res.ok) {
        const data = await res.json()
        setLogs(data.events ?? [])
      }
    } catch (err) {
      console.error('Error fetching logs', err)
    }
  }

  async function runDemoAnalysis() {
    setAnalyzing(true)
    setError('')
    setActionError('')
    setSuccessMsg('')
    try {
      const res = await fetch('/api/demo/analyze', { method: 'POST' })
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      const data = await res.json()
      const newAlerts = data.alert_count ?? 0
      const repeatedAlerts = data.duplicate_alert_count ?? 0
      const newAlertText = `${newAlerts} new alert${newAlerts === 1 ? '' : 's'}`
      const repeatedAlertText = repeatedAlerts
        ? `; matched ${repeatedAlerts} already-saved alert${repeatedAlerts === 1 ? '' : 's'}`
        : ''
      setSuccessMsg(`Ingested ${data.event_count} events and saved ${newAlertText}${repeatedAlertText}.`)
      await loadAlerts()
      if (currentTab === 'logs') await loadLogs()
    } catch (err) {
      setActionError(`Analysis execution failed (${err.message}). Check that the Flask backend is running on http://127.0.0.1:5000.`)
    } finally {
      setAnalyzing(false)
    }
  }

  async function handleRetrainModel() {
    setRetraining(true)
    setError('')
    setActionError('')
    setSuccessMsg('')
    try {
      const res = await fetch('/api/ml/train', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_count: 400 }),
      })
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      const data = await res.json()
      setSuccessMsg(`Isolation Forest retrained successfully on ${data.metrics?.training_samples} baseline samples!`)
      await loadAlerts()
    } catch (err) {
      setActionError('ML model training failed.')
    } finally {
      setRetraining(false)
    }
  }

  async function runMlEvaluation() {
    setMlEvaluationLoading(true)
    setMlEvaluationError('')
    try {
      const response = await fetch('/api/ml/evaluation')
      if (!response.ok) throw new Error(`Server returned ${response.status}`)
      setMlEvaluation(await response.json())
    } catch (err) {
      setMlEvaluationError('Could not run the evaluation. Check that the Flask backend is running.')
    } finally {
      setMlEvaluationLoading(false)
    }
  }

  async function loadCopilotAnalysis(alertId) {
    if (!alertId) return
    setCopilotAlertId(alertId)
    setCopilotLoading(true)
    setCopilotAnalysis(null)
    setAnalystNotes([])
    setNotesLoading(true)
    setActionError('')
    try {
      const [analysisResponse, notesResponse] = await Promise.all([
        fetch(`/api/alerts/${alertId}/copilot`),
        fetch(`/api/alerts/${alertId}/notes`),
      ])
      if (!analysisResponse.ok || !notesResponse.ok) throw new Error('Incident data request failed')
      const [analysisData, notesData] = await Promise.all([
        analysisResponse.json(),
        notesResponse.json(),
      ])
      setCopilotAnalysis(analysisData.analysis)
      setAnalystNotes(notesData.notes ?? [])
    } catch (err) {
      setActionError('Could not generate incident analysis. Check that the Flask backend is running.')
    } finally {
      setCopilotLoading(false)
      setNotesLoading(false)
    }
  }

  async function saveAnalystNote(event) {
    event.preventDefault()
    if (!copilotAlertId || !noteText.trim()) return
    setNoteSaving(true)
    setActionError('')
    try {
      const response = await fetch(`/api/alerts/${copilotAlertId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: noteText }),
      })
      if (!response.ok) throw new Error(`Server returned ${response.status}`)
      const data = await response.json()
      setAnalystNotes((current) => [...current, data.note])
      setNoteText('')
    } catch (err) {
      setActionError('Could not save the note. Check that the Flask backend is running.')
    } finally {
      setNoteSaving(false)
    }
  }

  async function updateAlertStatus(alertId, status) {
    setActionError('')
    try {
      const response = await fetch(`/api/alerts/${alertId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      })
      if (!response.ok) throw new Error(`Server returned ${response.status}`)
      setAlerts((current) => current.map((alert) => (
        alert.id === alertId ? { ...alert, status } : alert
      )))
    } catch (err) {
      setActionError('Could not update alert status. Check that the Flask backend is running.')
    }
  }

  useEffect(() => {
    loadAlerts()
  }, [])

  useEffect(() => {
    if (currentTab === 'logs') {
      loadLogs()
    }
  }, [currentTab, logFilterType, logSearchQuery])

  const highOrCriticalCount = alerts.filter((a) => a.severity === 'high' || a.severity === 'critical').length
  const openCount = alerts.filter((a) => a.status === 'open').length
  const mlAnomalyCount = alerts.filter((a) => a.rule === 'ml_behavioral_anomaly').length
  const totalEvents = stats?.total_events ?? (logs.length || 0)
  const normalizedAlertQuery = alertSearchQuery.trim().toLowerCase()
  const filteredAlerts = alerts.filter((alert) => {
    const searchableText = [
      alert.title,
      alert.source_ip,
      alert.rule,
      alert.mitre_technique_id,
      alert.mitre_technique_name,
    ].join(' ').toLowerCase()
    return (!normalizedAlertQuery || searchableText.includes(normalizedAlertQuery))
      && (!alertSeverityFilter || alert.severity === alertSeverityFilter)
      && (!alertStatusFilter || alert.status === alertStatusFilter)
  })

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark">S</div>
        <div className="brand-copy">
          <strong>Sentinel</strong>
          <span>MINI SOC</span>
        </div>

        <div className="side-label">WORKSPACE</div>
        <button
          className={`nav-item ${currentTab === 'overview' ? 'active' : ''}`}
          onClick={() => setCurrentTab('overview')}
        >
          <span className="nav-icon">◫</span> Overview
        </button>
        <button
          className={`nav-item ${currentTab === 'logs' ? 'active' : ''}`}
          onClick={() => setCurrentTab('logs')}
        >
          <span className="nav-icon">▤</span> Log Explorer
          {totalEvents > 0 && <span className="nav-count">{totalEvents}</span>}
        </button>
        <button
          className={`nav-item ${currentTab === 'ml' ? 'active' : ''}`}
          onClick={() => setCurrentTab('ml')}
        >
          <span className="nav-icon">✦</span> AI / ML Engine
        </button>
        <button
          className={`nav-item ${currentTab === 'incidents' ? 'active' : ''}`}
          onClick={() => setCurrentTab('incidents')}
        >
          <span className="nav-icon">◎</span> Incidents & Playbooks
        </button>

        <div className="sidebar-bottom">
          <div className="status-dot" /> Local SOC Environment
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span>{' '}
            <strong>
              {currentTab === 'overview'
                ? 'Threat Overview'
                : currentTab === 'logs'
                ? 'Log Explorer'
                : currentTab === 'ml'
                ? 'AI / ML Anomaly Engine'
                : 'Incidents & Playbooks'}
            </strong>
          </div>
          <div className="topbar-right">
            <span className="live-dot" /> DETECTION & ML ENGINE ACTIVE
            <div className="avatar">SOC</div>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>
              {currentTab === 'overview'
                ? 'Threat Detection Overview'
                : currentTab === 'logs'
                ? 'Security Log Explorer'
                : currentTab === 'ml'
                ? 'AI Anomaly Detection Engine'
                : 'Incident Investigation'}
            </h1>
            <p>
              {currentTab === 'overview'
                ? 'Correlated detection rules, sliding time-windows, and unsupervised ML anomaly detection.'
                : currentTab === 'logs'
                ? 'Search, inspect, and drill-down into ingested authentication and web logs.'
                : currentTab === 'ml'
                ? 'Scikit-Learn Isolation Forest baseline modeling, feature vectors, and anomaly attribution.'
                : 'Review an alert with a clear summary, attacker context, indicators, and response guidance.'}
            </p>
          </div>
          <div className="header-actions">
            <button
              className="primary-button"
              onClick={runDemoAnalysis}
              disabled={analyzing}
            >
              <span>▶</span> {analyzing ? 'Analyzing Logs…' : 'Ingest & Run Analysis'}
            </button>
            <button
              className="refresh-button"
              onClick={() => {
                loadAlerts()
                if (currentTab === 'logs') loadLogs()
              }}
              disabled={loading}
            >
              <span>↻</span> Refresh
            </button>
          </div>
        </section>

        {successMsg && <div className="message success">{successMsg}</div>}
        {error && <div className="message error">{error}</div>}
        {actionError && <div className="message error">{actionError}</div>}

        {/* Overview Tab Content */}
        {currentTab === 'overview' && (
          <>
            <section className="stat-grid" aria-label="Alert summary">
              <article className="stat-card">
                <div className="stat-label">
                  TOTAL ALERTS <span className="stat-symbol">◉</span>
                </div>
                <div className="stat-value">{alerts.length}</div>
                <div className="stat-note">SQLite persistence store</div>
              </article>
              <article className="stat-card">
                <div className="stat-label">
                  OPEN ALERTS <span className="stat-symbol amber">◷</span>
                </div>
                <div className="stat-value">{openCount}</div>
                <div className="stat-note">Awaiting analyst triage</div>
              </article>
              <article className="stat-card">
                <div className="stat-label">
                  AI ANOMALIES <span className="stat-symbol" style={{ color: '#db9bf5' }}>✦</span>
                </div>
                <div className="stat-value">{mlAnomalyCount}</div>
                <div className="stat-note">Isolation Forest outliers</div>
              </article>
              <article className="stat-card">
                <div className="stat-label">
                  CRITICAL / HIGH <span className="stat-symbol red">⬡</span>
                </div>
                <div className="stat-value">{highOrCriticalCount}</div>
                <div className="stat-note">Immediate priority</div>
              </article>
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Active Security Alerts</h2>
                  <p>Rule findings mapped to MITRE ATT&CK techniques & AI Behavioral Anomalies</p>
                </div>
                <span className="result-count">{filteredAlerts.length} / {alerts.length} ALERTS</span>
              </div>

              <div className="alert-filter-bar" role="search" aria-label="Filter security alerts">
                <input
                  type="search"
                  className="filter-input"
                  placeholder="Search title, IP, rule, or MITRE…"
                  aria-label="Search alerts"
                  value={alertSearchQuery}
                  onChange={(event) => setAlertSearchQuery(event.target.value)}
                />
                <select
                  className="filter-select"
                  aria-label="Filter alerts by severity"
                  value={alertSeverityFilter}
                  onChange={(event) => setAlertSeverityFilter(event.target.value)}
                >
                  <option value="">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  className="filter-select"
                  aria-label="Filter alerts by status"
                  value={alertStatusFilter}
                  onChange={(event) => setAlertStatusFilter(event.target.value)}
                >
                  <option value="">All statuses</option>
                  <option value="open">Open</option>
                  <option value="acknowledged">Acknowledged</option>
                  <option value="resolved">Resolved</option>
                </select>
                {(alertSearchQuery || alertSeverityFilter || alertStatusFilter) && (
                  <button
                    className="clear-filter-button"
                    onClick={() => {
                      setAlertSearchQuery('')
                      setAlertSeverityFilter('')
                      setAlertStatusFilter('')
                    }}
                  >
                    Clear filters
                  </button>
                )}
                <button
                  className="export-button"
                  onClick={() => downloadAlertsCsv(filteredAlerts)}
                  disabled={filteredAlerts.length === 0}
                >
                  ↓ Export CSV ({filteredAlerts.length})
                </button>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>THREAT & MITRE ATT&CK</th>
                      <th>SEVERITY</th>
                      <th>SOURCE IP</th>
                      <th>ACTIVITY BURST</th>
                      <th>EVIDENCE & ATTRIBUTION</th>
                      <th>ANALYST STATUS</th>
                      <th>LAST DETECTED</th>
                    </tr>
                  </thead>
                  <tbody>
                    {loading ? (
                      <tr>
                        <td className="empty-state" colSpan="7">
                          Loading alerts…
                        </td>
                      </tr>
                    ) : alerts.length === 0 ? (
                      <tr>
                        <td className="empty-state" colSpan="7">
                          No alerts recorded yet. Click <strong>"Ingest & Run Analysis"</strong> above to test detections!
                        </td>
                      </tr>
                    ) : filteredAlerts.length === 0 ? (
                      <tr>
                        <td className="empty-state" colSpan="7">
                          No alerts match these filters. Clear the filters or try a different search.
                        </td>
                      </tr>
                    ) : (
                      filteredAlerts.map((alert) => (
                        <tr key={alert.id}>
                          <td>
                            <div className="alert-title">{alert.title}</div>
                            <div className="alert-meta">
                              {alert.rule === 'ml_behavioral_anomaly' ? (
                                <span className="ai-badge">✦ AI ANOMALY</span>
                              ) : (
                                <span className="alert-subtitle">
                                  {alert.rule.replaceAll('_', ' ')}
                                </span>
                              )}
                              {alert.mitre_technique_id && alert.mitre_technique_id !== 'N/A' && (
                                <a
                                  href={alert.mitre_url || `https://attack.mitre.org/techniques/${alert.mitre_technique_id.replace('.', '/')}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="mitre-badge"
                                  title={`${alert.mitre_technique_name} (${alert.mitre_tactic})`}
                                >
                                  ⚔ {alert.mitre_technique_id}
                                </a>
                              )}
                            </div>
                          </td>
                          <td>
                            <span className={`severity ${alert.severity}`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td className="mono">{alert.source_ip}</td>
                          <td>
                            {alert.rule === 'ml_behavioral_anomaly' ? (
                              <span className="confidence-pill">{alert.event_count}% CONFIDENCE</span>
                            ) : (
                              <span className="attempt-count">
                                {alert.event_count} {alert.count_label}
                              </span>
                            )}
                          </td>
                          <td className="evidence-cell">
                            {alert.details?.explanation
                              ? alert.details.explanation
                              : alert.details?.path ??
                                alert.details?.matched_patterns?.join(', ').replaceAll('_', ' ') ??
                                (alert.usernames?.length
                                  ? `Users: ${alert.usernames.join(', ')}`
                                  : '—')}
                          </td>
                          <td>
                            <select
                              className={`status-select ${alert.status}`}
                              aria-label={`Status for ${alert.title}`}
                              value={alert.status}
                              onChange={(event) => updateAlertStatus(alert.id, event.target.value)}
                            >
                              <option value="open">Open</option>
                              <option value="acknowledged">Acknowledged</option>
                              <option value="resolved">Resolved</option>
                            </select>
                          </td>
                          <td className="date-cell">{formatDate(alert.last_seen)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              <div className="panel-footer">
                <span>
                  <span className="footer-dot" /> Live correlation & ML engine active
                </span>
                <span>SQLite Store • Scikit-Learn Isolation Forest</span>
              </div>
            </section>
          </>
        )}

        {/* Log Explorer Tab Content */}
        {currentTab === 'logs' && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Security Log Explorer</h2>
                <p>Filter and inspect raw security events stored in database</p>
              </div>
              <span className="result-count">{logs.length} LOGS RETRIEVED</span>
            </div>

            <div className="filter-bar">
              <input
                type="text"
                className="filter-input"
                placeholder="Search IP, username, or path…"
                value={logSearchQuery}
                onChange={(e) => setLogSearchQuery(e.target.value)}
              />
              <select
                className="filter-select"
                value={logFilterType}
                onChange={(e) => setLogFilterType(e.target.value)}
              >
                <option value="">All Event Types</option>
                <option value="login">Authentication (login)</option>
                <option value="web_request">Web Requests (web_request)</option>
              </select>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>TIMESTAMP</th>
                    <th>TYPE</th>
                    <th>SOURCE IP</th>
                    <th>USER / METHOD</th>
                    <th>TARGET / PATH</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td className="empty-state" colSpan="6">
                        No logs match current filters. Click "Ingest & Run Analysis" to load synthetic data.
                      </td>
                    </tr>
                  ) : (
                    logs.map((log) => (
                      <tr key={log.id}>
                        <td className="date-cell">{formatDate(log.timestamp)}</td>
                        <td>
                          <span className={`badge ${log.event_type === 'login' ? 'login' : 'web'}`}>
                            {log.event_type}
                          </span>
                        </td>
                        <td className="mono">{log.source_ip}</td>
                        <td className="mono">{log.username || log.method || '—'}</td>
                        <td className="evidence-cell">{log.path || (log.username ? `Auth: ${log.username}` : '—')}</td>
                        <td>
                          {log.event_type === 'login' ? (
                            <span className={`badge ${log.success ? 'status-ok' : 'status-err'}`}>
                              {log.success ? 'SUCCESS' : 'FAILED'}
                            </span>
                          ) : (
                            <span className={`badge ${log.status_code < 400 ? 'status-ok' : 'status-err'}`}>
                              HTTP {log.status_code}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="panel-footer">
              <span>
                <span className="footer-dot" /> Showing top {logs.length} events
              </span>
              <span>Raw JSON payloads indexed</span>
            </div>
          </section>
        )}

        {/* AI / ML Engine Tab Content */}
        {currentTab === 'ml' && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>AI Anomaly Detection Engine (UEBA)</h2>
                <p>Unsupervised Machine Learning model status, baseline configuration & XAI feature weights</p>
              </div>
              <button
                className="primary-button"
                onClick={handleRetrainModel}
                disabled={retraining}
              >
                <span>✦</span> {retraining ? 'Retraining Model…' : 'Retrain Isolation Forest'}
              </button>
            </div>

            <div style={{ padding: '20px' }}>
              <div className="model-info-grid">
                <div className="model-card">
                  <h3>Algorithm & Status</h3>
                  <p><strong>Model:</strong> {mlStatus?.model_name || 'Isolation Forest'}</p>
                  <p><strong>Status:</strong> {mlStatus?.is_trained ? 'Active & In-Memory' : 'Untrained'}</p>
                  <p><strong>Expected Contamination:</strong> {(mlStatus?.contamination ?? 0.08) * 100}%</p>
                </div>
                <div className="model-card">
                  <h3>Behavioral Profiling</h3>
                  <p><strong>Baseline Domain:</strong> Daytime corporate authentication & standard REST APIs</p>
                  <p><strong>Scoring:</strong> Decision distance mapped to 0-100% anomaly confidence</p>
                </div>
                <div className="model-card">
                  <h3>Explainable AI (XAI)</h3>
                  <p>Identifies exact feature z-score deviations behind each anomaly to eliminate black-box alert fatigue.</p>
                </div>
              </div>

              <div className="model-card">
                <h3>Extracted Feature Dimensions (7D Vector)</h3>
                <p>Every event is converted into a continuous multidimensional behavioral vector:</p>
                <div className="feature-chip-list">
                  {(mlStatus?.features || [
                    'hour_normalized',
                    'is_off_hours',
                    'is_failure_or_error',
                    'payload_length',
                    'endpoint_depth',
                    'suspicious_char_ratio',
                    'ip_burst_velocity',
                  ]).map((feat) => (
                    <span key={feat} className="feature-chip">
                      {feat}
                    </span>
                  ))}
                </div>
              </div>

              <section className="model-evaluation">
                <div className="evaluation-heading">
                  <div>
                    <h3>Synthetic Model Evaluation</h3>
                    <p>Compare model predictions with labeled normal and attack examples.</p>
                  </div>
                  <button className="refresh-button" onClick={runMlEvaluation} disabled={mlEvaluationLoading}>
                    {mlEvaluationLoading ? 'Evaluating…' : 'Run evaluation'}
                  </button>
                </div>
                {mlEvaluationError && <p className="evaluation-error">{mlEvaluationError}</p>}
                {mlEvaluation ? (
                  <>
                    <div className="evaluation-metrics">
                      {[
                        ['Precision', mlEvaluation.metrics.precision],
                        ['Recall', mlEvaluation.metrics.recall],
                        ['F1 score', mlEvaluation.metrics.f1],
                        ['False-positive rate', mlEvaluation.metrics.false_positive_rate],
                      ].map(([label, value]) => (
                        <div className="evaluation-metric" key={label}>
                          <span>{label}</span><strong>{(value * 100).toFixed(1)}%</strong>
                        </div>
                      ))}
                    </div>
                    <p className="evaluation-counts">
                      {mlEvaluation.normal_count} normal + {mlEvaluation.attack_count} attack samples ·
                      TP {mlEvaluation.confusion_matrix.true_positive}, FP {mlEvaluation.confusion_matrix.false_positive},
                      TN {mlEvaluation.confusion_matrix.true_negative}, FN {mlEvaluation.confusion_matrix.false_negative}
                    </p>
                    <div className="evaluation-category-grid" aria-label="Results by attack category">
                      {Object.entries(mlEvaluation.attack_categories || {}).map(([category, result]) => (
                        <div className="evaluation-category" key={category}>
                          <span>{category.replaceAll('_', ' ')}</span>
                          <strong>{(result.recall * 100).toFixed(0)}% detected</strong>
                          <small>{result.detected_count} of {result.sample_count} samples</small>
                        </div>
                      ))}
                    </div>
                    <p className="evaluation-caveat">{mlEvaluation.note}</p>
                    <button className="export-button evaluation-export" onClick={() => downloadMlEvaluationCsv(mlEvaluation)}>
                      ↓ Export evaluation CSV
                    </button>
                  </>
                ) : !mlEvaluationError && <p className="evaluation-caveat">Run the benchmark to see how the current model scores.</p>}
              </section>
            </div>

            <div className="panel-footer">
              <span>
                <span className="footer-dot" style={{ background: '#db9bf5' }} /> Model: Scikit-Learn IsolationForest
              </span>
              <span>Serialized via Joblib</span>
            </div>
          </section>
        )}

        {currentTab === 'incidents' && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>SOC Analyst Copilot</h2>
                <p>Template-based triage guidance generated from a saved alert</p>
              </div>
              <span className="result-count">{alerts.length} ALERTS AVAILABLE</span>
            </div>

            {alerts.length === 0 ? (
              <div className="incident-empty">
                No saved alerts yet. Go to Overview and click <strong>Ingest & Run Analysis</strong> first.
              </div>
            ) : (
              <div className="incident-content">
                <label className="incident-label" htmlFor="incident-alert">Choose an alert to investigate</label>
                <div className="incident-picker">
                  <select
                    id="incident-alert"
                    className="filter-select incident-select"
                    value={copilotAlertId}
                    onChange={(event) => loadCopilotAnalysis(event.target.value)}
                  >
                    <option value="">Select a saved alert…</option>
                    {alerts.map((alert) => (
                      <option key={alert.id} value={alert.id}>
                        [{alert.severity.toUpperCase()}] {alert.title} — {alert.source_ip}
                      </option>
                    ))}
                  </select>
                  <button
                    className="primary-button"
                    disabled={!copilotAlertId || copilotLoading}
                    onClick={() => loadCopilotAnalysis(copilotAlertId)}
                  >
                    {copilotLoading ? 'Preparing analysis…' : 'Generate analysis'}
                  </button>
                </div>

                {copilotLoading && <div className="incident-empty">Generating a report from the selected alert…</div>}
                {copilotAnalysis && (
                  <div className="incident-report">
                    {copilotAnalysis.confidence_note && (
                      <div className="copilot-note">{copilotAnalysis.confidence_note}</div>
                    )}
                    <div className="model-info-grid">
                      <article className="model-card incident-summary">
                        <h3>Incident summary</h3>
                        <p>{copilotAnalysis.executive_summary}</p>
                      </article>
                      <article className="model-card">
                        <h3>Attacker context</h3>
                        <p>{copilotAnalysis.adversary_intent}</p>
                        <p className="incident-kill-chain"><strong>Kill-chain stage:</strong> {copilotAnalysis.kill_chain_stage}</p>
                      </article>
                      <article className="model-card">
                        <h3>MITRE ATT&CK</h3>
                        <p><strong>{copilotAnalysis.mitre_technique_id || 'Not mapped'}</strong> {copilotAnalysis.mitre_technique_name}</p>
                        <p>{copilotAnalysis.mitre_tactic || 'Tactic not provided'}</p>
                      </article>
                    </div>

                    <div className="model-info-grid incident-detail-grid">
                      <article className="model-card">
                        <h3>Suggested response steps</h3>
                        <ol className="playbook-list">
                          {copilotAnalysis.remediation_playbook.map((step, index) => (
                            <li key={`${index}-${step}`} className={step.startsWith('#') ? 'playbook-heading' : ''}>
                              {step || '\u00a0'}
                            </li>
                          ))}
                        </ol>
                      </article>
                      <article className="model-card">
                        <h3>Indicators to review</h3>
                        {copilotAnalysis.ioc_list.length ? (
                          <ul className="ioc-list">
                            {copilotAnalysis.ioc_list.map((ioc, index) => (
                              <li key={`${ioc.type}-${index}`}>
                                <span>{ioc.type}</span>
                                <code>{ioc.value}</code>
                                {ioc.context && <small>{ioc.context}</small>}
                              </li>
                            ))}
                          </ul>
                        ) : <p>No indicators were included in this alert.</p>}
                      </article>
                    </div>
                    <section className="notes-panel">
                      <div className="notes-heading">
                        <div>
                          <h3>Analyst investigation notes</h3>
                          <p>Record observations and follow-up actions for this alert.</p>
                        </div>
                        <span className="result-count">{analystNotes.length} NOTES</span>
                      </div>
                      <form className="note-form" onSubmit={saveAnalystNote}>
                        <textarea
                          value={noteText}
                          onChange={(event) => setNoteText(event.target.value)}
                          placeholder="Example: Checked the related logs; no successful login found."
                          maxLength={2000}
                          aria-label="Write an investigation note"
                        />
                        <div className="note-form-footer">
                          <span>{noteText.length}/2000 characters</span>
                          <button className="primary-button" type="submit" disabled={!noteText.trim() || noteSaving}>
                            {noteSaving ? 'Saving note…' : 'Save note'}
                          </button>
                        </div>
                      </form>
                      {notesLoading ? (
                        <p className="notes-empty">Loading saved notes…</p>
                      ) : analystNotes.length === 0 ? (
                        <p className="notes-empty">No notes for this alert yet.</p>
                      ) : (
                        <ol className="notes-list">
                          {analystNotes.map((note) => (
                            <li key={note.id}>
                              <p>{note.note}</p>
                              <time dateTime={note.created_at}>{formatDate(note.created_at)}</time>
                            </li>
                          ))}
                        </ol>
                      )}
                    </section>
                    <p className="generated-at">Report generated {formatDate(copilotAnalysis.generated_at)} • Guidance is for analyst review.</p>
                  </div>
                )}
              </div>
            )}
            <div className="panel-footer">
              <span><span className="footer-dot" /> Uses saved alert details</span>
              <span>Local deterministic analysis • No external AI service</span>
            </div>
          </section>
        )}

        <footer className="page-footer">
          SENTINEL MINI SOC <span>•</span> THREAT DETECTION & INCIDENT RESPONSE PLATFORM
        </footer>
      </main>
    </div>
  )
}
