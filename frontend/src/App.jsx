import { useEffect, useState } from 'react'

function formatDate(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

export default function App() {
  const [currentTab, setCurrentTab] = useState('overview')
  const [alerts, setAlerts] = useState([])
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState(null)
  const [mlStatus, setMlStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [retraining, setRetraining] = useState(false)
  const [error, setError] = useState('')
  const [actionError, setActionError] = useState('')
  const [successMsg, setSuccessMsg] = useState('')

  // Log explorer filters
  const [logFilterType, setLogFilterType] = useState('')
  const [logSearchQuery, setLogSearchQuery] = useState('')

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
      setSuccessMsg(`Ingested ${data.event_count} events and generated ${data.alert_count} alerts (Rule-based & AI Anomaly)!`)
      await loadAlerts()
      if (currentTab === 'logs') await loadLogs()
    } catch (err) {
      setActionError('Analysis execution failed. Check backend console.')
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
        <div className="nav-item muted" title="Coming in next sprint">
          <span className="nav-icon">◎</span> Incidents & Playbooks
        </div>

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
                : 'AI / ML Anomaly Engine'}
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
                : 'AI Anomaly Detection Engine'}
            </h1>
            <p>
              {currentTab === 'overview'
                ? 'Correlated detection rules, sliding time-windows, and unsupervised ML anomaly detection.'
                : currentTab === 'logs'
                ? 'Search, inspect, and drill-down into ingested authentication and web logs.'
                : 'Scikit-Learn Isolation Forest baseline modeling, feature vectors, and anomaly attribution.'}
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
                <span className="result-count">{alerts.length} ALERTS</span>
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
                    ) : (
                      alerts.map((alert) => (
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
            </div>

            <div className="panel-footer">
              <span>
                <span className="footer-dot" style={{ background: '#db9bf5' }} /> Model: Scikit-Learn IsolationForest
              </span>
              <span>Serialized via Joblib</span>
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
