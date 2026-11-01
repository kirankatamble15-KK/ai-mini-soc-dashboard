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
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
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
      const [alertsRes, statsRes] = await Promise.all([
        fetch('/api/alerts'),
        fetch('/api/stats'),
      ])
      if (!alertsRes.ok) throw new Error(`Alerts server returned ${alertsRes.status}`)
      const alertsData = await alertsRes.json()
      setAlerts(alertsData.alerts ?? [])

      if (statsRes.ok) {
        const statsData = await statsRes.json()
        setStats(statsData)
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
      setSuccessMsg(`Ingested ${data.event_count} events and generated ${data.alert_count} alerts!`)
      await loadAlerts()
      if (currentTab === 'logs') await loadLogs()
    } catch (err) {
      setActionError('Analysis execution failed. Check backend console.')
    } finally {
      setAnalyzing(false)
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
  const detectionRuleCount = new Set(alerts.map((a) => a.rule)).size || 4
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
          className={`nav-item ${currentTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setCurrentTab('overview')}
        >
          <span className="nav-icon">⌁</span> Alerts
          <span className="nav-count">{alerts.length}</span>
        </button>
        <button
          className={`nav-item ${currentTab === 'logs' ? 'active' : ''}`}
          onClick={() => setCurrentTab('logs')}
        >
          <span className="nav-icon">▤</span> Log Explorer
          {totalEvents > 0 && <span className="nav-count">{totalEvents}</span>}
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
            <strong>{currentTab === 'overview' ? 'Threat Overview' : 'Log Explorer'}</strong>
          </div>
          <div className="topbar-right">
            <span className="live-dot" /> DETECTION ENGINE ACTIVE
            <div className="avatar">SOC</div>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>{currentTab === 'overview' ? 'Threat Detection Overview' : 'Security Log Explorer'}</h1>
            <p>
              {currentTab === 'overview'
                ? 'Correlated detection rules, sliding time-windows & MITRE ATT&CK taxonomy.'
                : 'Search, inspect, and drill-down into ingested authentication and web logs.'}
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
                  CRITICAL / HIGH <span className="stat-symbol red">⬡</span>
                </div>
                <div className="stat-value">{highOrCriticalCount}</div>
                <div className="stat-note">Immediate priority</div>
              </article>
              <article className="stat-card">
                <div className="stat-label">
                  TOTAL LOGS INGESTED <span className="stat-symbol blue">⌘</span>
                </div>
                <div className="stat-value">{String(totalEvents).padStart(2, '0')}</div>
                <div className="stat-note">Normalized security events</div>
              </article>
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Active Security Alerts</h2>
                  <p>Rule findings mapped to MITRE ATT&CK techniques with time-window correlation</p>
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
                      <th>EVIDENCE & PAYLOAD</th>
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
                              <span className="alert-subtitle">
                                {alert.rule.replaceAll('_', ' ')}
                              </span>
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
                          <td className="attempt-count">
                            {alert.event_count} {alert.count_label}
                          </td>
                          <td className="evidence-cell">
                            {alert.details?.path ??
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
                  <span className="footer-dot" /> Live correlation engine active
                </span>
                <span>SQLite Store • MITRE ATT&CK v14</span>
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

        <footer className="page-footer">
          SENTINEL MINI SOC <span>•</span> THREAT DETECTION & INCIDENT RESPONSE PLATFORM
        </footer>
      </main>
    </div>
  )
}
