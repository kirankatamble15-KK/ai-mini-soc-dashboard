import { useEffect, useState } from 'react'

function formatDate(value) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function loadAlerts() {
    setLoading(true)
    setError('')
    try {
      const response = await fetch('/api/alerts')
      if (!response.ok) throw new Error(`Server returned ${response.status}`)
      const data = await response.json()
      setAlerts(data.alerts ?? [])
    } catch (err) {
      setError('Could not load alerts. Check that the Flask backend is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAlerts()
  }, [])

  const highCount = alerts.filter((alert) => alert.severity === 'high').length
  const openCount = alerts.filter((alert) => alert.status === 'open').length

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark">S</div>
        <div className="brand-copy"><strong>Sentinel</strong><span>MINI SOC</span></div>
        <div className="side-label">WORKSPACE</div>
        <div className="nav-item active"><span className="nav-icon">◫</span> Overview</div>
        <div className="nav-item"><span className="nav-icon">⌁</span> Alerts <span className="nav-count">{alerts.length}</span></div>
        <div className="nav-item muted"><span className="nav-icon">▤</span> Log explorer</div>
        <div className="nav-item muted"><span className="nav-icon">◎</span> Incidents</div>
        <div className="sidebar-bottom"><div className="status-dot" /> Local demo environment</div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> <strong>Overview</strong></div>
          <div className="topbar-right"><span className="live-dot" /> SYSTEM ONLINE <div className="avatar">A</div></div>
        </header>

        <section className="page-heading">
          <div><div className="eyebrow">SECURITY OPERATIONS</div><h1>Overview</h1><p>Monitor detection activity across your environment.</p></div>
          <button className="refresh-button" onClick={loadAlerts} disabled={loading}><span>↻</span> Refresh data</button>
        </section>

        <section className="stat-grid" aria-label="Alert summary">
          <article className="stat-card"><div className="stat-label">TOTAL ALERTS <span className="stat-symbol">◉</span></div><div className="stat-value">{alerts.length}</div><div className="stat-note">Saved in local database</div></article>
          <article className="stat-card"><div className="stat-label">OPEN ALERTS <span className="stat-symbol amber">◷</span></div><div className="stat-value">{openCount}</div><div className="stat-note">Require analyst review</div></article>
          <article className="stat-card"><div className="stat-label">HIGH SEVERITY <span className="stat-symbol red">⬡</span></div><div className="stat-value">{highCount}</div><div className="stat-note">Across saved alerts</div></article>
          <article className="stat-card"><div className="stat-label">DETECTION RULES <span className="stat-symbol blue">⌘</span></div><div className="stat-value">01</div><div className="stat-note">Rule-based monitoring</div></article>
        </section>

        <section className="panel">
          <div className="panel-heading"><div><h2>Recent alerts</h2><p>Detection results generated from your log data</p></div><span className="result-count">{alerts.length} RECORD{alerts.length === 1 ? '' : 'S'}</span></div>
          {error && <div className="message error">{error}</div>}
          <div className="table-wrap">
            <table>
              <thead><tr><th>ALERT</th><th>SEVERITY</th><th>SOURCE IP</th><th>ATTEMPTS</th><th>STATUS</th><th>LAST SEEN</th></tr></thead>
              <tbody>
                {loading ? <tr><td className="empty-state" colSpan="6">Loading alerts…</td></tr> : alerts.length === 0 ? <tr><td className="empty-state" colSpan="6">No saved alerts yet. Run the sample analysis to populate this dashboard.</td></tr> : alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td><div className="alert-title">{alert.title}</div><div className="alert-subtitle">Rule: {alert.rule.replaceAll('_', ' ')}</div></td>
                    <td><span className={`severity ${alert.severity}`}>{alert.severity}</span></td>
                    <td className="mono">{alert.source_ip}</td>
                    <td className="attempt-count">{alert.failed_attempts}</td>
                    <td><span className="status"><span />{alert.status}</span></td>
                    <td className="date-cell">{formatDate(alert.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer"><span><span className="footer-dot" /> Data from local SQLite store</span><span>Auto-refresh is off</span></div>
        </section>
        <footer className="page-footer">SENTINEL MINI SOC <span>•</span> EDUCATIONAL SECURITY PROJECT</footer>
      </main>
    </div>
  )
}
