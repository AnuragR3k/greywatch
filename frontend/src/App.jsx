import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

function formatTime(value) {
  if (!value) return '—'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function label(value = '') {
  return value.replaceAll('_', ' ')
}

function EventTable({ events }) {
  if (!events.length) {
    return (
      <div className="empty-state">
        <span className="empty-icon">⌁</span>
        <strong>No events found</strong>
        <p>Events will appear here when Greywatch receives log data.</p>
      </div>
    )
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>EVENT</th>
            <th>HOST</th>
            <th>USERNAME</th>
            <th>SOURCE IP</th>
            <th>SEVERITY</th>
            <th>TIMESTAMP</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>
                <div className="event-name">
                  <span className={`event-dot ${event.severity}`} />
                  {label(event.event_type)}
                </div>
              </td>
              <td>{event.host || '—'}</td>
              <td>{event.username || '—'}</td>
              <td className="mono">{event.source_ip || '—'}</td>
              <td>
                <span className={`severity ${event.severity}`}>
                  {event.severity || 'unknown'}
                </span>
              </td>
              <td className="muted">{formatTime(event.timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertList({ alerts, onClose, closingId }) {
  if (!alerts.length) {
    return (
      <div className="empty-state">
        <span className="empty-icon">✓</span>
        <strong>No alerts in this view</strong>
        <p>Greywatch has no matching alerts to display.</p>
      </div>
    )
  }

  return (
    <div className="alert-list">
      {alerts.map((alert) => (
        <article className="alert-item" key={alert.id}>
          <div className="alert-symbol">!</div>

          <div className="alert-content">
            <div className="alert-heading">
              <span className={`severity ${alert.severity}`}>
                {alert.severity}
              </span>
              <span className="mono alert-rule">{alert.rule_id}</span>
              <span className={`status ${alert.status}`}>
                {alert.status}
              </span>
            </div>

            <h3>{alert.title}</h3>
            <p>{alert.description}</p>

            <div className="alert-meta">
              <span>Source: <b className="mono">{alert.source_ip}</b></span>
              <span>Events: <b>{alert.event_count}</b></span>
              <span>{formatTime(alert.created_at)}</span>
            </div>
          </div>

          {alert.status === 'open' && (
            <button
              className="button button-subtle resolve-button"
              disabled={closingId === alert.id}
              onClick={() => onClose(alert.id)}
            >
              {closingId === alert.id ? 'Saving…' : 'Resolve'}
            </button>
          )}
        </article>
      ))}
    </div>
  )
}

function App() {
  const [data, setData] = useState({
    events: [],
    alerts: [],
    health: null,
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [activeView, setActiveView] = useState('overview')
  const [lastUpdated, setLastUpdated] = useState(null)
  const [closingId, setClosingId] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const responses = await Promise.all([
        fetch('/api/v1/events?limit=100'),
        fetch('/api/v1/alerts?status=all&limit=100'),
        fetch('/health'),
      ])

      if (responses.some((response) => !response.ok)) {
        throw new Error('The API returned an unsuccessful response.')
      }

      const [eventData, alertData, health] = await Promise.all(
        responses.map((response) => response.json()),
      )

      setData({
        events: eventData.events ?? [],
        alerts: alertData.alerts ?? [],
        health,
      })
      setLastUpdated(new Date())
      setError('')
    } catch (err) {
      setError(
        'Cannot reach the Greywatch API. Check that FastAPI is running on port 8000.',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 10000)

    return () => window.clearInterval(timer)
  }, [refresh])

  const openAlerts = data.alerts.filter(
    (alert) => alert.status === 'open',
  )

  const failedLogins = data.events.filter(
    (event) => event.event_type === 'ssh_login_failed',
  )

  const hosts = new Set(
    data.events.map((event) => event.host).filter(Boolean),
  )

  const distribution = useMemo(() => {
    const counts = {}

    for (const event of data.events) {
      counts[event.event_type] = (counts[event.event_type] || 0) + 1
    }

    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
  }, [data.events])

  const filteredEvents = useMemo(() => {
    const term = query.trim().toLowerCase()

    if (!term) return data.events

    return data.events.filter((event) =>
      [
        event.event_type,
        event.host,
        event.username,
        event.source_ip,
        event.severity,
      ]
        .filter(Boolean)
        .some((value) => value.toLowerCase().includes(term)),
    )
  }, [data.events, query])

  const filteredAlerts = useMemo(() => {
    const term = query.trim().toLowerCase()

    if (!term) return data.alerts

    return data.alerts.filter((alert) =>
      [
        alert.title,
        alert.rule_id,
        alert.source_ip,
        alert.severity,
        alert.status,
        alert.description,
      ]
        .filter(Boolean)
        .some((value) => value.toLowerCase().includes(term)),
    )
  }, [data.alerts, query])

  async function closeAlert(id) {
    setClosingId(id)

    try {
      const response = await fetch(`/api/v1/alerts/${id}/close`, {
        method: 'POST',
      })

      if (!response.ok) {
        throw new Error('Could not resolve this alert.')
      }

      await refresh()
    } catch (err) {
      setError(err.message || 'Failed to resolve alert.')
    } finally {
      setClosingId(null)
    }
  }

  const connected = data.health?.status === 'ok'

  const titles = {
    overview: ['Security overview', 'A live view of your security telemetry.'],
    events: ['Security events', 'Review normalized authentication events.'],
    alerts: ['Alert investigation', 'Review and resolve detected security alerts.'],
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">G<span>.</span></div>
          <div>
            <div className="brand-name">greywatch</div>
            <div className="brand-caption">SECURITY OPERATIONS</div>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav className="navigation">
          {[
            ['overview', '◫', 'Overview'],
            ['events', '⌁', 'Security events'],
            ['alerts', '⚑', 'Alerts', openAlerts.length],
          ].map(([view, icon, title, count]) => (
            <button
              className={`nav-item ${activeView === view ? 'active' : ''}`}
              key={view}
              onClick={() => {
                setActiveView(view)
                setQuery('')
              }}
            >
              <span className="nav-icon">{icon}</span>
              <span>{title}</span>
              {count > 0 && <span className="nav-count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-row">
            <span className={`connection-dot ${connected ? 'online' : ''}`} />
            <span>{connected ? 'API connected' : 'API unavailable'}</span>
          </div>
          <div className="sidebar-version">GREYWATCH · v0.1.0</div>
          <div className="sidebar-version">Local development build</div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumb">
            GREYWATCH <span>/</span> {activeView.toUpperCase()}
          </div>
          <div className="topbar-right">
            <span className="live-indicator">
              <span className="connection-dot online" />
              POLLING EVERY 10S
            </span>
            <button
              className="button button-refresh"
              onClick={refresh}
              disabled={loading}
            >
              ↻ <span>Refresh</span>
            </button>
          </div>
        </header>

        <section className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY MONITORING</div>
              <h1>{titles[activeView][0]}</h1>
              <p>{titles[activeView][1]}</p>
            </div>
            <div className="updated">
              <span className="updated-dot" />
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : 'Waiting for data'}
            </div>
          </div>

          {error && <div className="error-banner">{error}</div>}

          <div className="metric-grid">
            <article className="metric-card">
              <div className="metric-label">RECENT EVENTS <span>⌁</span></div>
              <div className="metric-value">{data.events.length}</div>
              <div className="metric-foot">Latest 100 events available</div>
            </article>

            <article className="metric-card">
              <div className="metric-label">OPEN ALERTS <span>⚑</span></div>
              <div className="metric-value">{openAlerts.length}</div>
              <div className="metric-foot">
                <span className={openAlerts.length ? 'text-orange' : 'text-green'}>
                  {openAlerts.length ? 'Needs review' : 'All clear'}
                </span>
                {' '}in the current alert list
              </div>
            </article>

            <article className="metric-card">
              <div className="metric-label">FAILED SSH LOGINS <span>⌑</span></div>
              <div className="metric-value">{failedLogins.length}</div>
              <div className="metric-foot">Within the recent event list</div>
            </article>

            <article className="metric-card">
              <div className="metric-label">HOSTS OBSERVED <span>▦</span></div>
              <div className="metric-value">{hosts.size}</div>
              <div className="metric-foot">Distinct hosts in recent events</div>
            </article>
          </div>

          <div className="toolbar">
            <div>
              <h2>
                {activeView === 'alerts'
                  ? 'Alert queue'
                  : activeView === 'events'
                    ? 'Event stream'
                    : 'Security activity'}
              </h2>
              <p>Normalized telemetry collected by Greywatch</p>
            </div>

            <div className="search-box">
              <span>⌕</span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search events, IPs, users…"
              />
              {query && (
                <button className="clear-search" onClick={() => setQuery('')}>
                  ×
                </button>
              )}
            </div>
          </div>

          {activeView === 'overview' && (
            <div className="overview-grid">
              <section className="panel activity-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Event distribution</h3>
                    <p>By event type in the recent event list</p>
                  </div>
                  <span className="panel-icon">▥</span>
                </div>

                {distribution.length ? (
                  <div className="distribution-list">
                    {distribution.map(([type, count]) => {
                      const max = Math.max(...distribution.map((item) => item[1]))

                      return (
                        <div className="distribution-item" key={type}>
                          <div className="distribution-label">
                            <span>{label(type)}</span>
                            <b>{count}</b>
                          </div>
                          <div className="bar-track">
                            <div
                              className="bar-fill"
                              style={{ width: `${(count / max) * 100}%` }}
                            />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="empty-state compact">
                    <strong>{loading ? 'Loading events…' : 'No events yet'}</strong>
                    <p>Ingest log data to populate this panel.</p>
                  </div>
                )}

                <div className="panel-foot">
                  <span className="connection-dot online" />
                  Based on the latest {data.events.length} events
                </div>
              </section>

              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h3>Priority alerts</h3>
                    <p>Open items that need attention</p>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => setActiveView('alerts')}
                  >
                    View all →
                  </button>
                </div>
                <AlertList
                  alerts={openAlerts.slice(0, 4)}
                  onClose={closeAlert}
                  closingId={closingId}
                />
              </section>
            </div>
          )}

          {activeView === 'events' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h3>Normalized events</h3>
                  <p>{filteredEvents.length} matching events</p>
                </div>
              </div>
              <EventTable events={filteredEvents} />
            </section>
          )}

          {activeView === 'alerts' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h3>All alerts</h3>
                  <p>{filteredAlerts.length} matching alerts, open and resolved</p>
                </div>
              </div>
              <AlertList
                alerts={filteredAlerts}
                onClose={closeAlert}
                closingId={closingId}
              />
            </section>
          )}

          {activeView === 'overview' && (
            <section className="panel recent-panel">
              <div className="panel-heading">
                <div>
                  <h3>Recent events</h3>
                  <p>Latest normalized activity from your environment</p>
                </div>
                <button
                  className="text-button"
                  onClick={() => setActiveView('events')}
                >
                  Explore events →
                </button>
              </div>
              {loading && !data.events.length ? (
                <div className="loading-state">Connecting to Greywatch API…</div>
              ) : (
                <EventTable events={filteredEvents.slice(0, 8)} />
              )}
            </section>
          )}

          <footer className="page-footer">
            <span>GREYWATCH SIEM</span>
            <span>Open-source security monitoring · Early development</span>
          </footer>
        </section>
      </main>
    </div>
  )
}

export default App
