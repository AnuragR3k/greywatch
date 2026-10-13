import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const TIME_RANGES = [
  { value: '1h', label: 'Last hour', ms: 60 * 60 * 1000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { value: 'all', label: 'All retrieved data', ms: null },
]

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid' },
  { id: 'events', label: 'Events', icon: 'activity' },
  { id: 'alerts', label: 'Alerts', icon: 'bell', badge: true },
  { id: 'investigations', label: 'Investigations', icon: 'search', planned: true },
  { id: 'rules', label: 'Rules', icon: 'zap', planned: true },
  { id: 'sources', label: 'Sources', icon: 'database', planned: true },
  { id: 'hosts', label: 'Hosts', icon: 'server', planned: true },
  { id: 'analytics', label: 'Analytics', icon: 'chart', planned: true },
  { id: 'settings', label: 'Settings', icon: 'gear', planned: true },
]

const EVENT_TYPE_META = {
  ssh_login_failed: { label: 'Failed login', tone: 'red' },
  ssh_login_success: { label: 'Accepted login', tone: 'green' },
  ssh_invalid_user: { label: 'Invalid user', tone: 'amber' },
}

function eventMeta(type) {
  return EVENT_TYPE_META[type] || { label: label(type) || 'Other', tone: 'purple' }
}

function label(value = '') {
  return value.replaceAll('_', ' ')
}

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

function formatTableTime(value) {
  if (!value) return '—'

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  const time = date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })

  const today = new Date()
  if (date.toDateString() === today.toDateString()) return time

  const day = date.toLocaleDateString([], { month: '2-digit', day: '2-digit' })
  return `${day} ${time}`
}

const ICON_PATHS = {
  grid: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  activity: <polyline points="3 12 7 12 10 4 14 20 17 12 21 12" />,
  bell: (
    <>
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </>
  ),
  zap: <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />,
  database: (
    <>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
    </>
  ),
  server: (
    <>
      <rect x="2" y="3" width="20" height="7" rx="2" />
      <rect x="2" y="14" width="20" height="7" rx="2" />
      <line x1="6" y1="6.5" x2="6.01" y2="6.5" />
      <line x1="6" y1="17.5" x2="6.01" y2="17.5" />
    </>
  ),
  chart: (
    <>
      <line x1="6" y1="20" x2="6" y2="12" />
      <line x1="12" y1="20" x2="12" y2="4" />
      <line x1="18" y1="20" x2="18" y2="9" />
    </>
  ),
  gear: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </>
  ),
  shield: (
    <>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 11.5 11 13.5 15 9.5" />
    </>
  ),
  triangle: (
    <>
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13.5" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>
  ),
  monitor: (
    <>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </>
  ),
  calendar: (
    <>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <line x1="16" y1="3" x2="16" y2="7" />
      <line x1="8" y1="3" x2="8" y2="7" />
      <line x1="3" y1="10" x2="21" y2="10" />
    </>
  ),
  refresh: (
    <>
      <polyline points="23 4 23 10 17 10" />
      <polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
      <path d="M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </>
  ),
  menu: (
    <>
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </>
  ),
  arrowRight: (
    <>
      <line x1="4" y1="12" x2="18" y2="12" />
      <polyline points="13 6 18 12 13 18" />
    </>
  ),
  eye: (
    <>
      <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  check: (
    <>
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4" />
      <line x1="12" y1="1" x2="12" y2="4" />
      <line x1="12" y1="20" x2="12" y2="23" />
      <line x1="1" y1="12" x2="4" y2="12" />
      <line x1="20" y1="12" x2="23" y2="12" />
    </>
  ),
}

function Icon({ name, size = 16 }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICON_PATHS[name]}
    </svg>
  )
}

function EmptyState({ title, hint, loading = false }) {
  return (
    <div className="empty-state">
      <strong>{loading ? 'Loading…' : title}</strong>
      <p>{hint}</p>
    </div>
  )
}

function EventsTable({ events, dense = false, loading = false }) {
  const [expandedId, setExpandedId] = useState(null)

  if (!events.length) {
    return (
      <EmptyState
        loading={loading}
        title="No events found"
        hint="Events will appear here when Greywatch receives log data."
      />
    )
  }

  function toggle(id) {
    setExpandedId((current) => (current === id ? null : id))
  }

  return (
    <div className="table-scroll">
      <table className="data-table events-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Host</th>
            <th>Event type</th>
            {!dense && <th>Username</th>}
            <th>Source IP</th>
            {!dense && <th>Severity</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const meta = eventMeta(event.event_type)
            const expanded = expandedId === event.id

            return (
              <Fragment key={event.id}>
                <tr className={expanded ? 'row-expanded' : ''}>
                  <td>
                    <button
                      type="button"
                      className="row-toggle"
                      aria-expanded={expanded}
                      aria-label={`Show raw log for event ${event.id}`}
                      onClick={() => toggle(event.id)}
                    >
                      <span className={`chevron ${expanded ? 'open' : ''}`}>▾</span>
                      <span className="mono">{formatTableTime(event.timestamp)}</span>
                    </button>
                  </td>
                  <td>{event.host || '—'}</td>
                  <td>
                    <span className={`event-type tone-${meta.tone}`}>
                      <span className={`event-dot tone-${meta.tone}`} />
                      {meta.label}
                    </span>
                  </td>
                  {!dense && <td>{event.username || '—'}</td>}
                  <td className="mono">{event.source_ip || '—'}</td>
                  {!dense && (
                    <td>
                      <span className={`severity ${event.severity}`}>
                        {event.severity || 'unknown'}
                      </span>
                    </td>
                  )}
                </tr>
                {expanded && (
                  <tr className="raw-row">
                    <td colSpan={dense ? 4 : 6}>
                      <div className="raw-block">
                        <span className="raw-label">
                          RAW LOG · EVENT #{event.id}
                          {event.username ? ` · USER ${event.username}` : ''}
                        </span>
                        <code>{event.raw_message}</code>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function EvidenceTable({ events }) {
  if (!events.length) {
    return (
      <EmptyState
        title="No matching evidence events"
        hint="No failed-login records were found in the alert's evidence window."
      />
    )
  }

  return (
    <div className="table-scroll">
      <table className="data-table evidence-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Host</th>
            <th>Event type</th>
            <th>Username</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Raw log message</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const meta = eventMeta(event.event_type)

            return (
              <tr key={event.id}>
                <td className="mono">{event.id}</td>
                <td className="mono">{formatTableTime(event.timestamp)}</td>
                <td>{event.host || '—'}</td>
                <td>
                  <span className={`event-type tone-${meta.tone}`}>
                    <span className={`event-dot tone-${meta.tone}`} />
                    {meta.label}
                  </span>
                </td>
                <td>{event.username || '—'}</td>
                <td className="mono">{event.source_ip || '—'}</td>
                <td>
                  <span className={`severity ${event.severity}`}>
                    {event.severity || 'unknown'}
                  </span>
                </td>
                <td className="raw-message">{event.raw_message}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function AlertsTable({ alerts, onClose, closingId, onView, limit }) {
  const rows = typeof limit === 'number' ? alerts.slice(0, limit) : alerts

  if (!rows.length) {
    return (
      <EmptyState
        title="No alerts in this view"
        hint="Greywatch has no matching alerts to display."
      />
    )
  }

  return (
    <div className="table-scroll">
      <table className="data-table alerts-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Detection</th>
            <th>Source IP</th>
            <th>Title</th>
            <th>Severity</th>
            <th>Status</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((alert) => (
            <tr key={alert.id}>
              <td className="mono">{formatTableTime(alert.created_at)}</td>
              <td>
                <span className="rule-chip mono">{alert.rule_id}</span>
              </td>
              <td className="mono">{alert.source_ip}</td>
              <td className="alert-title-cell">{alert.title}</td>
              <td>
                <span className={`severity ${alert.severity}`}>
                  {alert.severity}
                </span>
              </td>
              <td>
                <span className={`status ${alert.status}`}>{alert.status}</span>
              </td>
              <td className="actions-cell">
                <button
                  type="button"
                  className="button button-ghost"
                  onClick={() => onView(alert.id)}
                >
                  <Icon name="eye" size={13} />
                  Evidence
                </button>
                {alert.status === 'open' && (
                  <button
                    type="button"
                    className="button button-ghost resolve-button"
                    disabled={closingId === alert.id}
                    onClick={() => onClose(alert.id)}
                  >
                    <Icon name="check" size={13} />
                    {closingId === alert.id ? 'Saving…' : 'Resolve'}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertEvidencePanel({
  evidence,
  loading,
  error,
  onClose,
  onResolve,
  closingId,
}) {
  const alert = evidence?.alert

  return (
    <div className="evidence-overlay" onClick={onClose}>
      <div
        className="evidence-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Alert investigation"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="evidence-header">
          <div>
            <span className="panel-eyebrow">INVESTIGATION</span>
            <h2>Alert evidence</h2>
          </div>
          <button
            type="button"
            className="button button-ghost"
            aria-label="Close alert evidence"
            onClick={onClose}
          >
            Close
          </button>
        </header>

        {loading && <div className="loading-state">Loading alert evidence…</div>}
        {error && <div className="error-banner">{error}</div>}

        {!loading && !error && evidence && alert && (
          <div className="evidence-content">
            <div className="evidence-titlebar">
              <span className={`severity severity-lg ${alert.severity}`}>
                {alert.severity}
              </span>
              <div className="evidence-titleblock">
                <h3>{alert.title}</h3>
                <p>
                  <span className="mono">{alert.rule_id}</span>
                  {' · triggered by '}
                  <span className="mono">{alert.source_ip}</span>
                </p>
              </div>
              <div className="evidence-actions">
                <span className={`status ${alert.status}`}>{alert.status}</span>
                {alert.status === 'open' && (
                  <button
                    type="button"
                    className="button button-primary"
                    disabled={closingId === alert.id}
                    onClick={() => onResolve(alert.id)}
                  >
                    {closingId === alert.id ? 'Saving…' : 'Mark as resolved'}
                  </button>
                )}
              </div>
            </div>

            <div className="evidence-grid">
              <aside className="info-card">
                <h4>Alert information</h4>
                <dl className="info-list">
                  <div>
                    <dt>Alert ID</dt>
                    <dd className="mono">{alert.id}</dd>
                  </div>
                  <div>
                    <dt>Rule ID</dt>
                    <dd className="mono">{alert.rule_id}</dd>
                  </div>
                  <div>
                    <dt>Source IP</dt>
                    <dd className="mono">{alert.source_ip}</dd>
                  </div>
                  <div>
                    <dt>Event count</dt>
                    <dd>{alert.event_count}</dd>
                  </div>
                  <div>
                    <dt>Created</dt>
                    <dd className="mono">{formatTime(alert.created_at)}</dd>
                  </div>
                  <div>
                    <dt>Window start</dt>
                    <dd className="mono">
                      {formatTime(evidence.evidence_window_start)}
                    </dd>
                  </div>
                  <div>
                    <dt>Window end</dt>
                    <dd className="mono">
                      {formatTime(evidence.evidence_window_end)}
                    </dd>
                  </div>
                  <div>
                    <dt>Matching evidence</dt>
                    <dd>{evidence.evidence_events.length} events</dd>
                  </div>
                </dl>
              </aside>

              <section className="evidence-section">
                <div className="section-subhead">
                  <h4>Evidence</h4>
                  <span className="count-chip">
                    {evidence.evidence_events.length}{' '}
                    {evidence.evidence_events.length === 1 ? 'event' : 'events'}
                  </span>
                </div>
                <EvidenceTable events={evidence.evidence_events} />
              </section>
            </div>
          </div>
        )}

        {!loading && !error && !evidence && (
          <EmptyState
            title="No evidence available"
            hint="Could not retrieve evidence for this alert."
          />
        )}
      </div>
    </div>
  )
}

function Sidebar({ activeView, onNavigate, openAlertCount, connected, open }) {
  return (
    <aside className={`sidebar ${open ? 'open' : ''}`} id="app-sidebar">
      <div className="brand">
        <span className="brand-mark">
          <Icon name="shield" size={22} />
        </span>
        <span className="brand-text">
          <span className="brand-name">Greywatch</span>
          <span className="brand-caption">SIEM PLATFORM</span>
        </span>
      </div>

      <nav className="navigation" aria-label="Primary navigation">
        {NAV_ITEMS.map((item) => {
          const isActive = activeView === item.id

          if (item.planned) {
            return (
              <span
                key={item.id}
                className="nav-item planned"
                aria-disabled="true"
                title="Planned — this section is not built yet"
              >
                <span className="nav-icon">
                  <Icon name={item.icon} size={17} />
                </span>
                <span className="nav-text">{item.label}</span>
                <span className="nav-soon">soon</span>
              </span>
            )
          }

          return (
            <button
              key={item.id}
              type="button"
              className={`nav-item ${isActive ? 'active' : ''}`}
              aria-current={isActive ? 'page' : undefined}
              onClick={() => onNavigate(item.id)}
            >
              <span className="nav-icon">
                <Icon name={item.icon} size={17} />
              </span>
              <span className="nav-text">{item.label}</span>
              {item.badge && openAlertCount > 0 && (
                <span className="nav-count" aria-label={`${openAlertCount} open alerts`}>
                  {openAlertCount}
                </span>
              )}
            </button>
          )
        })}
      </nav>

      <div className="sidebar-bottom">
        <div className="connection-row">
          <span className={`connection-dot ${connected ? 'online' : 'offline'}`} />
          <span>{connected ? 'API connected' : 'API unavailable'}</span>
        </div>

        <div className="profile">
          <span className="avatar" aria-hidden="true">A</span>
          <span className="profile-text">
            <span className="profile-name">Analyst</span>
            <span className="profile-handle">analyst@local</span>
          </span>
        </div>

        <div className="sidebar-version">GREYWATCH · v0.1.0</div>
      </div>
    </aside>
  )
}

function TopBar({
  query,
  onQueryChange,
  timeRange,
  onTimeRangeChange,
  connected,
  loading,
  onRefresh,
  onToggleNav,
  navOpen,
}) {
  return (
    <header className="topbar">
      <button
        type="button"
        className="nav-toggle"
        aria-label="Toggle navigation"
        aria-expanded={navOpen}
        aria-controls="app-sidebar"
        onClick={onToggleNav}
      >
        <Icon name="menu" size={18} />
      </button>

      <div className="global-search">
        <Icon name="search" size={15} />
        <input
          type="search"
          aria-label="Search events, IPs, users, or messages"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search events, IPs, users, or messages…"
        />
        {query && (
          <button
            type="button"
            className="clear-search"
            aria-label="Clear search"
            onClick={() => onQueryChange('')}
          >
            ×
          </button>
        )}
      </div>

      <div className="topbar-controls">
        <label className="time-select">
          <Icon name="calendar" size={14} />
          <span className="sr-only">Time range</span>
          <select
            aria-label="Time range"
            value={timeRange}
            onChange={(event) => onTimeRangeChange(event.target.value)}
          >
            {TIME_RANGES.map((range) => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>
        </label>

        <span className={`live-pill ${connected ? 'online' : 'offline'}`}>
          <span className="connection-dot" />
          {connected ? 'Live' : 'Offline'}
        </span>

        <button
          type="button"
          className="button button-refresh"
          onClick={onRefresh}
          disabled={loading}
        >
          <Icon name="refresh" size={13} />
          Refresh
        </button>
      </div>
    </header>
  )
}

function KpiCard({ icon, accent, label: cardLabel, value, foot }) {
  return (
    <article className="kpi-card">
      <div className="kpi-head">
        <span className={`kpi-icon accent-${accent}`}>
          <Icon name={icon} size={16} />
        </span>
        <span className="kpi-label">{cardLabel}</span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-foot">{foot}</div>
    </article>
  )
}

function buildVolume(events, timeRange) {
  const now = Date.now()
  const range = TIME_RANGES.find((entry) => entry.value === timeRange) || TIME_RANGES[1]

  const stamps = []
  for (const event of events) {
    const time = Date.parse(event.timestamp)
    if (!Number.isNaN(time)) stamps.push(time)
  }

  let start
  let end = now
  let bucketCount

  if (range.ms) {
    start = now - range.ms
    bucketCount = range.value === '1h' ? 12 : range.value === '24h' ? 24 : 7
  } else if (stamps.length) {
    start = Math.min(...stamps)
    bucketCount = 12
    if (end <= start) end = start + 60 * 60 * 1000
  } else {
    return null
  }

  const bucketMs = (end - start) / bucketCount
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    start: start + index * bucketMs,
    count: 0,
  }))

  let total = 0
  for (const time of stamps) {
    if (time < start || time > end) continue
    const index = Math.min(bucketCount - 1, Math.floor((time - start) / bucketMs))
    buckets[index].count += 1
    total += 1
  }

  const max = Math.max(...buckets.map((bucket) => bucket.count), 1)

  return { buckets, max, total, bucketMs }
}

function bucketLabel(start, bucketMs) {
  const date = new Date(start)
  if (bucketMs >= 24 * 60 * 60 * 1000) {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' })
  }
  if (bucketMs >= 60 * 60 * 1000) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
  }
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

function EventVolumePanel({ events, timeRange, loading }) {
  const volume = useMemo(
    () => buildVolume(events, timeRange),
    [events, timeRange],
  )

  if (!volume || !volume.total) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3>Event volume</h3>
            <p>Time-based distribution of retrieved events</p>
          </div>
        </div>
        <EmptyState
          loading={loading}
          title="No time-series data in this window"
          hint="Widen the time range or ingest new log data to populate this chart."
        />
      </section>
    )
  }

  const labelStep = Math.max(1, Math.ceil(volume.buckets.length / 6))
  const mid = Math.round(volume.max / 2)

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h3>Event volume</h3>
          <p>{volume.total} events in the selected time range</p>
        </div>
        <span className="panel-note mono">
          {bucketLabel(volume.buckets[0].start, volume.bucketMs)} —{' '}
          {bucketLabel(
            volume.buckets[volume.buckets.length - 1].start,
            volume.bucketMs,
          )}
        </span>
      </div>

      <div
        className="volume-chart"
        role="img"
        aria-label={`Bar chart of event volume: ${volume.total} events, peak ${volume.max} per bucket`}
      >
        <div className="y-axis" aria-hidden="true">
          <span>{volume.max}</span>
          <span>{mid}</span>
          <span>0</span>
        </div>

        <div className="plot">
          <div className="grid-lines" aria-hidden="true">
            <i />
            <i />
            <i />
          </div>
          <div className="bars">
            {volume.buckets.map((bucket) => (
              <span
                key={bucket.start}
                className="bar"
                style={{ height: `${Math.max((bucket.count / volume.max) * 100, bucket.count ? 3 : 0)}%` }}
                title={`${bucketLabel(bucket.start, volume.bucketMs)} — ${bucket.count} events`}
              >
                <span className="sr-only">
                  {bucketLabel(bucket.start, volume.bucketMs)}: {bucket.count} events
                </span>
              </span>
            ))}
          </div>
          <div className="x-axis" aria-hidden="true">
            {volume.buckets.map((bucket, index) => (
              <span key={bucket.start}>
                {index % labelStep === 0
                  ? bucketLabel(bucket.start, volume.bucketMs)
                  : ''}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

const DONUT_COLORS = {
  red: 'var(--red)',
  green: 'var(--green)',
  amber: 'var(--amber)',
  purple: 'var(--purple)',
}

function EventTypePanel({ events, loading }) {
  const segments = useMemo(() => {
    const counts = new Map()

    for (const event of events) {
      const type = event.event_type || 'other'
      counts.set(type, (counts.get(type) || 0) + 1)
    }

    const total = events.length
    if (!total) return []

    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([type, count]) => ({
        type,
        count,
        tone: eventMeta(type).tone,
        label: eventMeta(type).label,
        pct: (count / total) * 100,
      }))
  }, [events])

  const total = events.length

  if (!total) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3>Event types</h3>
            <p>Distribution by category</p>
          </div>
        </div>
        <EmptyState
          loading={loading}
          title="No events in this window"
          hint="Event categories will appear once logs are ingested."
        />
      </section>
    )
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h3>Event types</h3>
          <p>Share of retrieved events</p>
        </div>
      </div>

      <div className="donut-layout">
        <div
          className="donut-wrap"
          role="img"
          aria-label={`Donut chart of event types: ${segments
            .map((segment) => `${segment.label} ${Math.round(segment.pct)} percent`)
            .join(', ')}`}
        >
          <svg viewBox="0 0 120 120" width="132" height="132">
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="var(--border)"
              strokeWidth="15"
            />
            {segments.map((segment, index) => {
              const startOffset = segments
                .slice(0, index)
                .reduce((sum, entry) => sum + entry.pct, 0)

              return (
                <circle
                  key={segment.type}
                  cx="60"
                  cy="60"
                  r="44"
                  fill="none"
                  stroke={DONUT_COLORS[segment.tone]}
                  strokeWidth="15"
                  pathLength="100"
                  strokeDasharray={`${segment.pct} ${100 - segment.pct}`}
                  strokeDashoffset={-startOffset}
                  strokeLinecap="butt"
                  transform="rotate(-90 60 60)"
                />
              )
            })}
          </svg>
          <div className="donut-center">
            <strong>{total}</strong>
            <span>events</span>
          </div>
        </div>

        <ul className="donut-legend">
          {segments.map((segment) => (
            <li key={segment.type}>
              <span className={`legend-dot tone-${segment.tone}`} />
              <span className="legend-label">{segment.label}</span>
              <span className="legend-count mono">{segment.count}</span>
              <span className="legend-pct mono">{Math.round(segment.pct)}%</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

function TopSourceIpsPanel({ events, alerts, selectedIp, onSelect }) {
  const [mode, setMode] = useState('events')

  const rows = useMemo(() => {
    const counts = new Map()

    if (mode === 'events') {
      for (const event of events) {
        if (!event.source_ip) continue
        counts.set(event.source_ip, (counts.get(event.source_ip) || 0) + 1)
      }
    } else {
      for (const alert of alerts) {
        if (!alert.source_ip) continue
        counts.set(alert.source_ip, (counts.get(alert.source_ip) || 0) + 1)
      }
    }

    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
  }, [events, alerts, mode])

  const total = mode === 'events' ? events.length : alerts.length
  const max = rows.length ? rows[0][1] : 1

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h3>Top source IPs</h3>
          <p>
            {mode === 'events'
              ? 'Summary of retrieved events'
              : 'Summary of retrieved alerts'}
          </p>
        </div>
        <div className="segmented" role="group" aria-label="Count source IPs by">
          <button
            type="button"
            className={mode === 'events' ? 'active' : ''}
            aria-pressed={mode === 'events'}
            onClick={() => setMode('events')}
          >
            Events
          </button>
          <button
            type="button"
            className={mode === 'alerts' ? 'active' : ''}
            aria-pressed={mode === 'alerts'}
            onClick={() => setMode('alerts')}
          >
            Alerts
          </button>
        </div>
      </div>

      {rows.length ? (
        <div className="ip-bars">
          {rows.map(([ip, count]) => (
            <button
              key={ip}
              type="button"
              className={`ip-row ${selectedIp === ip ? 'selected' : ''}`}
              onClick={() => onSelect(ip)}
              aria-label={`Analyze source IP ${ip} with ${count} ${mode}`}
            >
              <span className="ip-address mono">{ip}</span>
              <span className="ip-track" aria-hidden="true">
                <span
                  className="ip-fill"
                  style={{ width: `${Math.max((count / max) * 100, 4)}%` }}
                />
              </span>
              <span className="ip-count mono">{count}</span>
            </button>
          ))}
        </div>
      ) : (
        <EmptyState
          title="No source IPs yet"
          hint="Source IPs appear here once events or alerts are retrieved."
        />
      )}

      <div className="panel-foot">
        Based on the latest {total} {mode} returned by the API — not full
        historical telemetry.
      </div>
    </section>
  )
}

function SourceIpAnalysisPanel({
  events,
  alerts,
  selectedIp,
  onSelect,
  onView,
  onClose,
  closingId,
}) {
  const ips = useMemo(() => {
    const counts = new Map()

    for (const event of events) {
      if (!event.source_ip) continue
      counts.set(event.source_ip, (counts.get(event.source_ip) || 0) + 1)
    }
    for (const alert of alerts) {
      if (!alert.source_ip || counts.has(alert.source_ip)) continue
      counts.set(alert.source_ip, 0)
    }

    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([ip]) => ip)
  }, [events, alerts])

  const activeIp = selectedIp || ips[0] || ''

  const ipEvents = useMemo(
    () =>
      events
        .filter((event) => event.source_ip === activeIp)
        .slice()
        .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp))),
    [events, activeIp],
  )

  const ipAlerts = useMemo(
    () => alerts.filter((alert) => alert.source_ip === activeIp),
    [alerts, activeIp],
  )

  const failed = ipEvents.filter(
    (event) => event.event_type === 'ssh_login_failed',
  ).length
  const accepted = ipEvents.filter(
    (event) => event.event_type === 'ssh_login_success',
  ).length

  if (!ips.length) {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3>Source IP analysis</h3>
            <p>Investigate a single source address</p>
          </div>
        </div>
        <EmptyState
          title="No source IPs in retrieved data"
          hint="Ingest events or wait for alerts to analyze source addresses."
        />
      </section>
    )
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h3>Source IP analysis</h3>
          <p>Activity derived from retrieved events and alerts</p>
        </div>
        <label className="ip-select">
          <span className="sr-only">Select source IP</span>
          <select
            aria-label="Select source IP to analyze"
            value={activeIp}
            onChange={(event) => onSelect(event.target.value)}
          >
            {ips.map((ip) => (
              <option key={ip} value={ip}>
                {ip}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="ip-stats">
        <div className="ip-stat">
          <span className="ip-stat-value mono">{ipEvents.length}</span>
          <span className="ip-stat-label">Total events</span>
        </div>
        <div className="ip-stat">
          <span className="ip-stat-value mono text-red">{failed}</span>
          <span className="ip-stat-label">Failed logins</span>
        </div>
        <div className="ip-stat">
          <span className="ip-stat-value mono text-green">{accepted}</span>
          <span className="ip-stat-label">Accepted logins</span>
        </div>
        <div className="ip-stat">
          <span className="ip-stat-value mono text-blue">{ipAlerts.length}</span>
          <span className="ip-stat-label">Associated alerts</span>
        </div>
      </div>

      {ipAlerts.length > 0 && (
        <div className="ip-alerts">
          <h4>Alerts for this IP</h4>
          {ipAlerts.slice(0, 4).map((alert) => (
            <div className="ip-alert-row" key={alert.id}>
              <span className={`severity ${alert.severity}`}>{alert.severity}</span>
              <span className="ip-alert-title">{alert.title}</span>
              <span className={`status ${alert.status}`}>{alert.status}</span>
              <button
                type="button"
                className="button button-ghost"
                onClick={() => onView(alert.id)}
              >
                <Icon name="eye" size={13} />
                Evidence
              </button>
              {alert.status === 'open' && (
                <button
                  type="button"
                  className="button button-ghost resolve-button"
                  disabled={closingId === alert.id}
                  onClick={() => onClose(alert.id)}
                >
                  {closingId === alert.id ? 'Saving…' : 'Resolve'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="timeline">
        <h4>Activity timeline</h4>
        {ipEvents.length ? (
          <ol className="timeline-list">
            {ipEvents.map((event) => {
              const meta = eventMeta(event.event_type)
              return (
                <li key={event.id}>
                  <span className="mono timeline-time">
                    {formatTableTime(event.timestamp)}
                  </span>
                  <span className={`event-type tone-${meta.tone}`}>
                    <span className={`event-dot tone-${meta.tone}`} />
                    {meta.label}
                  </span>
                  <span className="timeline-host">{event.host || '—'}</span>
                  <span className="timeline-user">{event.username || '—'}</span>
                </li>
              )
            })}
          </ol>
        ) : (
          <EmptyState
            title="No events for this IP"
            hint="No retrieved events match this source address."
          />
        )}
      </div>

      <div className="panel-foot">
        Based on the latest {events.length} events and {alerts.length} alerts
        returned by the API. First-seen / last-seen history would require a
        dedicated backend endpoint (<span className="mono">/api/v1/source-ips/&#123;ip&#125;</span>),
        which is not available yet.
      </div>
    </section>
  )
}

function GeoPanel() {
  return (
    <section className="panel geo-panel">
      <div className="panel-heading">
        <div>
          <h3>Geographic view</h3>
          <p>Optional feature — not available</p>
        </div>
        <span className="planned-chip">not available</span>
      </div>

      <div className="geo-body">
        <span className="geo-icon">
          <Icon name="globe" size={26} />
        </span>
        <p>
          Greywatch has no trusted geolocation source. IP-to-location lookups
          are intentionally not implemented: they would require shipping event
          data to an external service or maintaining a local GeoIP database.
        </p>
        <p className="geo-hint">
          Until then, use <strong>Top source IPs</strong> and{' '}
          <strong>Source IP analysis</strong> for address-based investigation.
        </p>
      </div>
    </section>
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
  const [activeView, setActiveView] = useState('dashboard')
  const [timeRange, setTimeRange] = useState('24h')
  const [navOpen, setNavOpen] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [closingId, setClosingId] = useState(null)
  const [viewingAlertId, setViewingAlertId] = useState(null)
  const [evidence, setEvidence] = useState(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [evidenceError, setEvidenceError] = useState('')
  const [selectedIp, setSelectedIp] = useState('')

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
    } catch {
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

  useEffect(() => {
    function onKeyDown(event) {
      if (event.key !== 'Escape') return
      if (viewingAlertId !== null) {
        closeEvidencePanel()
      } else if (navOpen) {
        setNavOpen(false)
      }
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [viewingAlertId, navOpen])

  const connected = data.health?.status === 'ok'

  const range = TIME_RANGES.find((entry) => entry.value === timeRange)

  const rangedEvents = useMemo(() => {
    if (!range?.ms) return data.events
    const cutoff = Date.now() - range.ms

    return data.events.filter((event) => {
      const time = Date.parse(event.timestamp)
      return !Number.isNaN(time) && time >= cutoff
    })
  }, [data.events, range])

  const filteredEvents = useMemo(() => {
    const term = query.trim().toLowerCase()

    if (!term) return rangedEvents

    return rangedEvents.filter((event) =>
      [
        event.event_type,
        event.host,
        event.username,
        event.source_ip,
        event.severity,
        event.raw_message,
      ]
        .filter(Boolean)
        .some((value) => value.toLowerCase().includes(term)),
    )
  }, [rangedEvents, query])

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

  const openAlerts = useMemo(
    () => data.alerts.filter((alert) => alert.status === 'open'),
    [data.alerts],
  )

  const highAlerts = useMemo(
    () => data.alerts.filter((alert) => alert.severity === 'high'),
    [data.alerts],
  )

  const highOpen = highAlerts.filter((alert) => alert.status === 'open').length
  const highClosed = highAlerts.length - highOpen

  const hosts = useMemo(
    () =>
      new Set(
        rangedEvents.map((event) => event.host).filter(Boolean),
      ).size,
    [rangedEvents],
  )

  const topIp = useMemo(() => {
    const counts = new Map()

    for (const event of rangedEvents) {
      if (!event.source_ip) continue
      counts.set(event.source_ip, (counts.get(event.source_ip) || 0) + 1)
    }

    return (
      [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || ''
    )
  }, [rangedEvents])

  const activeIp = selectedIp || topIp

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

  async function viewEvidence(id) {
    setViewingAlertId(id)
    setEvidence(null)
    setEvidenceError('')
    setEvidenceLoading(true)

    try {
      const response = await fetch(`/api/v1/alerts/${id}`)

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Alert not found.')
        }
        throw new Error('Could not load alert evidence.')
      }

      const payload = await response.json()
      setEvidence(payload)
    } catch (err) {
      setEvidenceError(err.message || 'Failed to load alert evidence.')
    } finally {
      setEvidenceLoading(false)
    }
  }

  function closeEvidencePanel() {
    setViewingAlertId(null)
    setEvidence(null)
    setEvidenceError('')
  }

  function navigate(view) {
    setActiveView(view)
    setNavOpen(false)
  }

  const titles = {
    dashboard: ['Dashboard', 'Live security telemetry from your environment.'],
    events: ['Security events', 'Normalized SSH authentication events from the API.'],
    alerts: ['Alerts', 'Investigate evidence and resolve detected security alerts.'],
  }

  const rangeLabel =
    TIME_RANGES.find((entry) => entry.value === timeRange)?.label ?? 'Last 24 hours'

  return (
    <div className={`app-shell ${navOpen ? 'nav-open' : ''}`}>
      <Sidebar
        activeView={activeView}
        onNavigate={navigate}
        openAlertCount={openAlerts.length}
        connected={connected}
        open={navOpen}
      />

      {navOpen && (
        <button
          type="button"
          className="nav-scrim"
          aria-label="Close navigation"
          onClick={() => setNavOpen(false)}
        />
      )}

      <div className="main">
        <TopBar
          query={query}
          onQueryChange={setQuery}
          timeRange={timeRange}
          onTimeRangeChange={setTimeRange}
          connected={connected}
          loading={loading}
          onRefresh={refresh}
          onToggleNav={() => setNavOpen((current) => !current)}
          navOpen={navOpen}
        />

        <main className="page-content">
          <div className="page-heading">
            <div>
              <h1>{titles[activeView][0]}</h1>
              <p>{titles[activeView][1]}</p>
            </div>
            <div className="updated">
              <span className={`connection-dot ${connected ? 'online' : 'offline'}`} />
              {lastUpdated
                ? `Updated ${lastUpdated.toLocaleTimeString()}`
                : 'Waiting for data'}
            </div>
          </div>

          {error && <div className="error-banner">{error}</div>}

          {activeView === 'dashboard' && (
            <>
              <section className="kpi-grid" aria-label="Key metrics">
                <KpiCard
                  icon="database"
                  accent="blue"
                  label="Total events"
                  value={rangedEvents.length}
                  foot={`${rangeLabel.toLowerCase()} · latest ${data.events.length} fetched`}
                />
                <KpiCard
                  icon="bell"
                  accent="amber"
                  label="Open alerts"
                  value={openAlerts.length}
                  foot={`${data.alerts.length} alerts in the current list`}
                />
                <KpiCard
                  icon="triangle"
                  accent="red"
                  label="High severity"
                  value={highAlerts.length}
                  foot={`${highOpen} open · ${highClosed} resolved`}
                />
                <KpiCard
                  icon="monitor"
                  accent="green"
                  label="Monitored hosts"
                  value={hosts}
                  foot="Distinct hosts in retrieved events"
                />
              </section>

              <div className="kpi-note">
                Metrics are derived from the latest {data.events.length} events
                and {data.alerts.length} alerts returned by the API — the
                backend does not expose all-time totals.
              </div>

              <div className="dash-grid">
                <div className="dash-main">
                  <div className="charts-grid">
                    <EventVolumePanel
                      events={rangedEvents}
                      timeRange={timeRange}
                      loading={loading}
                    />
                    <EventTypePanel events={rangedEvents} loading={loading} />
                  </div>

                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Recent alerts</h3>
                        <p>
                          {filteredAlerts.length} alerts, open and resolved
                        </p>
                      </div>
                      <button
                        type="button"
                        className="text-button"
                        onClick={() => navigate('alerts')}
                      >
                        View all <Icon name="arrowRight" size={13} />
                      </button>
                    </div>
                    <AlertsTable
                      alerts={filteredAlerts}
                      limit={5}
                      onClose={closeAlert}
                      closingId={closingId}
                      onView={viewEvidence}
                    />
                  </section>

                  <div className="lower-grid">
                    <TopSourceIpsPanel
                      events={rangedEvents}
                      alerts={data.alerts}
                      selectedIp={activeIp}
                      onSelect={setSelectedIp}
                    />
                    <SourceIpAnalysisPanel
                      events={rangedEvents}
                      alerts={data.alerts}
                      selectedIp={activeIp}
                      onSelect={setSelectedIp}
                      onView={viewEvidence}
                      onClose={closeAlert}
                      closingId={closingId}
                    />
                  </div>
                </div>

                <aside className="dash-rail" aria-label="Live activity">
                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h3>Live events</h3>
                        <p>Newest first · polling every 10s</p>
                      </div>
                      <button
                        type="button"
                        className="text-button"
                        onClick={() => navigate('events')}
                      >
                        View all <Icon name="arrowRight" size={13} />
                      </button>
                    </div>
                    <EventsTable
                      events={filteredEvents.slice(0, 8)}
                      dense
                      loading={loading}
                    />
                  </section>

                  <GeoPanel />
                </aside>
              </div>
            </>
          )}

          {activeView === 'events' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h3>Normalized events</h3>
                  <p>{filteredEvents.length} matching events · {rangeLabel.toLowerCase()}</p>
                </div>
              </div>
              <EventsTable events={filteredEvents} loading={loading} />
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
              <AlertsTable
                alerts={filteredAlerts}
                onClose={closeAlert}
                closingId={closingId}
                onView={viewEvidence}
              />
            </section>
          )}

          <footer className="page-footer">
            <span>GREYWATCH SIEM</span>
            <span>Open-source security monitoring · Early development</span>
          </footer>
        </main>
      </div>

      {viewingAlertId !== null && (
        <AlertEvidencePanel
          evidence={evidence}
          loading={evidenceLoading}
          error={evidenceError}
          onClose={closeEvidencePanel}
          onResolve={closeAlert}
          closingId={closingId}
        />
      )}
    </div>
  )
}

export default App
