import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { Dock, DockIcon } from './components/Dock'
import { RangeSelect } from './components/DropdownMenu'
import {
  alertDetailFields,
  alertNetworkSummary,
  alertRuleLabel,
  alertSearchHaystack,
  alertSignatureLabel,
  categorizeEventType,
  eventDetailFields,
  eventPreview,
  eventRawPayload,
  eventSearchHaystack,
  eventSourceKey,
  eventSourceLabel,
  eventSourceTone,
  eventTypeBreakdown,
  formatDisplay,
  formatHost,
  formatNetworkSummary,
  isSuricataAlert,
  SOURCE_FILTERS,
  suricataSeverityFromAlert,
  suricataSeverityFromRecord,
  suricataSeverityLabel,
  suricataStatusView,
} from './lib/telemetry'
import './App.css'

const TIME_RANGES = [
  { value: '1h', label: 'Last hour', ms: 60 * 60 * 1000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { value: 'all', label: 'All retrieved data', ms: null },
]

// Short labels used by the compact mobile time-range selector.
const TIME_RANGE_SHORT = [
  { value: '1h', label: '1H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
  { value: 'all', label: 'ALL' },
]

// Alert metadata fields whose value is an ISO-8601 timestamp to render in full.
const ISO_TIME_FIELDS = new Set(['First seen', 'Last triggered', 'Resolved at'])

function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatHeaderTime(date) {
  if (!date) return 'Waiting for data'
  return (
    date.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }) +
    ', ' +
    date.toLocaleTimeString([], { hour12: false })
  )
}

function formatTableTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

// Alerts and their evidence can be older than the current day, so alert
// timestamps carry a short date prefix when they are not from today.
function formatAlertTime(value) {
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
  const day = date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
  return `${day} ${time}`
}

function formatLiveEventTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return (
    date.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    }) +
    ', ' +
    date.toLocaleTimeString([], { hour12: false })
  )
}

// Event-type presentation lives in lib/telemetry.js so Suricata and journal
// sources share one badge/filter mapping.

/* ==========================================================================
   Minimal Inline SVGs
   ========================================================================== */
function Icon({ name, size = 16, className = '' }) {
  const props = {
    width: size,
    height: size,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: '2',
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    className,
  }

  switch (name) {
    case 'grid':
      return (
        <svg {...props}>
          <circle cx="5" cy="5" r="1.5" />
          <circle cx="12" cy="5" r="1.5" />
          <circle cx="19" cy="5" r="1.5" />
          <circle cx="5" cy="12" r="1.5" />
          <circle cx="12" cy="12" r="1.5" />
          <circle cx="19" cy="12" r="1.5" />
          <circle cx="5" cy="19" r="1.5" />
          <circle cx="12" cy="19" r="1.5" />
          <circle cx="19" cy="19" r="1.5" />
        </svg>
      )
    case 'menu':
      return (
        <svg {...props}>
          <line x1="4" y1="7" x2="20" y2="7" />
          <line x1="4" y1="12" x2="20" y2="12" />
          <line x1="4" y1="17" x2="20" y2="17" />
        </svg>
      )
    case 'home':
      return (
        <svg {...props}>
          <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          <polyline points="9 22 9 12 15 12 15 22" />
        </svg>
      )
    case 'document':
      return (
        <svg {...props}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="16" y1="13" x2="8" y2="13" />
          <line x1="16" y1="17" x2="8" y2="17" />
          <polyline points="10 9 9 9 8 9" />
        </svg>
      )
    case 'alertTriangle':
      return (
        <svg {...props}>
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      )
    case 'monitor':
      return (
        <svg {...props}>
          <rect width="20" height="14" x="2" y="3" rx="2" />
          <line x1="8" y1="21" x2="16" y2="21" />
          <line x1="12" y1="17" x2="12" y2="21" />
        </svg>
      )
    case 'chart':
      return (
        <svg {...props}>
          <line x1="18" y1="20" x2="18" y2="10" />
          <line x1="12" y1="20" x2="12" y2="4" />
          <line x1="6" y1="20" x2="6" y2="14" />
        </svg>
      )
    case 'pulse':
      return (
        <svg {...props}>
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
      )
    case 'refresh':
      return (
        <svg {...props}>
          <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
          <path d="M3 3v5h5" />
          <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
          <path d="M16 21h5v-5" />
        </svg>
      )
    case 'calendar':
      return (
        <svg {...props}>
          <rect width="18" height="18" x="3" y="4" rx="2" ry="2" />
          <line x1="16" y1="2" x2="16" y2="6" />
          <line x1="8" y1="2" x2="8" y2="6" />
          <line x1="3" y1="10" x2="21" y2="10" />
        </svg>
      )
    case 'export':
      return (
        <svg {...props}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
      )
    case 'assign':
      return (
        <svg {...props}>
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
          <circle cx="9" cy="7" r="4" />
          <line x1="19" y1="8" x2="19" y2="14" />
          <line x1="22" y1="11" x2="16" y2="11" />
        </svg>
      )
    case 'more':
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="1.5" />
          <circle cx="19" cy="12" r="1.5" />
          <circle cx="5" cy="12" r="1.5" />
        </svg>
      )
    case 'bell':
      return (
        <svg {...props}>
          <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
          <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
        </svg>
      )
    case 'gear':
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
      )
    case 'help':
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="10" />
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      )
    case 'search':
      return (
        <svg {...props}>
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      )
    case 'chevronLeft':
      return (
        <svg {...props}>
          <polyline points="15 18 9 12 15 6" />
        </svg>
      )
    case 'chevronRight':
      return (
        <svg {...props}>
          <polyline points="9 18 15 12 9 6" />
        </svg>
      )
    case 'chevronDown':
      return (
        <svg {...props}>
          <polyline points="6 9 12 15 18 9" />
        </svg>
      )
    case 'arrowRight':
      return (
        <svg {...props}>
          <line x1="5" y1="12" x2="19" y2="12" />
          <polyline points="12 5 19 12 12 19" />
        </svg>
      )
    case 'server':
      return (
        <svg {...props}>
          <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
          <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
          <line x1="6" y1="6" x2="6.01" y2="6" />
          <line x1="6" y1="18" x2="6.01" y2="18" />
        </svg>
      )
    case 'wifi':
      return (
        <svg {...props}>
          <path d="M12 20h.01" />
          <path d="M8.5 16.429a5 5 0 0 1 7 0" />
          <path d="M5 12.859a10 10 0 0 1 14 0" />
          <path d="M1.5 9.288a15 15 0 0 1 21 0" />
        </svg>
      )
    case 'shield':
      return (
        <svg {...props}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      )
    case 'user':
      return (
        <svg {...props}>
          <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
          <circle cx="12" cy="7" r="4" />
        </svg>
      )
    case 'pause':
      return (
        <svg {...props}>
          <rect x="6" y="4" width="4" height="16" />
          <rect x="14" y="4" width="4" height="16" />
        </svg>
      )
    case 'play':
      return (
        <svg {...props}>
          <polygon points="5 3 19 12 5 21 5 3" />
        </svg>
      )
    case 'check':
      return (
        <svg {...props}>
          <polyline points="20 6 9 17 4 12" />
        </svg>
      )
    case 'close':
      return (
        <svg {...props}>
          <line x1="18" y1="6" x2="6" y2="18" />
          <line x1="6" y1="6" x2="18" y2="18" />
        </svg>
      )
    default:
      return null
  }
}

/* ==========================================================================
   Main App Component
   ========================================================================== */
export default function App() {
  const [data, setData] = useState({
    events: [],
    alerts: [],
    health: null,
    suricata: null,
    suricataUnavailable: false,
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [activeView, setActiveView] = useState('overview') // 'overview' | 'events' | 'alerts' | 'hosts' | 'analytics'
  const [timeRange, setTimeRange] = useState('24h')
  const [isLive, setIsLive] = useState(true)
  const [lastUpdated, setLastUpdated] = useState(null)

  // Interactive filters
  const [selectedIp, setSelectedIp] = useState('')
  const [selectedEventType, setSelectedEventType] = useState('')
  const [selectedSource, setSelectedSource] = useState('all')
  const [expandedEventId, setExpandedEventId] = useState(null)

  // Alert Evidence Investigation Drawer State
  const [viewingAlertId, setViewingAlertId] = useState(null)
  const [evidence, setEvidence] = useState(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [evidenceError, setEvidenceError] = useState('')
  const [expandedEvidenceId, setExpandedEvidenceId] = useState(null)
  const [closingId, setClosingId] = useState(null)

  // Fetch API data
  const refresh = useCallback(async () => {
    try {
      const [eventRes, alertRes, healthRes, suricataOutcome] = await Promise.all([
        fetch('/api/v1/events?limit=100'),
        fetch('/api/v1/alerts?status=all&limit=100'),
        fetch('/health'),
        fetch('/api/v1/suricata/status')
          .then(async (res) => {
            if (!res.ok) return { ok: false, data: null }
            return { ok: true, data: await res.json() }
          })
          .catch(() => ({ ok: false, data: null })),
      ])

      if ([eventRes, alertRes, healthRes].some((res) => !res.ok)) {
        throw new Error('API returned an unsuccessful status code.')
      }

      const [eventData, alertData, health] = await Promise.all([
        eventRes.json(),
        alertRes.json(),
        healthRes.json(),
      ])

      setData({
        events: eventData.events ?? [],
        alerts: alertData.alerts ?? [],
        health,
        suricata: suricataOutcome.data,
        suricataUnavailable: !suricataOutcome.ok,
      })
      setLastUpdated(new Date())
      setError('')
    } catch {
      setError('Cannot reach Greywatch API. Verify backend is running on port 8000.')
    } finally {
      setLoading(false)
    }
  }, [])

  // Auto-polling effect (every 10s when isLive is true)
  useEffect(() => {
    refresh()
    if (!isLive) return

    const timer = window.setInterval(refresh, 10000)
    return () => window.clearInterval(timer)
  }, [refresh, isLive])

  // Keyboard shortcut (Escape closes modal)
  useEffect(() => {
    function onKeyDown(e) {
      if (e.key === 'Escape' && viewingAlertId !== null) {
        closeEvidencePanel()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [viewingAlertId])

  // Connection status from real /health response
  const connected = data.health?.status === 'ok'

  // Time range calculation
  const rangeConfig = TIME_RANGES.find((r) => r.value === timeRange)
  const rangedEvents = useMemo(() => {
    if (!rangeConfig?.ms) return data.events
    const cutoff = Date.now() - rangeConfig.ms
    return data.events.filter((e) => {
      const time = Date.parse(e.timestamp)
      return !Number.isNaN(time) && time >= cutoff
    })
  }, [data.events, rangeConfig])

  // Filtered events (text search, IP selection, event type selection)
  const filteredEvents = useMemo(() => {
    let list = rangedEvents

    if (selectedIp) {
      list = list.filter((e) => e.source_ip === selectedIp)
    }

    if (selectedEventType) {
      list = list.filter(
        (e) => categorizeEventType(e.event_type).category === selectedEventType,
      )
    }

    if (selectedSource !== 'all') {
      list = list.filter((e) => eventSourceKey(e.source) === selectedSource)
    }

    const term = query.trim().toLowerCase()
    if (term) {
      list = list.filter((e) =>
        eventSearchHaystack(e).some((val) => val.includes(term)),
      )
    }

    return list
  }, [rangedEvents, selectedIp, selectedEventType, selectedSource, query])

  // Filtered alerts — searches Suricata signatures, network 5-tuple and category
  // in addition to the journal-derived alert fields.
  const filteredAlerts = useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return data.alerts
    return data.alerts.filter((alert) =>
      alertSearchHaystack(alert).some((val) => val.includes(term)),
    )
  }, [data.alerts, query])

  const openAlerts = useMemo(
    () => data.alerts.filter((a) => a.status === 'open'),
    [data.alerts],
  )
  const highAlerts = useMemo(
    () => data.alerts.filter((a) => a.severity === 'high'),
    [data.alerts],
  )
  const highOpen = highAlerts.filter((a) => a.status === 'open').length

  // Monitored hosts count
  const monitoredHostsCount = useMemo(() => {
    return new Set(rangedEvents.map((e) => e.host).filter(Boolean)).size || 1
  }, [rangedEvents])

  // Top source IPs aggregation
  const topSourceIps = useMemo(() => {
    const ipCounts = new Map()
    for (const e of rangedEvents) {
      if (!e.source_ip) continue
      ipCounts.set(e.source_ip, (ipCounts.get(e.source_ip) || 0) + 1)
    }
    return [...ipCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([ip, count]) => ({ ip, count }))
  }, [rangedEvents])

  // Active source IP & Associated Host for "Source IP -> Host" card
  const activeIp = selectedIp || topSourceIps[0]?.ip || '—'
  const activeHost = useMemo(() => {
    if (activeIp === '—') return '—'
    const ev = rangedEvents.find((e) => e.source_ip === activeIp && e.host)
    return formatHost(ev?.host)
  }, [rangedEvents, activeIp])

  // Event types aggregation
  const eventTypesAgg = useMemo(() => eventTypeBreakdown(rangedEvents), [rangedEvents])
  const suricataView = useMemo(
    () => suricataStatusView(data.suricata, data.suricataUnavailable),
    [data.suricata, data.suricataUnavailable],
  )

  // Alert investigation drawer presentation. The detail endpoint returns
  // { alert, evidence_window_start, evidence_window_end, evidence_events }.
  const evidenceAlert = evidence?.alert ?? null
  const evidenceEvents = evidence?.evidence_events ?? []
  const evidenceDetailFields = evidenceAlert ? alertDetailFields(evidenceAlert) : []
  const evidenceRawSeverity =
    (evidenceAlert ? suricataSeverityFromAlert(evidenceAlert) : null) ??
    evidenceEvents.map(suricataSeverityFromRecord).find((value) => value !== null) ??
    null

  // Waveform Bar Chart calculation (buckets over time)
  const waveformData = useMemo(() => {
    const numBuckets = 52
    const buckets = Array.from({ length: numBuckets }, (_, i) => ({
      index: i,
      auth: 0,
      sudo: 0,
      other: 0,
      total: 0,
      baselineHeight: 6 + Math.round(Math.sin((i / numBuckets) * Math.PI * 4) * 3 + (i % 3) * 2),
    }))

    const now = Date.now()
    const msRange = rangeConfig?.ms || 24 * 60 * 60 * 1000
    const startMs = now - msRange
    const bucketDuration = msRange / numBuckets

    let peakIndex = Math.floor(numBuckets / 2)
    let maxEventsInBucket = 0

    for (const ev of rangedEvents) {
      const t = Date.parse(ev.timestamp)
      if (Number.isNaN(t) || t < startMs || t > now) continue
      const bIdx = Math.min(
        numBuckets - 1,
        Math.max(0, Math.floor((t - startMs) / bucketDuration)),
      )
      const cat = categorizeEventType(ev.event_type).category
      if (cat === 'Authentication failure') buckets[bIdx].auth += 1
      else if (cat === 'Sudo activity') buckets[bIdx].sudo += 1
      else buckets[bIdx].other += 1
      buckets[bIdx].total += 1

      if (buckets[bIdx].total > maxEventsInBucket) {
        maxEventsInBucket = buckets[bIdx].total
        peakIndex = bIdx
      }
    }

    const maxTotal = Math.max(...buckets.map((b) => b.total), 1)
    return { buckets, maxTotal, peakIndex }
  }, [rangedEvents, rangeConfig])

  // Close Alert (Mark as resolved)
  async function closeAlert(id) {
    setClosingId(id)
    try {
      const res = await fetch(`/api/v1/alerts/${id}/close`, { method: 'POST' })
      if (!res.ok) throw new Error('Could not resolve alert.')
      await refresh()
      // If we are viewing evidence for this alert, reload it
      if (viewingAlertId === id) {
        await viewEvidence(id)
      }
    } catch (err) {
      setError(err.message || 'Failed to resolve alert.')
    } finally {
      setClosingId(null)
    }
  }

  // View Alert Evidence
  async function viewEvidence(id) {
    setViewingAlertId(id)
    setExpandedEvidenceId(null)
    setEvidence(null)
    setEvidenceError('')
    setEvidenceLoading(true)
    try {
      const res = await fetch(`/api/v1/alerts/${id}`)
      if (!res.ok) throw new Error('Could not load alert evidence.')
      const payload = await res.json()
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
    setExpandedEvidenceId(null)
  }

  // Export current filtered events
  function exportEvents() {
    const jsonStr = JSON.stringify(filteredEvents, null, 2)
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `greywatch-events-${new Date().toISOString().slice(0, 10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="app-shell">
      {/* Desktop Vertical Left Navigation Rail */}
      <aside className="nav-rail" aria-label="Main Navigation">
        <div className="nav-rail-inner">
          <button
            type="button"
            className="rail-collapse-btn"
            aria-label="Collapse Navigation"
            title="Collapse"
          >
            <Icon name="chevronLeft" size={14} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeView === 'overview' ? 'active' : ''}`}
            aria-label="Overview Dashboard"
            title="Overview"
            onClick={() => setActiveView('overview')}
          >
            <Icon name="home" size={18} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeView === 'events' ? 'active' : ''}`}
            aria-label="Events Table"
            title="Events"
            onClick={() => setActiveView('events')}
          >
            <Icon name="document" size={18} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeView === 'alerts' ? 'active' : ''}`}
            aria-label="Alerts List"
            title="Alerts"
            onClick={() => setActiveView('alerts')}
          >
            <Icon name="alertTriangle" size={18} />
            {openAlerts.length > 0 && <span className="rail-badge-dot" />}
          </button>

          <button
            type="button"
            className={`rail-btn ${activeView === 'hosts' ? 'active' : ''}`}
            aria-label="Monitored Hosts"
            title="Hosts"
            onClick={() => setActiveView('hosts')}
          >
            <Icon name="monitor" size={18} />
          </button>

          <button
            type="button"
            className={`rail-btn ${activeView === 'analytics' ? 'active' : ''}`}
            aria-label="Analytics & Reports"
            title="Analytics"
            onClick={() => setActiveView('analytics')}
          >
            <Icon name="chart" size={18} />
          </button>
        </div>
      </aside>

      {/* Main Viewport */}
      <div className="main-viewport">
        {/* Top Header & Floating Center Black Pill Toolbar */}
        <header className="top-header">
          {/* Left Brand */}
          <div className="header-brand">
            <div className="brand-icon-box">
              <Icon name="grid" size={18} />
            </div>
            <div className="brand-titles">
              <span className="brand-name">Greywatch</span>
              <span className="brand-tagline">SIEM Platform</span>
            </div>
          </div>

          {/* Center Floating Black Pill Toolbar (with motion magnification Dock) */}
          <Dock className="floating-toolbar" role="toolbar" aria-label="Control Actions">
            <DockIcon>
              <button
                type="button"
                className={`tb-btn ${isLive ? 'active-live' : 'paused'}`}
                onClick={() => setIsLive((prev) => !prev)}
                aria-label={isLive ? 'Live mode active (click to pause)' : 'Paused (click to go live)'}
              >
                <Icon name="pulse" size={14} className="pulse-icon" />
                <span>Live</span>
              </button>
            </DockIcon>

            <DockIcon>
              <button
                type="button"
                className="tb-btn"
                onClick={refresh}
                aria-label="Refresh telemetry data"
                disabled={loading}
              >
                <Icon name="refresh" size={13} />
                <span>Refresh</span>
              </button>
            </DockIcon>

            <DockIcon>
              <RangeSelect value={timeRange} onChange={setTimeRange} options={TIME_RANGES}>
                <div
                  className="tb-btn"
                  aria-label="Select time range"
                  style={{ cursor: 'pointer' }}
                >
                  <Icon name="calendar" size={13} />
                  <span>{TIME_RANGES.find((r) => r.value === timeRange)?.label ?? 'Range'}</span>
                  <Icon name="chevronDown" size={11} />
                </div>
              </RangeSelect>
            </DockIcon>

            <DockIcon>
              <button
                type="button"
                className="tb-btn"
                onClick={exportEvents}
                aria-label="Export events data"
              >
                <Icon name="export" size={13} />
                <span>Export</span>
              </button>
            </DockIcon>

            <DockIcon>
              <button
                type="button"
                className="tb-btn tb-btn-more"
                aria-label="More options"
                onClick={() => {
                  setSelectedIp('')
                  setSelectedEventType('')
                  setSelectedSource('all')
                  setExpandedEventId(null)
                  setQuery('')
                }}
                title="Reset Filters"
              >
                <Icon name="more" size={14} />
              </button>
            </DockIcon>
          </Dock>

          {/* Right Utilities & Mobile Hamburger Menu */}
          <div className="header-actions">
            <button
              type="button"
              className="action-circle-btn"
              aria-label="Notifications"
              title="Notifications"
              onClick={() => setActiveView('alerts')}
            >
              <Icon name="bell" size={16} />
            </button>

            <button
              type="button"
              className="action-circle-btn"
              aria-label="Settings"
              title="Settings"
            >
              <Icon name="gear" size={16} />
            </button>

            <button
              type="button"
              className="action-circle-btn"
              aria-label="Help and Documentation"
              title="Help"
            >
              <Icon name="help" size={16} />
            </button>

            <div
              className="action-circle-btn avatar-btn"
              title="Operator: Anurag"
              aria-label="User profile Anurag"
            >
              {/* Realistic vector portrait avatar matching reference */}
              <svg viewBox="0 0 36 36" fill="none" className="avatar-svg">
                <circle cx="18" cy="18" r="18" fill="#1e293b" />
                <path d="M18 19c3.314 0 6-2.686 6-6s-2.686-6-6-6-6 2.686-6 6 2.686 6 6 6z" fill="#f87171" />
                <path d="M7 32c0-5 5-9 11-9s11 4 11 9" fill="#0284c7" />
              </svg>
            </div>

            {/* Mobile hamburger menu */}
            <button
              type="button"
              className="mobile-menu-btn"
              aria-label="Open menu"
              onClick={() => setActiveView((v) => (v === 'overview' ? 'events' : 'overview'))}
            >
              <Icon name="menu" size={20} />
            </button>
          </div>
        </header>

        {/* Dashboard Hero Area: Breadcrumb, Title, Metadata & Sub-tabs */}
        <div className="dashboard-hero">
          <div className="hero-top-row">
            <div className="hero-titles">
              <span className="breadcrumb-label">
                <span className="mobile-breadcrumb-back">&lt; </span>Dashboard
              </span>
              <h1 className="page-title">Live Security Telemetry</h1>
              <p className="page-subtitle">Real-time detection, investigation and response.</p>
            </div>

            <div className="hero-meta-grid">
              <div className="meta-item">
                <span className="meta-item-label">Range</span>
                <div className="meta-item-value">
                  <RangeSelect value={timeRange} onChange={setTimeRange} options={TIME_RANGES}>
                    <span
                      aria-label="Time range selector"
                      style={{ display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}
                    >
                      <span>{TIME_RANGES.find((r) => r.value === timeRange)?.label ?? 'Range'}</span>
                      <Icon name="chevronDown" size={11} />
                    </span>
                  </RangeSelect>
                </div>
              </div>

              <div className="meta-item">
                <span className="meta-item-label">Updated</span>
                <span className="meta-item-value mono">
                  <span className={`status-dot ${connected ? 'online' : 'offline'}`} />
                  {formatHeaderTime(lastUpdated)}
                </span>
              </div>

              <div className="meta-item">
                <span className="meta-item-label">Source</span>
                <span className="meta-item-value">
                  <span className={`status-dot ${connected ? 'online' : 'offline'}`} />
                  {connected ? 'API connected' : 'API disconnected'}
                </span>
              </div>

              <div className="meta-item">
                <span className="meta-item-label">Suricata</span>
                <span className="meta-item-value suricata-status" title={suricataView.detail}>
                  <span className={`status-dot ${suricataView.dot}`} />
                  <span>
                    <span className="suricata-status-label">{suricataView.label}</span>
                    <span className="suricata-status-detail">{suricataView.detail}</span>
                  </span>
                </span>
              </div>

              <div className="meta-item">
                <span className="meta-item-label">Owner</span>
                <span className="meta-item-value">
                  <Icon name="user" size={13} />
                  Anurag
                </span>
              </div>
            </div>
          </div>

          {/* Sub-Tabs (Overview, Events, Alerts) */}
          <div className="hero-tabs-row" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={activeView === 'overview'}
              className={`tab-btn ${activeView === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveView('overview')}
            >
              Overview
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeView === 'events'}
              className={`tab-btn ${activeView === 'events' ? 'active' : ''}`}
              onClick={() => setActiveView('events')}
            >
              Events
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeView === 'alerts'}
              className={`tab-btn ${activeView === 'alerts' ? 'active' : ''}`}
              onClick={() => setActiveView('alerts')}
            >
              Alerts
            </button>
          </div>
        </div>

        {error && (
          <div
            style={{
              padding: '12px 18px',
              borderRadius: '12px',
              backgroundColor: '#fee2e2',
              color: '#991b1b',
              marginBottom: '18px',
              fontSize: '13px',
              fontWeight: 500,
            }}
          >
            {error}
          </div>
        )}

        {/* View 1: Overview Dashboard (Matches the Exact Attached Image) */}
        {activeView === 'overview' && (
          <main>
            {/* Four KPI Cards */}
            <section className="kpi-row" aria-label="Key Performance Indicators">
              {/* Card 1: Total Events */}
              <div className="kpi-card">
                <div className="kpi-card-left">
                  <div className="kpi-header-row">
                    <div className="kpi-icon-bubble cyan">
                      <Icon name="pulse" size={16} />
                    </div>
                    <span className="kpi-label">Total events</span>
                  </div>
                  <div className="kpi-value-row">
                    <span className="kpi-stat-number">{rangedEvents.length.toLocaleString()}</span>
                    <span className="kpi-trend-pill green">↑ 18%</span>
                  </div>
                </div>
                <div className="kpi-mini-chart" aria-hidden="true">
                  <span className="kpi-mini-bar cyan" style={{ height: '35%' }} />
                  <span className="kpi-mini-bar cyan" style={{ height: '55%' }} />
                  <span className="kpi-mini-bar cyan" style={{ height: '45%' }} />
                  <span className="kpi-mini-bar cyan" style={{ height: '80%' }} />
                  <span className="kpi-mini-bar cyan" style={{ height: '100%' }} />
                  <span className="kpi-mini-bar cyan" style={{ height: '70%' }} />
                </div>
              </div>

              {/* Card 2: Open Alerts */}
              <div className="kpi-card">
                <div className="kpi-card-left">
                  <div className="kpi-header-row">
                    <div className="kpi-icon-bubble amber">
                      <Icon name="alertTriangle" size={16} />
                    </div>
                    <span className="kpi-label">Open alerts</span>
                  </div>
                  <div className="kpi-value-row">
                    <span className="kpi-stat-number">{openAlerts.length}</span>
                    <span className="kpi-trend-pill red">↑ 200%</span>
                  </div>
                </div>
                <div className="kpi-mini-chart" aria-hidden="true">
                  <span className="kpi-mini-bar amber" style={{ height: '40%' }} />
                  <span className="kpi-mini-bar amber" style={{ height: '60%' }} />
                  <span className="kpi-mini-bar amber" style={{ height: '50%' }} />
                  <span className="kpi-mini-bar amber" style={{ height: '75%' }} />
                  <span className="kpi-mini-bar amber" style={{ height: '90%' }} />
                  <span className="kpi-mini-bar amber" style={{ height: '65%' }} />
                </div>
              </div>

              {/* Card 3: High Severity */}
              <div className="kpi-card">
                <div className="kpi-card-left">
                  <div className="kpi-header-row">
                    <div className="kpi-icon-bubble red">
                      <Icon name="shield" size={16} />
                    </div>
                    <span className="kpi-label">High severity</span>
                  </div>
                  <div className="kpi-value-row">
                    <span className="kpi-stat-number">{highOpen}</span>
                    <span className="kpi-stat-sub">of {highAlerts.length || 1}</span>
                  </div>
                </div>
                <div className="kpi-mini-chart" aria-hidden="true">
                  <span className="kpi-mini-bar red" style={{ height: '30%' }} />
                  <span className="kpi-mini-bar red" style={{ height: '50%' }} />
                  <span className="kpi-mini-bar red" style={{ height: '70%' }} />
                  <span className="kpi-mini-bar red" style={{ height: '85%' }} />
                  <span className="kpi-mini-bar red" style={{ height: '100%' }} />
                  <span className="kpi-mini-bar red" style={{ height: '60%' }} />
                </div>
              </div>

              {/* Card 4: Monitored Hosts */}
              <div className="kpi-card">
                <div className="kpi-card-left">
                  <div className="kpi-header-row">
                    <div className="kpi-icon-bubble blue">
                      <Icon name="server" size={16} />
                    </div>
                    <span className="kpi-label">Monitored hosts</span>
                  </div>
                  <div className="kpi-value-row">
                    <span className="kpi-stat-number">{monitoredHostsCount}</span>
                    <span className="kpi-trend-pill blue">↑ 0%</span>
                  </div>
                </div>
                <div className="kpi-mini-chart" aria-hidden="true">
                  <span className="kpi-mini-bar blue" style={{ height: '40%' }} />
                  <span className="kpi-mini-bar blue" style={{ height: '60%' }} />
                  <span className="kpi-mini-bar blue" style={{ height: '50%' }} />
                  <span className="kpi-mini-bar blue" style={{ height: '80%' }} />
                  <span className="kpi-mini-bar blue" style={{ height: '95%' }} />
                  <span className="kpi-mini-bar blue" style={{ height: '70%' }} />
                </div>
              </div>
            </section>

            {/* Split Grid: Left Investigation Summaries + Right Teal Analytics Panel */}
            <div className="dash-split-grid">
              {/* Left Column Cards */}
              <div className="dash-left-column">
                {/* 1. Source IP -> Host Card */}
                <div className="summary-card">
                  <div className="summary-card-header">
                    <span className="summary-card-title">Source IP → Host</span>
                  </div>
                  <div className="source-host-pair">
                    <div className="node-item">
                      <div className="node-icon-circle">
                        <Icon name="wifi" size={18} />
                      </div>
                      <div className="node-texts">
                        <span className="node-val mono">{activeIp}</span>
                        <span className="node-lbl">Source IP</span>
                      </div>
                    </div>

                    <span className="flow-arrow">→</span>

                    <div className="node-item">
                      <div className="node-icon-circle">
                        <Icon name="server" size={18} />
                      </div>
                      <div className="node-texts">
                        <span className="node-val">{activeHost}</span>
                        <span className="node-lbl">Host</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Top Source IPs Card */}
                <div className="summary-card">
                  <div className="summary-card-header">
                    <span className="summary-card-title">
                      Top source IPs <span className="summary-card-count">({topSourceIps.length})</span>
                    </span>
                    <button
                      type="button"
                      className="view-all-link"
                      onClick={() => {
                        setSelectedIp('')
                        setActiveView('events')
                      }}
                    >
                      View all <Icon name="arrowRight" size={11} />
                    </button>
                  </div>
                  <div className="summary-list">
                    {topSourceIps.length === 0 && (
                      <span className="empty-panel-msg" style={{ padding: '8px 0', fontSize: '12px' }}>
                        No source IPs in selected range
                      </span>
                    )}
                    {topSourceIps.slice(0, 3).map((entry, idx) => {
                      const dotColor = idx === 0 ? 'teal' : idx === 1 ? 'orange' : 'purple'
                      const isSelected = selectedIp === entry.ip
                      return (
                        <button
                          key={entry.ip}
                          type="button"
                          className={`summary-row-btn ${isSelected ? 'selected' : ''}`}
                          onClick={() => setSelectedIp((prev) => (prev === entry.ip ? '' : entry.ip))}
                          title={`Filter by ${entry.ip}`}
                        >
                          <div className="summary-row-left">
                            <span className={`row-dot ${dotColor}`} />
                            <span className="row-text mono">{entry.ip}</span>
                          </div>
                          <div className="summary-row-right">
                            <span className="row-badge">{entry.count}</span>
                            <span className="row-chevron">›</span>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* 3. Event Types Card */}
                <div className="summary-card">
                  <div className="summary-card-header">
                    <span className="summary-card-title">
                      Event types <span className="summary-card-count">({eventTypesAgg.length})</span>
                    </span>
                    <button
                      type="button"
                      className="view-all-link"
                      onClick={() => {
                        setSelectedEventType('')
                        setActiveView('events')
                      }}
                    >
                      View all <Icon name="arrowRight" size={11} />
                    </button>
                  </div>
                  <div className="summary-list">
                    {eventTypesAgg.map((item) => {
                      const isSelected = selectedEventType === item.name
                      return (
                        <button
                          key={item.name}
                          type="button"
                          className={`summary-row-btn ${isSelected ? 'selected' : ''}`}
                          onClick={() =>
                            setSelectedEventType((prev) => (prev === item.name ? '' : item.name))
                          }
                          title={`Filter by ${item.name}`}
                        >
                          <div className="summary-row-left">
                            <span className={`row-dot ${item.tone}`} />
                            <span className="row-text">{item.name}</span>
                          </div>
                          <div className="summary-row-right">
                            <span className="row-badge">{item.count}</span>
                            <span className="row-chevron">›</span>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* 4. Alerts Card */}
                <div className="summary-card">
                  <div className="summary-card-header">
                    <span className="summary-card-title">
                      Alerts <span className="summary-card-count">({data.alerts.length})</span>
                    </span>
                    <button
                      type="button"
                      className="view-all-link"
                      onClick={() => setActiveView('alerts')}
                    >
                      View all <Icon name="arrowRight" size={11} />
                    </button>
                  </div>
                  <div className="summary-list">
                    {data.alerts.length === 0 && (
                      <span className="empty-panel-msg" style={{ padding: '8px 0', fontSize: '12px' }}>
                        No alerts detected
                      </span>
                    )}
                    {data.alerts.slice(0, 3).map((alert) => (
                      <button
                        key={alert.id}
                        type="button"
                        className="summary-row-btn"
                        onClick={() => viewEvidence(alert.id)}
                        title={`Investigate ${alert.title}`}
                      >
                        <div className="summary-row-left">
                          <span className="row-dot red" />
                          <span className="row-text mono">{alert.rule_id}</span>
                        </div>
                        <div className="summary-row-right">
                          <span className="row-badge">{alert.event_count || 1}</span>
                          <span className="row-chevron">›</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Column: Teal Analytics Panel (Visual Centerpiece) */}
              <div className="teal-panel">
                {/* Search & Range controls inside Teal Panel */}
                <div className="teal-top-controls">
                  <div className="teal-search-bar">
                    <Icon name="search" size={16} className="teal-search-icon" />
                    <input
                      type="search"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search events, IPs, rules..."
                      className="teal-search-input"
                      aria-label="Search events"
                    />
                  </div>

                  <div className="teal-range-pill">
                    <RangeSelect value={selectedSource} onChange={setSelectedSource} options={SOURCE_FILTERS}>
                      <span
                        aria-label="Filter events by source"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}
                      >
                        <span>{SOURCE_FILTERS.find((s) => s.value === selectedSource)?.label ?? 'All Sources'}</span>
                        <Icon name="chevronDown" size={11} />
                      </span>
                    </RangeSelect>
                  </div>

                  <div className="teal-range-pill">
                    <RangeSelect value={timeRange} onChange={setTimeRange} options={TIME_RANGES}>
                      <span
                        aria-label="Change chart time range"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}
                      >
                        <span>{TIME_RANGES.find((r) => r.value === timeRange)?.label ?? 'Range'}</span>
                        <Icon name="chevronDown" size={11} />
                      </span>
                    </RangeSelect>
                  </div>
                </div>

                  <div className="teal-volume-section">
                    <div className="volume-heading-row">
                      <div className="volume-title-wrap">
                        <h2 className="teal-section-title">Event volume</h2>
                        <div className="mobile-volume-range">
                          <RangeSelect value={timeRange} onChange={setTimeRange} options={TIME_RANGE_SHORT}>
                            <span
                              aria-label="Change time range"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }}
                            >
                              <span>
                                {TIME_RANGE_SHORT.find((r) => r.value === timeRange)?.label ?? 'Range'}
                              </span>
                              <Icon name="chevronDown" size={10} />
                            </span>
                          </RangeSelect>
                        </div>
                      </div>
                      <div className="volume-legend">
                      <div className="legend-item">
                        <span className="legend-dot auth" />
                        <span>Authentication failure</span>
                        <span className="legend-count">
                          {eventTypesAgg.find((e) => e.name === 'Authentication failure')?.count || 0}
                        </span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot sudo" />
                        <span>Sudo activity</span>
                        <span className="legend-count">
                          {eventTypesAgg.find((e) => e.name === 'Sudo activity')?.count || 0}
                        </span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot other" />
                        <span>Other</span>
                        <span className="legend-count">
                          {(eventTypesAgg.find((e) => e.name === 'System')?.count || 0) +
                            (eventTypesAgg.find((e) => e.name === 'Other')?.count || 0)}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Waveform Bar Chart */}
                  <div className="waveform-chart-wrap" aria-label="Event volume timeline">
                    <div className="waveform-bars-area">
                      {waveformData.buckets.map((b) => {
                        const hasEvents = b.total > 0
                        const totalPct = hasEvents
                          ? Math.min(100, Math.max(16, (b.total / waveformData.maxTotal) * 100))
                          : b.baselineHeight

                        return (
                          <div
                            key={b.index}
                            className="waveform-bar-col"
                            title={`Bucket ${b.index}: ${b.total} events (${b.auth} auth, ${b.sudo} sudo, ${b.other} other)`}
                          >
                            {hasEvents ? (
                              <div
                                style={{
                                  display: 'flex',
                                  flexDirection: 'column-reverse',
                                  width: '100%',
                                  height: `${totalPct}%`,
                                }}
                              >
                                {b.auth > 0 && (
                                  <div
                                    className="bar-segment auth"
                                    style={{ height: `${(b.auth / b.total) * 100}%` }}
                                  />
                                )}
                                {b.sudo > 0 && (
                                  <div
                                    className="bar-segment sudo"
                                    style={{ height: `${(b.sudo / b.total) * 100}%` }}
                                  />
                                )}
                                {b.other > 0 && (
                                  <div
                                    className="bar-segment other"
                                    style={{ height: `${(b.other / b.total) * 100}%` }}
                                  />
                                )}
                              </div>
                            ) : (
                              <div
                                className="bar-segment other"
                                style={{ height: `${totalPct}px`, opacity: 0.35 }}
                              />
                            )}
                          </div>
                        )
                      })}

                      {/* Scrubber pin at peak or mid position */}
                      <div
                        className="chart-marker-pin"
                        style={{ left: `${(waveformData.peakIndex / 52) * 100}%` }}
                      >
                        <div className="marker-pin-head" />
                      </div>
                    </div>

                    {/* Time Axis Labels */}
                    <div className="waveform-axis-labels">
                      <span>12:00</span>
                      <span>14:00</span>
                      <span>16:00</span>
                      <span>18:00</span>
                      <span>20:00</span>
                      <span>22:00</span>
                      <span>00:00</span>
                      <span>02:00</span>
                      <span>04:00</span>
                      <span>06:00</span>
                      <span>08:00</span>
                      <span>10:00</span>
                      <span>12:00</span>
                    </div>
                  </div>
                </div>

                {/* Live Events Section */}
                <div className="teal-events-section">
                  <div className="live-events-header">
                    <h2 className="teal-section-title">Live events</h2>
                    <div className="refresh-status-badge">
                      <span
                        className="status-dot online"
                        style={{
                          backgroundColor: isLive ? '#38bdf8' : '#94a3b8',
                          boxShadow: isLive ? '0 0 0 3px rgba(56, 189, 248, 0.25)' : 'none',
                        }}
                      />
                      <span>{isLive ? 'Auto-refreshing every 10s' : 'Polling paused'}</span>
                      <button
                        type="button"
                        className="refresh-pause-btn"
                        onClick={() => setIsLive((prev) => !prev)}
                        aria-label={isLive ? 'Pause auto-refresh' : 'Resume auto-refresh'}
                      >
                        <Icon name={isLive ? 'pause' : 'play'} size={12} />
                      </button>
                    </div>
                  </div>

                  {/* List of Live Events */}
                  <div className="live-events-list">
                    {filteredEvents.length === 0 && (
                      <div className="empty-panel-msg">
                        No events match current filters or time range.
                      </div>
                    )}
                    {filteredEvents.slice(0, 6).map((ev) => {
                      const cat = categorizeEventType(ev.event_type)
                      const preview = eventPreview(ev)
                      const typeTone = cat.kind === 'ids' ? 'ids' : cat.tone
                      return (
                      <div key={ev.id} className="live-event-row">
                        <div className="event-row-left">
                          <div className="event-squircle-icon">
                            <Icon name={cat.kind === 'ids' || cat.kind === 'network' ? 'shield' : 'server'} size={17} />
                          </div>
                          <div className="event-host-time">
                            <span className="event-host-name">{formatHost(ev.host)}</span>
                            <span className="event-timestamp">
                              {formatLiveEventTime(ev.timestamp)}
                            </span>
                            <span className={`badge ${eventSourceTone(ev.source)} live-event-source`}>
                              {eventSourceLabel(ev.source)}
                            </span>
                          </div>
                        </div>

                        <div className="event-message-preview" title={preview}>
                          <span className={`badge ${typeTone}`} style={{ marginRight: '8px' }}>{cat.category}</span>
                          {preview}
                        </div>

                        <button
                          type="button"
                          className="event-more-btn"
                          aria-label={`Open details for event ${ev.id}`}
                          onClick={() => {
                            setActiveView('events')
                            setExpandedEventId(ev.id)
                          }}
                          title="Open event details"
                        >
                          <Icon name="more" size={14} />
                        </button>
                      </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            </div>
          </main>
        )}

        {/* View 2: Full Events Table View */}
        {activeView === 'events' && (
          <main className="full-view-panel">
            <div className="panel-header-bar">
              <div className="panel-title-block">
                <h3>Normalized Security Events</h3>
                <p>
                  Showing {filteredEvents.length} events from API · {rangeConfig?.label || 'Last 24 hours'}
                </p>
              </div>

              <div className="source-filter-wrap">
                <RangeSelect
                  value={selectedSource}
                  onChange={setSelectedSource}
                  options={SOURCE_FILTERS}
                >
                  <button type="button" className="btn-outline" aria-label="Filter events by source">
                    {SOURCE_FILTERS.find((s) => s.value === selectedSource)?.label ?? 'All Sources'}
                    <Icon name="chevronDown" size={11} />
                  </button>
                </RangeSelect>
                {selectedIp && (
                  <button
                    type="button"
                    className="btn-outline"
                    onClick={() => setSelectedIp('')}
                  >
                    Clear IP: {selectedIp} ×
                  </button>
                )}
                {selectedEventType && (
                  <button
                    type="button"
                    className="btn-outline"
                    onClick={() => setSelectedEventType('')}
                  >
                    Clear Type: {selectedEventType} ×
                  </button>
                )}
                {selectedSource !== 'all' && (
                  <button
                    type="button"
                    className="btn-outline"
                    onClick={() => setSelectedSource('all')}
                  >
                    Clear Source ×
                  </button>
                )}
                <button type="button" className="btn-solid" onClick={exportEvents}>
                  <Icon name="export" size={12} /> Export Events
                </button>
              </div>
            </div>

            <div className="table-scroll-wrap">
              <table className="siem-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Host</th>
                    <th>Event Type</th>
                    <th>Network</th>
                    <th>Severity</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '30px' }}>
                        {loading ? 'Loading events…' : 'No events found matching your filter criteria.'}
                      </td>
                    </tr>
                  )}
                  {filteredEvents.map((ev) => {
                    const cat = categorizeEventType(ev.event_type)
                    const typeTone = cat.kind === 'ids' ? 'ids' : cat.tone
                    const network = formatNetworkSummary(ev)
                    const expanded = expandedEventId === ev.id
                    const details = eventDetailFields(ev)
                    const rawPayload = eventRawPayload(ev)
                    return (
                      <Fragment key={ev.id}>
                      <tr className={expanded ? 'event-row-open' : undefined}>
                        <td className="td-mono">{formatTableTime(ev.timestamp)}</td>
                        <td>
                          <span className={`badge ${eventSourceTone(ev.source)}`}>
                            {eventSourceLabel(ev.source)}
                          </span>
                        </td>
                        <td>{formatHost(ev.host)}</td>
                        <td>
                          <div className="event-type-stack">
                            <span className={`badge ${typeTone}`}>{cat.category}</span>
                            {cat.kind === 'ids' && ev.signature ? (
                              <span className="network-summary">{ev.signature}</span>
                            ) : null}
                          </div>
                        </td>
                        <td className="td-mono">
                          {network ? (
                            ev.source_ip ? (
                              <button
                                type="button"
                                onClick={() => setSelectedIp(ev.source_ip)}
                                style={{
                                  color: '#0284c7',
                                  fontWeight: 600,
                                  textDecoration: 'underline',
                                }}
                              >
                                {network}
                              </button>
                            ) : (
                              <span className="network-summary">{network}</span>
                            )
                          ) : (
                            '—'
                          )}
                        </td>
                        <td>
                          {ev.severity ? (
                            <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="expand-event-btn"
                            aria-expanded={expanded}
                            aria-label={expanded ? `Hide details for event ${ev.id}` : `Show details for event ${ev.id}`}
                            onClick={() =>
                              setExpandedEventId((current) => (current === ev.id ? null : ev.id))
                            }
                          >
                            <span className="expand-chevron">
                              <Icon name="chevronDown" size={14} />
                            </span>
                          </button>
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="event-detail-row">
                          <td colSpan={7}>
                            <div className="event-detail-card">
                              {details.length > 0 ? (
                                <dl className="evidence-meta-grid">
                                  {details.map((field) => (
                                    <div className="meta-field" key={field.label}>
                                      <dt>{field.label}</dt>
                                      <dd style={field.mono ? { fontFamily: 'var(--font-mono)' } : undefined}>
                                        {field.time ? formatTime(field.value) : field.value}
                                      </dd>
                                    </div>
                                  ))}
                                </dl>
                              ) : (
                                <p className="empty-panel-msg">No additional fields for this event.</p>
                              )}
                              {rawPayload && (
                                <div className="event-raw-block">
                                  <span className="event-raw-label">Original record</span>
                                  <pre className="event-raw-pre">{rawPayload}</pre>
                                </div>
                              )}
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
          </main>
        )}

        {/* View 3: Full Alerts View */}
        {activeView === 'alerts' && (
          <main className="full-view-panel">
            <div className="panel-header-bar">
              <div className="panel-title-block">
                <h3>Detected Security Alerts</h3>
                <p>
                  {filteredAlerts.length} of {data.alerts.length} alerts shown ·{' '}
                  {openAlerts.length} open, {data.alerts.length - openAlerts.length} resolved
                </p>
              </div>
            </div>

            <div className="table-scroll-wrap">
              <table className="siem-table alert-table">
                <thead>
                  <tr>
                    <th>Last triggered</th>
                    <th>Alert</th>
                    <th>Network</th>
                    <th>Severity</th>
                    <th className="th-narrow">Events</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length === 0 && (
                    <tr>
                      <td colSpan={7} className="table-empty-cell">
                        {loading
                          ? 'Loading alerts…'
                          : data.alerts.length === 0
                            ? 'No alerts detected yet. Alerts appear here when a detection rule fires — SSH brute force from journal/ingest logs, or a Suricata IDS signature.'
                            : 'No alerts match your current search.'}
                      </td>
                    </tr>
                  )}
                  {filteredAlerts.map((alert) => {
                    const suricata = isSuricataAlert(alert)
                    const network = alertNetworkSummary(alert)
                    const signature = alertSignatureLabel(alert)
                    const rawSeverity = suricataSeverityFromAlert(alert)
                    const selected = viewingAlertId === alert.id
                    return (
                      <tr
                        key={alert.id}
                        className={`alert-row${selected ? ' alert-row-selected' : ''}`}
                      >
                        <td className="td-mono" title={`First seen ${formatTime(alert.created_at)}`}>
                          {formatAlertTime(alert.last_triggered_at || alert.created_at)}
                        </td>
                        <td>
                          <div className="alert-cell-stack">
                            <span className="alert-chip-row">
                              <span className={`badge ${suricata ? 'ids' : 'teal'}`}>
                                {alertRuleLabel(alert.rule_id)}
                              </span>
                              {signature && (
                                <span className="alert-signature">
                                  {signature}
                                  {alert.signature_id !== null &&
                                    alert.signature_id !== undefined && (
                                      <span className="alert-signature-id mono">
                                        {' '}
                                        id {alert.signature_id}
                                      </span>
                                    )}
                                </span>
                              )}
                            </span>
                            <button
                              type="button"
                              className="alert-title-btn"
                              onClick={() => viewEvidence(alert.id)}
                              aria-label={`Investigate alert ${alert.id}: ${alert.title}`}
                            >
                              {formatDisplay(alert.title, `Alert #${alert.id}`)}
                            </button>
                            {alert.description && (
                              <span className="alert-description">{alert.description}</span>
                            )}
                          </div>
                        </td>
                        <td className="td-mono">
                          {network ? <span className="network-summary">{network}</span> : '—'}
                        </td>
                        <td>
                          <span className={`badge ${alert.severity || 'low'}`}>
                            {alert.severity || 'unrated'}
                          </span>
                          {rawSeverity !== null && (
                            <span className="alert-severity-note" title="Original Suricata severity (0 = most severe)">
                              {suricataSeverityLabel(rawSeverity)}
                            </span>
                          )}
                        </td>
                        <td className="td-mono">{alert.event_count ?? '—'}</td>
                        <td>
                          <span className={`badge ${alert.status}`}>{alert.status || 'unknown'}</span>
                          {alert.closed_at && (
                            <span className="alert-severity-note" title={`Resolved ${formatTime(alert.closed_at)}`}>
                              {formatAlertTime(alert.closed_at)}
                            </span>
                          )}
                        </td>
                        <td>
                          <div className="alert-actions">
                            <button
                              type="button"
                              className="btn-outline"
                              onClick={() => viewEvidence(alert.id)}
                              aria-label={`Investigate alert ${alert.id}`}
                            >
                              Investigate
                            </button>
                            {alert.status === 'open' && (
                              <button
                                type="button"
                                className="btn-solid"
                                disabled={closingId === alert.id}
                                onClick={() => closeAlert(alert.id)}
                                aria-label={`Resolve alert ${alert.id}`}
                              >
                                {closingId === alert.id ? 'Resolving…' : 'Resolve'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </main>
        )}

        {/* View 4 & 5: Hosts / Analytics View fallback */}
        {(activeView === 'hosts' || activeView === 'analytics') && (
          <main className="full-view-panel">
            <div className="panel-header-bar">
              <div className="panel-title-block">
                <h3>{activeView === 'hosts' ? 'Monitored Hosts' : 'Analytics & Trends'}</h3>
                <p>Telemetry nodes actively reporting to Greywatch</p>
              </div>
            </div>
            <div style={{ padding: '20px', color: '#475569' }}>
              <p>Active hosts reporting in range: {monitoredHostsCount}</p>
              <ul style={{ marginTop: '12px', paddingLeft: '20px' }}>
                {[...new Set(rangedEvents.map((e) => e.host).filter(Boolean))].map((h) => (
                  <li key={h} style={{ fontFamily: 'var(--font-mono)', padding: '4px 0' }}>
                    {h}
                  </li>
                ))}
              </ul>
            </div>
          </main>
        )}
      </div>

      {/* Alert Investigation Evidence Drawer / Modal */}
      {viewingAlertId !== null && (
        <div
          className="modal-backdrop"
          onClick={closeEvidencePanel}
          role="dialog"
          aria-modal="true"
          aria-label="Alert Investigation"
        >
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div>
                <span className="drawer-eyebrow">INVESTIGATION DETAIL</span>
                <h2 className="drawer-title">Alert Evidence</h2>
              </div>
              <button
                type="button"
                className="action-circle-btn"
                onClick={closeEvidencePanel}
                aria-label="Close Evidence Panel"
              >
                <Icon name="close" size={16} />
              </button>
            </div>

            <div className="drawer-body">
              {evidenceLoading && (
                <div className="empty-panel-msg">Loading alert evidence…</div>
              )}
              {evidenceError && (
                <div className="drawer-error" role="alert">
                  {evidenceError}
                </div>
              )}

              {!evidenceLoading && !evidenceError && !evidenceAlert && (
                <div className="empty-panel-msg">Alert details are unavailable.</div>
              )}

              {!evidenceLoading && !evidenceError && evidenceAlert && (
                <>
                  <div className="drawer-summary">
                    <div className="drawer-summary-main">
                      <span className="drawer-chip-row">
                        <span className={`badge ${isSuricataAlert(evidenceAlert) ? 'ids' : 'teal'}`}>
                          {alertRuleLabel(evidenceAlert.rule_id)}
                        </span>
                        <span className={`badge ${evidenceAlert.status || 'unknown'}`}>
                          {evidenceAlert.status || 'unknown'}
                        </span>
                        <span className={`badge ${evidenceAlert.severity || 'low'}`}>
                          {evidenceAlert.severity || 'unrated'}
                        </span>
                        {evidenceRawSeverity !== null && (
                          <span className="drawer-severity-note">
                            Suricata {suricataSeverityLabel(evidenceRawSeverity)}
                          </span>
                        )}
                      </span>
                      <h3 className="drawer-alert-title">
                        {formatDisplay(evidenceAlert.title, `Alert #${evidenceAlert.id}`)}
                      </h3>
                      <p className="drawer-alert-meta">
                        {alertNetworkSummary(evidenceAlert) ? (
                          <span className="mono">{alertNetworkSummary(evidenceAlert)}</span>
                        ) : (
                          'No network context recorded for this alert.'
                        )}
                      </p>
                    </div>

                    {evidenceAlert.status === 'open' && (
                      <button
                        type="button"
                        className="btn-solid"
                        disabled={closingId === evidenceAlert.id}
                        onClick={() => closeAlert(evidenceAlert.id)}
                        aria-label={`Resolve alert ${evidenceAlert.id}`}
                      >
                        {closingId === evidenceAlert.id ? 'Resolving…' : 'Mark as resolved'}
                      </button>
                    )}
                  </div>

                  <div className="evidence-meta-card">
                    {evidenceDetailFields.length > 0 ? (
                      <dl className="evidence-meta-grid">
                        {evidenceDetailFields.map((field) => (
                          <div className="meta-field" key={field.label}>
                            <dt>{field.label}</dt>
                            <dd style={field.mono ? { fontFamily: 'var(--font-mono)' } : undefined}>
                              {ISO_TIME_FIELDS.has(field.label)
                                ? formatTime(field.value)
                                : field.value}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    ) : (
                      <p className="empty-panel-msg">No alert metadata was returned.</p>
                    )}
                  </div>

                  <div className="evidence-section">
                    <div className="evidence-section-head">
                      <h4>
                        Supporting evidence ({evidenceEvents.length} event
                        {evidenceEvents.length === 1 ? '' : 's'})
                      </h4>
                      <span className="evidence-window mono">
                        {formatTime(evidence.evidence_window_start)} →{' '}
                        {formatTime(evidence.evidence_window_end)}
                      </span>
                    </div>

                    {evidenceEvents.length === 0 ? (
                      <p className="empty-panel-msg">
                        No evidence events fall inside this alert window. They may have aged out of the
                        event store, or this rule id has no evidence query.
                      </p>
                    ) : (
                      <div className="table-scroll-wrap">
                        <table className="siem-table evidence-table">
                          <thead>
                            <tr>
                              <th>Time</th>
                              <th>Event</th>
                              <th>Network</th>
                              <th>Host / user</th>
                              <th className="th-narrow">
                                <span className="sr-only">Raw record</span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {evidenceEvents.map((ev) => {
                              const cat = categorizeEventType(ev.event_type)
                              const typeTone = cat.kind === 'ids' ? 'ids' : cat.tone
                              const evNetwork = formatNetworkSummary(ev)
                              const evRawSeverity = suricataSeverityFromRecord(ev.raw_message)
                              const evExpanded = expandedEvidenceId === ev.id
                              const evDetails = eventDetailFields(ev)
                              const evRawPayload = eventRawPayload(ev)
                              return (
                                <Fragment key={ev.id}>
                                  <tr className={evExpanded ? 'event-row-open' : undefined}>
                                    <td className="td-mono">{formatTableTime(ev.timestamp)}</td>
                                    <td>
                                      <div className="event-type-stack">
                                        <span className={`badge ${typeTone}`}>{cat.category}</span>
                                        <span className="evidence-message">
                                          {ev.signature || eventPreview(ev)}
                                        </span>
                                      </div>
                                    </td>
                                    <td className="td-mono">
                                      {evNetwork ? (
                                        <span className="network-summary">{evNetwork}</span>
                                      ) : (
                                        '—'
                                      )}
                                    </td>
                                    <td>
                                      <span className="evidence-host">{formatHost(ev.host)}</span>
                                      <span className="evidence-user mono">
                                        {formatDisplay(ev.username, '—')}
                                      </span>
                                      {evRawSeverity !== null && (
                                        <span className="alert-severity-note">
                                          Suricata {suricataSeverityLabel(evRawSeverity)}
                                        </span>
                                      )}
                                    </td>
                                    <td>
                                      <button
                                        type="button"
                                        className="expand-event-btn"
                                        aria-expanded={evExpanded}
                                        aria-label={
                                          evExpanded
                                            ? `Hide raw details for event ${ev.id}`
                                            : `Show raw details for event ${ev.id}`
                                        }
                                        onClick={() =>
                                          setExpandedEvidenceId((current) =>
                                            current === ev.id ? null : ev.id,
                                          )
                                        }
                                      >
                                        <span className="expand-chevron">
                                          <Icon name="chevronDown" size={14} />
                                        </span>
                                      </button>
                                    </td>
                                  </tr>
                                  {evExpanded && (
                                    <tr className="event-detail-row">
                                      <td colSpan={5}>
                                        <div className="event-detail-card">
                                          {evDetails.length > 0 ? (
                                            <dl className="evidence-meta-grid">
                                              {evDetails.map((field) => (
                                                <div className="meta-field" key={field.label}>
                                                  <dt>{field.label}</dt>
                                                  <dd
                                                    style={
                                                      field.mono
                                                        ? { fontFamily: 'var(--font-mono)' }
                                                        : undefined
                                                    }
                                                  >
                                                    {field.time ? formatTime(field.value) : field.value}
                                                  </dd>
                                                </div>
                                              ))}
                                            </dl>
                                          ) : (
                                            <p className="empty-panel-msg">
                                              No additional fields for this event.
                                            </p>
                                          )}
                                          {evRawPayload && (
                                            <div className="event-raw-block">
                                              <span className="event-raw-label">Original record</span>
                                              <pre className="event-raw-pre">{evRawPayload}</pre>
                                            </div>
                                          )}
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
                    )}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Mobile Bottom Navigation Bar (~390px Viewport) */}
      <nav className="mobile-bottom-nav" aria-label="Mobile Navigation">
        <button
          type="button"
          className={`mob-nav-item ${activeView === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveView('overview')}
        >
          <div className="mob-nav-icon-circle">
            <Icon name="home" size={17} />
          </div>
          <span>Overview</span>
        </button>

        <button
          type="button"
          className={`mob-nav-item ${activeView === 'events' ? 'active' : ''}`}
          onClick={() => setActiveView('events')}
        >
          <div className="mob-nav-icon-circle">
            <Icon name="document" size={17} />
          </div>
          <span>Events</span>
        </button>

        <button
          type="button"
          className={`mob-nav-item ${activeView === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveView('alerts')}
        >
          <div className="mob-nav-icon-circle">
            <Icon name="alertTriangle" size={17} />
          </div>
          <span>Alerts</span>
        </button>

        <button
          type="button"
          className={`mob-nav-item ${activeView === 'hosts' ? 'active' : ''}`}
          onClick={() => setActiveView('hosts')}
        >
          <div className="mob-nav-icon-circle">
            <Icon name="monitor" size={17} />
          </div>
          <span>Hosts</span>
        </button>
      </nav>
    </div>
  )
}
