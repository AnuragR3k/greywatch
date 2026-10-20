// Domain-level API calls. Each maps to a verified backend route and returns
// normalized data (arrays for collections, objects for single resources).

import { get, post } from './client'
import { API_PATHS, ALERT_STATUSES, DEFAULT_LIMIT, INCIDENT_STATUSES, MAX_LIMIT } from './config'

const clampLimit = (n) => Math.min(Math.max(Number(n) || DEFAULT_LIMIT, 1), MAX_LIMIT)

/* GET /health (public liveness probe) */
export function fetchHealth(options = {}) {
  return get(API_PATHS.health, options)
}

/* GET /api/v1/events?limit= -> event[] */
export async function fetchEvents({ limit = DEFAULT_LIMIT, signal } = {}) {
  const data = await get(`${API_PATHS.events}?limit=${clampLimit(limit)}`, { signal })
  if (Array.isArray(data)) return data
  return Array.isArray(data?.events) ? data.events : []
}

/* POST /api/v1/events/ingest { lines } */
export function ingestLines(lines, options = {}) {
  return post(`${API_PATHS.events}/ingest`, { lines }, options)
}

/* GET /api/v1/alerts?status=&limit=&offset=&source_ip= -> { count, total, alerts[] } */
export async function fetchAlerts({
  status = 'all',
  limit = DEFAULT_LIMIT,
  offset = 0,
  source_ip,
  signal,
} = {}) {
  const safeStatus = ALERT_STATUSES.includes(status) ? status : 'all'
  const params = new URLSearchParams({
    status: safeStatus,
    limit: String(clampLimit(limit)),
    offset: String(Math.max(Number(offset) || 0, 0)),
  })
  if (source_ip) params.set('source_ip', source_ip)
  const data = await get(`${API_PATHS.alerts}?${params}`, { signal })
  if (Array.isArray(data)) return { count: data.length, total: data.length, alerts: data }
  return {
    count: Array.isArray(data?.alerts) ? data.alerts.length : 0,
    total: Number.isFinite(Number(data?.total)) ? Number(data.total) : 0,
    alerts: Array.isArray(data?.alerts) ? data.alerts : [],
  }
}

/* GET /api/v1/alerts/{id} -> { alert, evidence_window_start, evidence_window_end, evidence_events } */
export function fetchAlertDetail(id, options = {}) {
  return get(API_PATHS.alertDetail(id), options)
}

/* POST /api/v1/alerts/{id}/close -> { id, status: 'closed' } */
export function closeAlert(id, options = {}) {
  return post(API_PATHS.closeAlert(id), null, options)
}

/* GET /api/v1/incidents?status=&limit=&offset= -> { count, total, incidents[] } */
export async function fetchIncidents({
  status = "all",
  limit = DEFAULT_LIMIT,
  offset = 0,
  signal,
} = {}) {
  const safeStatus = INCIDENT_STATUSES.includes(status) ? status : "all"
  const data = await get(
    `${API_PATHS.incidents}?status=${safeStatus}&limit=${clampLimit(
      limit
    )}&offset=${Math.max(Number(offset) || 0, 0)}`,
    { signal }
  )
  if (Array.isArray(data)) return { count: data.length, total: data.length, incidents: data }
  return {
    count: Array.isArray(data?.incidents) ? data.incidents.length : 0,
    total: Number.isFinite(Number(data?.total)) ? Number(data.total) : 0,
    incidents: Array.isArray(data?.incidents) ? data.incidents : [],
  }
}

/* GET /api/v1/incidents/{id} -> { incident, related_events, related_event_ids } */
export function fetchIncidentDetail(id, options = {}) {
  return get(API_PATHS.incidentDetail(id), options)
}

/* POST /api/v1/incidents/{id}/acknowledge -> { id, status: 'acknowledged' } */
export function acknowledgeIncident(id, options = {}) {
  return post(API_PATHS.acknowledgeIncident(id), null, options)
}

/* POST /api/v1/incidents/{id}/resolve -> { id, status: 'resolved' } */
export function resolveIncident(id, options = {}) {
  return post(API_PATHS.resolveIncident(id), null, options)
}

/* GET /api/v1/journal/status */
export function fetchJournalStatus(options = {}) {
  return get(API_PATHS.journalStatus, options)
}

/* POST /api/v1/journal/collect -> { records_seen, events_ingested, alerts, fallback_used, errors } */
export function collectJournal(options = {}) {
  return post(API_PATHS.journalCollect, null, options)
}

/* GET /api/v1/suricata/status */
export function fetchSuricataStatus(options = {}) {
  return get(API_PATHS.suricataStatus, options)
}

/* POST /api/v1/suricata/collect */
export function collectSuricata(options = {}) {
  return post(API_PATHS.suricataCollect, null, options)
}
