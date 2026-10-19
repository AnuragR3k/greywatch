// API configuration.
//
// Greywatch is a local / trusted-host deployment: the backend trust boundary
// grants loopback access without a token, so the browser calls the same origin
// via the Vite dev proxy (`/api`, `/health` -> 127.0.0.1:8000) or same-origin
// serving in production. The frontend never holds a server-side secret. Remote
// deployments must terminate authentication at a reverse proxy.

// Resolve the API base URL from the environment.
//
//   * Unset -> "" (same-origin; the Vite dev proxy forwards /api and /health).
//   * Set   -> that origin, with any trailing slashes trimmed.
//
// Both `VITE_API_BASE_URL` (the documented name) and the legacy `VITE_API_URL`
// are honoured; the former wins when both are set. Neither ever carries a
// secret — a build-time `VITE_*` value is compiled into a public bundle.
function resolveBaseUrl() {
  if (typeof import.meta === 'undefined' || !import.meta.env) return ''
  const raw = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL
  return raw ? String(raw).replace(/\/+$/, '') : ''
}

// Optional, runtime-injected bearer token.
//
// Deliberately NOT read from a `VITE_*` env var: those are baked into the
// public bundle, so a token there would be a leaked secret. Instead an
// operator that fronts the API with token mode can inject the token at
// runtime (e.g. a bootstrap script served alongside a same-origin dashboard):
//
//     window.__GREYWATCH_API_TOKEN__ = '<token>'
//
// The value is held only in memory for the page's lifetime and is never
// persisted to storage. When it is absent (the loopback/local default) no
// Authorization header is sent and the backend's loopback trust boundary
// applies.
export function getRuntimeToken() {
  if (typeof window === 'undefined') return null
  const token = window.__GREYWATCH_API_TOKEN__
  return typeof token === 'string' && token ? token : null
}

export const API_CONFIG = {
  baseUrl: resolveBaseUrl(),

  // Reads are cheap; collector actions can be slower.
  timeoutMs: 10000,

  // Maximum automatic retries for transient network failures only.
  maxRetries: 2,

  // Backoff base (ms) between retries.
  retryBaseMs: 500,

  // Upper bound (ms) for honouring a server Retry-After header.
  maxRetryAfterMs: 30000,
}

// Endpoint paths — the single place the real backend schema is referenced.
export const API_PATHS = {
  health: '/health',
  events: '/api/v1/events',
  alerts: '/api/v1/alerts',
  alertDetail: (id) => `/api/v1/alerts/${id}`,
  closeAlert: (id) => `/api/v1/alerts/${id}/close`,
  journalStatus: '/api/v1/journal/status',
  journalCollect: '/api/v1/journal/collect',
  suricataStatus: '/api/v1/suricata/status',
  suricataCollect: '/api/v1/suricata/collect',
  incidents: '/api/v1/incidents',
  incidentDetail: (id) => `/api/v1/incidents/${id}`,
  acknowledgeIncident: (id) => `/api/v1/incidents/${id}/acknowledge`,
  resolveIncident: (id) => `/api/v1/incidents/${id}/resolve`,
}

export const ALERT_STATUSES = ['open', 'closed', 'all']
export const INCIDENT_STATUSES = ['open', 'acknowledged', 'resolved', 'all']
export const DEFAULT_LIMIT = 100
export const MAX_LIMIT = 500
export const POLL_INTERVAL_MS = 15000
