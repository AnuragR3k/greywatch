// API configuration.
//
// Greywatch is a local / trusted-host deployment: the backend trust boundary
// grants loopback access without a token, so the browser calls the same origin
// via the Vite dev proxy (`/api`, `/health` -> 127.0.0.1:8000) or same-origin
// serving in production. The frontend never holds a server-side secret. Remote
// deployments must terminate authentication at a reverse proxy.

export const API_CONFIG = {
  // Empty base URL keeps requests same-origin (proxied in dev). Override with
  // VITE_API_URL only for non-secret deployment wiring.
  baseUrl:
    typeof import.meta !== 'undefined' && import.meta.env.VITE_API_URL
      ? String(import.meta.env.VITE_API_URL).replace(/\/+$/, '')
      : '',

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
}

export const ALERT_STATUSES = ['open', 'closed', 'all']
export const DEFAULT_LIMIT = 100
export const MAX_LIMIT = 500
export const POLL_INTERVAL_MS = 15000
