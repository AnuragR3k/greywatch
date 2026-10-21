// Helpers for Greywatch end-to-end smoke tests.
//
// All backend calls go to the isolated API on 127.0.0.1:8000 (temp DB, never
// data/greywatch.db). The frontend dev server proxies /api and /health to it.

const API_BASE = 'http://127.0.0.1:8000'

export async function ingestLines(lines) {
  const res = await fetch(`${API_BASE}/api/v1/events/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lines }),
  })
  if (!res.ok) throw new Error(`ingest failed HTTP ${res.status}`)
  return res.json()
}

export function failedLoginLine(idx, ip, portBase = 54000) {
  return `sshd[600${idx}]: Failed password for attacker${idx} from ${ip} port ${portBase + idx} ssh2`
}

export function successfulLoginLine(ip, port = 56001) {
  return `sshd[6100]: Accepted publickey for demo from ${ip} port ${port} ssh2`
}

// Seed one SSH_BRUTE_FORCE_THEN_SUCCESS incident for `ip`. Returns the created
// incident id. Each call must use a distinct ip (one incident per rule+ip).
export async function createIncident(ip, index = 0) {
  const portBase = 54000 + index * 100
  const lines = [
    ...Array.from({ length: 5 }, (_, i) => failedLoginLine(i, ip, portBase)),
    successfulLoginLine(ip, portBase + 5000),
  ]
  const result = await ingestLines(lines)
  const incidents = (result.incidents || [])
  return incidents[0]?.id ?? null
}

// Seed `count` distinct incidents (distinct source IPs) and return their ids.
export async function seedIncidents(count = 30) {
  const ids = []
  for (let i = 0; i < count; i += 1) {
    const ip = `203.0.113.${100 + i}`
    const id = await createIncident(ip, i)
    if (id) ids.push(id)
  }
  return ids
}

// Seed one SSH_BRUTE_FORCE alert (5 failures, no success) and return its id.
export async function seedAlert(ip = '203.0.113.50') {
  const lines = Array.from({ length: 5 }, (_, i) =>
    failedLoginLine(i, ip, 59000 + i),
  )
  const result = await ingestLines(lines)
  const id = (result.alerts || [])[0]?.id
  if (!id) throw new Error(`seedAlert: no alert was created (${JSON.stringify(result)})`)
  return id
}

export async function listIncidents() {
  const res = await fetch(`${API_BASE}/api/v1/incidents?status=all&limit=500`)
  return res.json()
}

export async function getIncident(id) {
  const res = await fetch(`${API_BASE}/api/v1/incidents/${id}`)
  return res.json()
}

export async function getAlert(id) {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${id}`)
  if (!res.ok) throw new Error(`getAlert ${id} HTTP ${res.status}`)
  return res.json()
}

/* Resolve an incident via the real backend API (the mutation the UI calls). */
export async function resolveIncident(id) {
  const res = await fetch(`${API_BASE}/api/v1/incidents/${id}/resolve`, {
    method: 'POST',
  })
  if (!res.ok) throw new Error(`resolve incident ${id} HTTP ${res.status}`)
  return res.json()
}

/* Close (resolve) an alert via the real backend API (the mutation the UI calls). */
export async function resolveAlert(id) {
  const res = await fetch(`${API_BASE}/api/v1/alerts/${id}/close`, {
    method: 'POST',
  })
  if (!res.ok) throw new Error(`resolve alert ${id} HTTP ${res.status}`)
  return res.json()
}
