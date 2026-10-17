// Event, alert, and collector presentation helpers.
//
// These derive human-readable labels and tones strictly from the real backend
// fields; missing values return null or a neutral fallback so nothing is invented.

import { formatEndpoint } from './network'
import { ageMs } from './datetime'
import { hasValue } from './values'

export { hasValue, displayValue } from './values'
export { formatEndpoint, formatHost } from './network'

/* ------------------------------------------------------------- severities */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function normalizeSeverity(severity) {
  const s = String(severity || '').toLowerCase()
  if (SEVERITY_ORDER.includes(s)) return s
  return 'unknown'
}

/* Nmap severity tiers used by Suricata (0 = most severe). */
export function suricataSeverityLabel(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  const tier = { 0: 'most severe', 1: 'high', 2: 'medium', 3: 'low', 4: 'low' }[n]
  return tier ? `sev ${n} · ${tier}` : `sev ${n}`
}

/* --------------------------------------------------------------- sources */

export function eventSourceKey(source) {
  if (!hasValue(source)) return 'ingest'
  if (source === 'suricata' || source === 'journal' || source === 'test') return source
  return 'unknown'
}

export function eventSourceLabel(source) {
  switch (eventSourceKey(source)) {
    case 'suricata': return 'Suricata'
    case 'journal': return 'systemd journal'
    case 'test': return 'Test'
    case 'ingest': return 'HTTP ingest'
    default: return 'Unknown'
  }
}

export function eventSourceTone(source) {
  switch (eventSourceKey(source)) {
    case 'suricata': return 'violet'
    case 'journal': return 'teal'
    case 'test': return 'amber'
    default: return 'neutral'
  }
}

export const SOURCE_FILTERS = [
  { value: 'all', label: 'All sources' },
  { value: 'journal', label: 'systemd journal' },
  { value: 'suricata', label: 'Suricata' },
  { value: 'ingest', label: 'HTTP ingest' },
  { value: 'test', label: 'Test' },
  { value: 'unknown', label: 'Unknown' },
]

/* --------------------------------------------------------- event typing */

export function categorizeEvent(type = '') {
  const t = String(type || '').toLowerCase()
  if (t === 'suricata_alert') return { category: 'IDS alert', tone: 'critical', kind: 'ids' }
  if (t === 'suricata_dns' || t === 'suricata_http' || t === 'suricata_tls' || t === 'suricata_flow') {
    return { category: t.replace('suricata_', '').toUpperCase(), tone: 'violet', kind: 'network' }
  }
  if (t.includes('login_failed') || t.includes('invalid_user') || t.includes('auth_fail') || t.includes('pam_auth_failed')) {
    return { category: 'Auth failure', tone: 'high', kind: 'auth' }
  }
  if (t.includes('login_success') || t.includes('session') || t.includes('service') || t.includes('system')) {
    return { category: 'System', tone: 'info', kind: 'system' }
  }
  if (t.includes('sudo') || t.includes('command') || t.includes('privilege')) {
    return { category: 'Sudo', tone: 'medium', kind: 'sudo' }
  }
  return { category: 'Other', tone: 'unknown', kind: 'other' }
}

export function eventPreview(event) {
  const cat = categorizeEvent(event?.event_type)
  if (cat.kind === 'ids' && hasValue(event?.signature)) return event.signature
  const net = formatNetworkSummary(event)
  if ((cat.kind === 'ids' || cat.kind === 'network') && net) return net
  if (hasValue(event?.raw_message)) {
    const raw = String(event.raw_message)
    if (raw.startsWith('{') || raw.startsWith('[')) return cat.kind === 'network' ? (net || cat.category) : cat.category
    return raw
  }
  if (hasValue(event?.event_type)) {
    return hasValue(event?.username) ? `${event.event_type} (${event.username})` : String(event.event_type)
  }
  return 'Event'
}

export function eventDetailFields(event) {
  const fields = [
    { label: 'Timestamp', value: event?.timestamp, mono: true },
    { label: 'Host', value: event?.host },
    { label: 'Source', value: eventSourceLabel(event?.source) },
    { label: 'Event type', value: event?.event_type, mono: true },
    { label: 'Username', value: event?.username },
    { label: 'Source IP', value: event?.source_ip, mono: true },
    { label: 'Destination IP', value: event?.dest_ip, mono: true },
    { label: 'Source port', value: event?.src_port, mono: true },
    { label: 'Destination port', value: event?.dest_port, mono: true },
    { label: 'Protocol', value: event?.proto, mono: true },
    { label: 'Signature', value: event?.signature },
    { label: 'Signature ID', value: event?.signature_id, mono: true },
    { label: 'Category', value: event?.category },
    { label: 'Severity', value: event?.severity },
  ]
  return fields.filter((f) => hasValue(f.value)).map((f) => ({ ...f, value: String(f.value) }))
}

export function eventRawPayload(event) {
  if (!hasValue(event?.raw_message)) return null
  const text = String(event.raw_message)
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

export function eventSearchText(event) {
  return [
    event?.event_type, event?.host, event?.username, event?.source_ip, event?.dest_ip,
    event?.src_port, event?.dest_port, event?.proto, event?.signature, event?.signature_id,
    event?.category, event?.severity, event?.raw_message, eventSourceLabel(event?.source),
  ].filter(hasValue).map((v) => String(v).toLowerCase())
}

/* ------------------------------------------------------------- network */

export function formatNetworkSummary(entity) {
  const src = formatEndpoint(entity?.source_ip, entity?.src_port)
  const dst = formatEndpoint(entity?.dest_ip, entity?.dest_port)
  const proto = hasValue(entity?.proto) ? String(entity.proto) : null
  if (!src && !dst && !proto) return null
  if (src && dst) return proto ? `${src} → ${dst} · ${proto}` : `${src} → ${dst}`
  return [src, dst, proto].filter(Boolean).join(' · ')
}

/* Alias used by alert views (same compact network context). */
export const alertNetworkSummary = formatNetworkSummary

/* --------------------------------------------------------------- alerts */

export const SSH_BRUTE_FORCE_RULE = 'SSH_BRUTE_FORCE'
export const SURICATA_ALERT_RULE = 'SURICATA_ALERT'

const RULE_LABELS = {
  [SSH_BRUTE_FORCE_RULE]: 'SSH brute force',
  [SURICATA_ALERT_RULE]: 'Suricata IDS',
}

export function isSuricataAlert(alert) {
  return alert?.rule_id === SURICATA_ALERT_RULE
}

export function alertRuleLabel(ruleId) {
  if (!hasValue(ruleId)) return 'Unknown rule'
  return RULE_LABELS[ruleId] || String(ruleId).replace(/_/g, ' ').toLowerCase()
}

export function suricataSeverityFromAlert(alert) {
  if (!isSuricataAlert(alert) || !hasValue(alert?.description)) return null
  const m = String(alert.description).match(/Suricata severity\s+(\d+)/i)
  return m ? Number(m[1]) : null
}

export function alertDetailFields(alert) {
  const rawSeverity = suricataSeverityFromAlert(alert)
  const fields = [
    { label: 'Alert ID', value: alert?.id != null ? `#${alert.id}` : null, mono: true },
    { label: 'Status', value: alert?.status },
    { label: 'Severity', value: alert?.severity },
    { label: 'Rule', value: alertRuleLabel(alert?.rule_id) },
    { label: 'Rule ID', value: alert?.rule_id, mono: true },
    { label: 'Severity (Suricata)', value: rawSeverity == null ? null : suricataSeverityLabel(rawSeverity), mono: true },
    { label: 'Signature', value: alert?.signature },
    { label: 'Signature ID', value: alert?.signature_id, mono: true },
    { label: 'Category', value: alert?.category },
    { label: 'Source IP', value: alert?.source_ip, mono: true },
    { label: 'Source port', value: alert?.src_port, mono: true },
    { label: 'Destination IP', value: alert?.dest_ip, mono: true },
    { label: 'Destination port', value: alert?.dest_port, mono: true },
    { label: 'Protocol', value: alert?.proto, mono: true },
    { label: 'Event count', value: alert?.event_count },
    { label: 'First seen', value: alert?.created_at, mono: true },
    { label: 'Last triggered', value: alert?.last_triggered_at, mono: true },
    { label: 'Resolved at', value: alert?.closed_at, mono: true },
  ]
  return fields.filter((f) => hasValue(f.value)).map((f) => ({ ...f, value: String(f.value) }))
}

export function alertSearchText(alert) {
  return [
    alert?.title, alert?.rule_id, alert?.description, alert?.status, alert?.severity,
    alert?.source_ip, alert?.dest_ip, alert?.signature, alert?.signature_id, alert?.category,
    alertRuleLabel(alert?.rule_id),
  ].filter(hasValue).map((v) => String(v).toLowerCase())
}

/* ------------------------------------------------------------ collectors */

// An enabled-but-silent collector is "Stale" once its last run ages past this.
export const COLLECTOR_FRESH_MS = 30 * 60 * 1000

/* Derive an honest collector state. tone: healthy | degraded | disabled |
   unavailable | unknown. `stale` marks enabled-but-not-recently-run. */
export function collectorState(status, { freshMs = COLLECTOR_FRESH_MS } = {}) {
  if (status == null) return { tone: 'unavailable', label: 'Unavailable', stale: false }
  if (!status.enabled) return { tone: 'disabled', label: 'Disabled', stale: false }
  if (!hasValue(status.last_run_at)) return { tone: 'unknown', label: 'Awaiting first run', stale: false }
  const age = ageMs(status.last_run_at)
  const ingested = Number(status.events_ingested) || 0
  if (age != null && age > freshMs) return { tone: 'degraded', label: 'Stale', stale: true, ageMs: age, ingested }
  if (ingested > 0) return { tone: 'healthy', label: 'Active', stale: false, ageMs: age, ingested }
  return { tone: 'unknown', label: 'Idle', stale: false, ageMs: age, ingested }
}
