/** Event presentation helpers for the Greywatch dashboard. */

export const SOURCE_FILTERS = [
  { value: 'all', label: 'All Sources' },
  { value: 'suricata', label: 'Suricata' },
  { value: 'journal', label: 'systemd journal' },
  { value: 'ingest', label: 'HTTP ingest' },
  { value: 'test', label: 'Test' },
  { value: 'unknown', label: 'Unknown' },
]

const NETWORK_CATEGORIES = [
  { name: 'IDS alert', tone: 'high' },
  { name: 'DNS', tone: 'teal' },
  { name: 'TLS', tone: 'purple' },
  { name: 'HTTP', tone: 'orange' },
  { name: 'Flow', tone: 'grey' },
]

/**
 * Map events.source to a stable filter key.
 * journal / suricata / test are stored as those strings; HTTP/manual ingest is NULL.
 */
export function eventSourceKey(source) {
  if (source === null || source === undefined || source === '') return 'ingest'
  if (source === 'suricata' || source === 'journal' || source === 'test') return source
  return 'unknown'
}

export function eventSourceLabel(source) {
  switch (eventSourceKey(source)) {
    case 'suricata':
      return 'Suricata'
    case 'journal':
      return 'systemd journal'
    case 'test':
      return 'Test'
    case 'ingest':
      return 'HTTP ingest'
    default:
      return 'Unknown'
  }
}

export function eventSourceTone(source) {
  switch (eventSourceKey(source)) {
    case 'suricata':
      return 'purple'
    case 'journal':
      return 'teal'
    case 'test':
      return 'orange'
    default:
      return 'grey'
  }
}

export function hasDisplayValue(value) {
  return value !== null && value !== undefined && value !== ''
}

export function formatDisplay(value, fallback = '—') {
  return hasDisplayValue(value) ? String(value) : fallback
}

export function formatHost(host) {
  return hasDisplayValue(host) ? String(host) : '—'
}

export function formatEndpoint(ip, port) {
  if (!hasDisplayValue(ip) && !hasDisplayValue(port)) return null
  if (!hasDisplayValue(ip)) return `:${port}`
  if (!hasDisplayValue(port)) return String(ip)
  return `${ip}:${port}`
}

export function formatNetworkSummary(event) {
  const src = formatEndpoint(event.source_ip, event.src_port)
  const dst = formatEndpoint(event.dest_ip, event.dest_port)
  const proto = hasDisplayValue(event.proto) ? String(event.proto) : null
  if (!src && !dst && !proto) return null
  if (src && dst) return proto ? `${src} → ${dst} (${proto})` : `${src} → ${dst}`
  return [src, dst, proto].filter(Boolean).join(' ')
}

export function categorizeEventType(type = '') {
  const t = String(type || '').toLowerCase()

  if (t === 'suricata_alert') {
    return { category: 'IDS alert', tone: 'high', kind: 'ids' }
  }
  if (t === 'suricata_dns') {
    return { category: 'DNS', tone: 'teal', kind: 'network' }
  }
  if (t === 'suricata_tls') {
    return { category: 'TLS', tone: 'purple', kind: 'network' }
  }
  if (t === 'suricata_http') {
    return { category: 'HTTP', tone: 'orange', kind: 'network' }
  }
  if (t === 'suricata_flow') {
    return { category: 'Flow', tone: 'grey', kind: 'network' }
  }
  if (t.includes('login_failed') || t.includes('invalid_user') || t.includes('auth_fail')) {
    return { category: 'Authentication failure', tone: 'teal', kind: 'auth' }
  }
  if (t.includes('sudo') || t.includes('command') || t.includes('privilege')) {
    return { category: 'Sudo activity', tone: 'orange', kind: 'sudo' }
  }
  if (t.includes('system') || t.includes('session') || t.includes('login_success') || t.includes('service')) {
    return { category: 'System', tone: 'purple', kind: 'system' }
  }
  return { category: 'Other', tone: 'grey', kind: 'other' }
}

export function eventTypeBreakdown(events) {
  const counts = new Map()
  for (const event of events) {
    const { category } = categorizeEventType(event.event_type)
    counts.set(category, (counts.get(category) || 0) + 1)
  }

  const core = [
    { name: 'Authentication failure', tone: 'teal' },
    { name: 'Sudo activity', tone: 'orange' },
    { name: 'System', tone: 'purple' },
  ]

  const rows = core.map((item) => ({
    ...item,
    count: counts.get(item.name) || 0,
  }))

  for (const item of NETWORK_CATEGORIES) {
    const count = counts.get(item.name) || 0
    if (count > 0) rows.push({ ...item, count })
  }

  rows.push({
    name: 'Other',
    tone: 'grey',
    count: counts.get('Other') || 0,
  })

  return rows
}

function prettyRawMessage(rawMessage) {
  if (!hasDisplayValue(rawMessage)) return null
  const text = String(rawMessage)
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

export function eventPreview(event) {
  const cat = categorizeEventType(event.event_type)
  if (cat.kind === 'ids' && hasDisplayValue(event.signature)) {
    return event.signature
  }
  const network = formatNetworkSummary(event)
  if ((cat.kind === 'ids' || cat.kind === 'network') && network) {
    return network
  }
  if (hasDisplayValue(event.raw_message)) {
    const raw = String(event.raw_message)
    if (raw.startsWith('{') || raw.startsWith('[')) {
      return network || cat.category
    }
    return raw
  }
  if (hasDisplayValue(event.event_type)) {
    return hasDisplayValue(event.username)
      ? `${event.event_type} (${event.username})`
      : String(event.event_type)
  }
  return 'Event'
}

export function eventDetailFields(event) {
  const fields = [
    // ``time: true`` asks the view to render the value with the shared
    // date/time formatter; the exact ISO string stays in the raw record.
    { label: 'Timestamp', value: event.timestamp, mono: true, time: true },
    { label: 'Host', value: event.host },
    { label: 'Event source', value: eventSourceLabel(event.source) },
    { label: 'Event type', value: event.event_type, mono: true },
    { label: 'Source IP', value: event.source_ip, mono: true },
    { label: 'Destination IP', value: event.dest_ip, mono: true },
    { label: 'Source port', value: event.src_port, mono: true },
    { label: 'Destination port', value: event.dest_port, mono: true },
    { label: 'Protocol', value: event.proto, mono: true },
    { label: 'Signature', value: event.signature },
    { label: 'Signature ID', value: event.signature_id, mono: true },
    { label: 'Alert category', value: event.category },
    { label: 'Severity', value: event.severity },
    { label: 'Username', value: event.username },
  ]

  return fields.filter((field) => hasDisplayValue(field.value)).map((field) => ({
    ...field,
    value: String(field.value),
  }))
}

export function eventRawPayload(event) {
  return prettyRawMessage(event.raw_message)
}

export function eventSearchHaystack(event) {
  return [
    event.event_type,
    event.host,
    event.username,
    event.source_ip,
    event.dest_ip,
    event.src_port,
    event.dest_port,
    event.proto,
    event.signature,
    event.signature_id,
    event.category,
    event.severity,
    event.raw_message,
    eventSourceLabel(event.source),
    event.source,
  ]
    .filter(hasDisplayValue)
    .map((value) => String(value).toLowerCase())
}

/* ==========================================================================
   Alert presentation

   Alert rows come from GET /api/v1/alerts (and a single alert plus its
   evidence events from GET /api/v1/alerts/{id}). Suricata-derived alerts
   (rule_id SURICATA_ALERT) carry extra network/IDS columns; the journal-based
   SSH_BRUTE_FORCE rule carries only source_ip. Every helper below returns null
   or a neutral fallback for missing optional fields so an alert with absent
   metadata never renders a misleading value or throws.
   ========================================================================== */

export const SURICATA_ALERT_RULE = 'SURICATA_ALERT'
export const SSH_BRUTE_FORCE_RULE = 'SSH_BRUTE_FORCE'

const RULE_LABELS = {
  [SURICATA_ALERT_RULE]: 'Suricata IDS',
  [SSH_BRUTE_FORCE_RULE]: 'SSH brute force',
}

export function isSuricataAlert(alert) {
  return hasDisplayValue(alert?.rule_id) && alert.rule_id === SURICATA_ALERT_RULE
}

export function alertRuleLabel(ruleId) {
  if (!hasDisplayValue(ruleId)) return 'Unknown rule'
  return RULE_LABELS[ruleId] || 'Detection rule'
}

/** Original Suricata severity tier (0-4, 0 = most severe) as a short label. */
export function suricataSeverityLabel(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  const tier = { 0: 'most severe', 1: 'high', 2: 'medium', 3: 'low', 4: 'low' }[n]
  return tier ? `sev ${n} · ${tier}` : `sev ${n}`
}

/**
 * Read the original `alert.severity` from a Suricata EVE record stored as an
 * evidence event's raw_message. Returns null when the value is absent or the
 * message is not JSON (e.g. journal log lines).
 */
export function suricataSeverityFromRecord(rawMessage) {
  if (!hasDisplayValue(rawMessage)) return null
  const text = String(rawMessage).trim()
  if (!text.startsWith('{')) return null
  try {
    const sev = JSON.parse(text)?.alert?.severity
    if (sev === null || sev === undefined || sev === '') return null
    const n = Number(sev)
    return Number.isFinite(n) ? n : null
  } catch {
    return null
  }
}

/**
 * Original Suricata severity for an alert row. The alert description written
 * by the backend embeds it ("Suricata severity 2"); when that sentence is
 * absent the field is simply omitted rather than guessed.
 */
export function suricataSeverityFromAlert(alert) {
  if (!isSuricataAlert(alert) || !hasDisplayValue(alert?.description)) return null
  const match = String(alert.description).match(/Suricata severity\s+(\d+)/i)
  return match ? Number(match[1]) : null
}

/** Signature text when present, else a signature-id label, else null. */
export function alertSignatureLabel(alert) {
  if (hasDisplayValue(alert?.signature)) return String(alert.signature)
  if (hasDisplayValue(alert?.signature_id)) return `Signature id ${alert.signature_id}`
  return null
}

/** Compact network context: `src:port → dst:port · proto`. Null when absent. */
export function alertNetworkSummary(alert) {
  const src = formatEndpoint(alert?.source_ip, alert?.src_port)
  const dst = formatEndpoint(alert?.dest_ip, alert?.dest_port)
  const proto = hasDisplayValue(alert?.proto) ? String(alert.proto) : null
  if (!src && !dst && !proto) return null
  if (src && dst) return proto ? `${src} → ${dst} · ${proto}` : `${src} → ${dst}`
  return [src, dst, proto].filter(Boolean).join(' · ')
}

/** Fields shown in the alert detail grid; missing values are omitted. */
export function alertDetailFields(alert) {
  const rawSeverity = suricataSeverityFromAlert(alert)
  const fields = [
    { label: 'Alert ID', value: alert?.id !== undefined ? `#${alert.id}` : null, mono: true },
    { label: 'Rule ID', value: alert?.rule_id, mono: true },
    { label: 'Rule', value: alertRuleLabel(alert?.rule_id) },
    { label: 'Status', value: alert?.status },
    { label: 'Severity (Greywatch)', value: alert?.severity },
    {
      label: 'Severity (Suricata)',
      value: rawSeverity === null ? null : suricataSeverityLabel(rawSeverity),
      mono: true,
    },
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

  return fields
    .filter((field) => hasDisplayValue(field.value))
    .map((field) => ({ ...field, value: String(field.value) }))
}

/** Searchable text for an alert, including Suricata network/IDS metadata. */
export function alertSearchHaystack(alert) {
  return [
    alert?.title,
    alert?.rule_id,
    alert?.description,
    alert?.status,
    alert?.severity,
    alert?.source_ip,
    alert?.dest_ip,
    alert?.src_port,
    alert?.dest_port,
    alert?.proto,
    alert?.signature,
    alert?.signature_id,
    alert?.category,
    alertRuleLabel(alert?.rule_id),
  ]
    .filter(hasDisplayValue)
    .map((value) => String(value).toLowerCase())
}

/**
 * Derive a compact Suricata collector status from GET /api/v1/suricata/status.
 * Does not claim Suricata is installed or that traffic is being inspected.
 */
export function suricataStatusView(status, unavailable) {
  if (unavailable) {
    return {
      state: 'unavailable',
      label: 'Unavailable',
      detail: 'Status endpoint could not be reached.',
      evePath: null,
      dot: 'offline',
    }
  }

  if (!status) {
    return {
      state: 'unavailable',
      label: 'Unavailable',
      detail: 'No collector status yet.',
      evePath: null,
      dot: 'offline',
    }
  }

  const evePath = hasDisplayValue(status.eve_path) ? String(status.eve_path) : null
  const ingested = Number(status.events_ingested) || 0
  const hasRun = hasDisplayValue(status.last_run_at)
  const hasOffset = status.last_offset !== null && status.last_offset !== undefined
  const hasEventTs = hasDisplayValue(status.last_event_ts)

  if (!status.enabled) {
    return {
      state: 'disabled',
      label: 'Disabled',
      detail: evePath ? `EVE ${evePath}` : 'Collector is off by default.',
      evePath,
      dot: 'idle',
    }
  }

  if (!hasRun && !hasOffset && ingested === 0 && !hasEventTs) {
    return {
      state: 'idle',
      label: 'Enabled',
      detail: evePath ? `Not yet collecting · ${evePath}` : 'Enabled, not yet collecting.',
      evePath,
      dot: 'warn',
    }
  }

  const ingestedLabel = ingested > 0 ? `${ingested} event${ingested === 1 ? '' : 's'} ingested` : 'Cycle recorded'
  return {
    state: 'active',
    label: 'Recently active',
    detail: evePath ? `${ingestedLabel} · ${evePath}` : ingestedLabel,
    evePath,
    dot: 'online',
  }
}
