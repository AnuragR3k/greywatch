// Date/time formatting helpers. All return a neutral fallback for empty or
// invalid input rather than throwing or printing "Invalid Date".

const DASH = '—'

function toDate(value) {
  if (value == null || value === '') return null
  const d = value instanceof Date ? value : new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/** Full locale date + time, e.g. "17 Oct 2026, 14:42:07". */
export function formatDateTime(value) {
  const d = toDate(value)
  if (!d) return value ? String(value) : DASH
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  })
}

/** Time only, e.g. "14:42:07". */
export function formatClock(value) {
  const d = toDate(value)
  if (!d) return value ? String(value) : DASH
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

/** Time today, otherwise short date + time. */
export function formatCompact(value) {
  const d = toDate(value)
  if (!d) return value ? String(value) : DASH
  const time = formatClock(d)
  const now = new Date()
  if (d.toDateString() === now.toDateString()) return time
  const day = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
  return `${day} ${time}`
}

/** Relative age, e.g. "just now", "4m ago", "3h ago", "2d ago". */
export function formatRelative(value) {
  const d = toDate(value)
  if (!d) return DASH
  const secs = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000))
  if (secs < 45) return 'just now'
  const mins = Math.round(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return `${days}d ago`
}

/** Age in milliseconds, or null when unparseable. */
export function ageMs(value) {
  const d = toDate(value)
  return d ? Date.now() - d.getTime() : null
}
